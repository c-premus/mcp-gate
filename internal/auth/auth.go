// Package auth provides JWT validation middleware using JWKS.
//
// It validates Bearer tokens per RFC 6750, enforces RS256 algorithm
// restriction, and returns RFC 9728-aware WWW-Authenticate challenges.
// JWKS keys are fetched on startup and refreshed periodically, with
// rate-limited refresh on unknown key IDs.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/c-premus/mcp-gate/internal/metadata"
	"github.com/c-premus/mcp-gate/internal/metrics"
	"github.com/c-premus/mcp-gate/internal/realip"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"
)

// Scopes holds the OAuth `scope` claim. RFC 6749 §3.3 specifies the wire form
// as a space-separated string, but some providers (e.g. Cloudflare Access) emit
// a JSON array. Scopes accepts both on unmarshal and emits the RFC-compliant
// string form on marshal.
type Scopes []string

// UnmarshalJSON decodes a scope claim from either a JSON array of strings or a
// space-separated string. A JSON null decodes to an empty slice.
func (s *Scopes) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*s = nil
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err == nil {
		*s = arr
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return fmt.Errorf("scope claim: expected string or array of strings: %w", err)
	}
	*s = strings.Fields(str)
	return nil
}

// MarshalJSON emits the RFC 6749 space-separated string form.
func (s Scopes) MarshalJSON() ([]byte, error) {
	return json.Marshal(strings.Join(s, " "))
}

// Claims represents the JWT claims validated by this middleware.
type Claims struct {
	jwt.RegisteredClaims
	Scope Scopes `json:"scope,omitempty"`

	// Cnf is the RFC 7800 confirmation claim. Its presence means the AS bound
	// the token to a key the client must prove possession of (DPoP, RFC 9449;
	// mTLS, RFC 8705). mcp-gate verifies neither proof, so accepting such a
	// token as a plain bearer token would discard the binding the AS asked
	// for — RFC 9700 §4.10. Decoded raw because only presence matters.
	Cnf json.RawMessage `json:"cnf,omitempty"`
}

// Config holds JWT validation configuration.
type Config struct {
	Ctx              context.Context
	JWKSURI          string
	RefreshInterval  time.Duration
	ExpectedIssuer   string
	ExpectedAudience string
	RequiredScopes   []string
	ResourceURI     string // Public URL for WWW-Authenticate resource_metadata
	Realm           string // Protection space name; operator-supplied, sanitized at emit
	ScopesSupported string // Space-separated scopes for WWW-Authenticate

	// StrictTyp accepts only the RFC 9068 access-token types (`at+jwt`,
	// `application/at+jwt`), as RFC 9068 §4 requires. Off by default because
	// common IdPs (Authentik included) sign access tokens with `typ: JWT`.
	// Turning it on is the strongest guard against an OIDC ID token from the
	// same issuer being replayed as an access token (RFC 8725 §3.11).
	StrictTyp bool
}

// Middleware validates JWT Bearer tokens against a JWKS endpoint.
type Middleware struct {
	kf      keyfunc.Keyfunc
	storage jwkset.Storage
	cfg     Config
	parser  *jwt.Parser

	// metadataURL is the resource_metadata value emitted in every
	// WWW-Authenticate challenge. Derived from cfg.ResourceURI once at
	// construction so the three challenge builders stay identical in shape and
	// cannot drift apart. Still passed through sanitizeQuotedString at emit
	// time — sanitizing is the invariant, not a judgement about this value's
	// provenance.
	metadataURL string
}

// NewMiddleware creates a new auth middleware. It performs a blocking JWKS fetch
// on startup and returns an error if the initial fetch fails.
//
// It also spawns a background goroutine bound to cfg.Ctx that polls the JWKS
// storage to update observability metrics (key count and last-key-change
// timestamp). The goroutine exits when cfg.Ctx is cancelled.
func NewMiddleware(cfg Config) (*Middleware, error) {
	// Validate required fields before making the blocking JWKS fetch,
	// so misconfigurations produce clear error messages.
	if cfg.JWKSURI == "" {
		return nil, errors.New("auth config: JWKSURI is required")
	}
	if cfg.ExpectedIssuer == "" {
		return nil, errors.New("auth config: ExpectedIssuer is required")
	}
	if cfg.ExpectedAudience == "" {
		return nil, errors.New("auth config: ExpectedAudience is required")
	}

	// Build per-URL storage with blocking initial fetch
	store, err := jwkset.NewStorageFromHTTP(cfg.JWKSURI, jwkset.HTTPClientStorageOptions{
		Ctx:             cfg.Ctx,
		RefreshInterval: cfg.RefreshInterval,
		RefreshErrorHandler: func(ctx context.Context, err error) {
			metrics.JWKSRefreshErrorsTotal.Inc()
			slog.Error("JWKS refresh failed", "error", err, "jwks_uri", cfg.JWKSURI)
		},
		// NoErrorReturnFirstHTTPReq defaults to false: blocks and returns error on failure
	})
	if err != nil {
		return nil, fmt.Errorf("JWKS initial fetch: %w", err)
	}

	// Wrap in aggregating client with rate-limited unknown-kid refresh.
	// RateLimitWaitMax is bounded at 5s so an attacker flooding unknown-kid
	// tokens cannot hold request goroutines (and concurrent-limit slots) for
	// a full minute each. 5s is still well above the legitimate post-rotation
	// race window where a freshly issued token's kid might not yet be cached.
	client, err := jwkset.NewHTTPClient(jwkset.HTTPClientOptions{
		HTTPURLs:          map[string]jwkset.Storage{cfg.JWKSURI: store},
		RefreshUnknownKID: rate.NewLimiter(rate.Every(time.Minute), 1),
		RateLimitWaitMax:  5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("JWKS HTTP client: %w", err)
	}

	kf, err := keyfunc.New(keyfunc.Options{
		Ctx:     cfg.Ctx,
		Storage: client,
	})
	if err != nil {
		return nil, fmt.Errorf("keyfunc init: %w", err)
	}

	keys, err := client.KeyReadAll(cfg.Ctx)
	if err != nil {
		// Non-fatal: the initial NewStorageFromHTTP fetch already succeeded,
		// so at this point an error from the aggregating client is unexpected.
		// Log so startup posture stays visible, then continue with zero keys.
		slog.Warn("JWKS post-init read failed", "error", err, "jwks_uri", cfg.JWKSURI)
	}
	slog.Info("JWKS loaded", "key_count", len(keys), "jwks_uri", cfg.JWKSURI)

	// Prime the key-count gauge on startup. The polling goroutine below keeps
	// it updated over time.
	metrics.JWKSKeysLoaded.Set(float64(len(keys)))
	metrics.JWKSLastKeyChangeTimestamp.Set(float64(time.Now().Unix()))

	// Poll at half the refresh interval (Nyquist) — whichever is smaller, so
	// the gauge keeps up with short refresh intervals — but cap at 5 minutes
	// so very long refresh intervals still detect key changes promptly.
	// For RefreshInterval = 0 (misconfig caught upstream) fall back to 1m.
	pollInterval := min(cfg.RefreshInterval/2, 5*time.Minute)
	if pollInterval <= 0 {
		pollInterval = time.Minute
	}
	go pollJWKSMetrics(cfg.Ctx, client, initialKeyFingerprint(keys), pollInterval)

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(cfg.ExpectedIssuer),
		jwt.WithAudience(cfg.ExpectedAudience),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)

	return &Middleware{
		kf:          kf,
		storage:     client,
		cfg:         cfg,
		parser:      parser,
		metadataURL: metadata.URLFor(cfg.ResourceURI),
	}, nil
}

// pollErrWarnThreshold is the number of consecutive poll-loop read failures
// after which the goroutine escalates from Debug to Warn. Below the threshold
// transient errors stay quiet so a single ctx-cancel race or storage hiccup
// doesn't page; at and above it, repeated failures imply a real problem worth
// surfacing in operator-facing logs. The counter is reset on every success.
const pollErrWarnThreshold = 3

// pollJWKSMetrics periodically reads the JWKS storage and updates the
// mcpgate_jwks_keys_loaded gauge. When the set of key IDs changes relative
// to the previous poll, it bumps mcpgate_jwks_last_key_change_timestamp.
// Read failures increment mcpgate_jwks_poll_errors_total and escalate from
// Debug to Warn after pollErrWarnThreshold consecutive failures (the counter
// is the primary alerting signal; the log level escalation is a secondary
// hint for on-call eyeballs).
// The goroutine exits when ctx is cancelled.
func pollJWKSMetrics(ctx context.Context, storage jwkset.Storage, lastFingerprint string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	prev := lastFingerprint
	consecutiveErrs := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			keys, err := storage.KeyReadAll(ctx)
			if err != nil {
				// Errors reading storage are distinct from refresh errors —
				// the refresh goroutine reports its own failures via
				// RefreshErrorHandler. Always increment the counter; promote
				// to Warn only after consecutive failures so a single race
				// doesn't spam logs.
				metrics.JWKSPollErrorsTotal.Inc()
				consecutiveErrs++
				if consecutiveErrs >= pollErrWarnThreshold {
					slog.Warn("JWKS metrics poll: storage read failing repeatedly",
						"error", err,
						"consecutive_failures", consecutiveErrs,
					)
				} else {
					slog.Debug("JWKS metrics poll: storage read failed",
						"error", err,
						"consecutive_failures", consecutiveErrs,
					)
				}
				continue
			}
			consecutiveErrs = 0
			metrics.JWKSKeysLoaded.Set(float64(len(keys)))
			fp := initialKeyFingerprint(keys)
			if fp != prev {
				metrics.JWKSLastKeyChangeTimestamp.Set(float64(time.Now().Unix()))
				prev = fp
			}
		}
	}
}

// initialKeyFingerprint returns a deterministic string derived from the sorted
// list of key IDs. It is used to detect changes in the key set between polls
// without hashing the key material itself.
func initialKeyFingerprint(keys []jwkset.JWK) string {
	if len(keys) == 0 {
		return ""
	}
	kids := make([]string, 0, len(keys))
	for i := range keys {
		kids = append(kids, keys[i].Marshal().KID)
	}
	slices.Sort(kids)
	return strings.Join(kids, ",")
}

// IsReady returns true if the JWKS store has at least one key loaded. The
// caller should pass a request-scoped context so the underlying storage read
// is bounded by the caller's deadline.
func (m *Middleware) IsReady(ctx context.Context) bool {
	keys, err := m.storage.KeyReadAll(ctx)
	return err == nil && len(keys) > 0
}

// Handler returns an HTTP middleware that validates JWT Bearer tokens.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span := trace.SpanFromContext(r.Context())
		clientIP := realip.FromContext(r)

		// OAuth 2.1 §5.3.2: a request that "repeats the same parameter" or
		// "is otherwise malformed" is invalid_request (400). Header.Get would
		// silently validate only the first of several Authorization headers,
		// leaving which credential authorised the request up to field order.
		authHeaders := r.Header.Values("Authorization")
		if len(authHeaders) > 1 {
			m.rejectInvalidRequest(w, span, clientIP, "multiple_authorization_headers")
			return
		}
		if len(authHeaders) == 0 || authHeaders[0] == "" {
			metrics.AuthValidationsTotal.WithLabelValues("no_token").Inc()
			span.SetAttributes(attribute.String("auth.outcome", "no_token"))
			m.writeNoTokenError(w)
			return
		}

		// RFC 9110 §11.1 and RFC 6750 §2.1 define auth-scheme as a
		// case-INSENSITIVE token, and §11.6.2 allows more than one space
		// between the scheme and the credentials. A case-sensitive CutPrefix
		// told a client sending `bearer <valid token>` that it had supplied no
		// credentials at all (no_token, a 401 carrying no error parameter),
		// which is both wrong and actively misleading to debug.
		//
		// A different scheme (Basic, DPoP) is "no bearer credentials" and gets
		// the bare challenge. The Bearer scheme with nothing after it is a
		// malformed bearer request, not an absent one — 400, not 401.
		token, found := cutBearerPrefix(authHeaders[0])
		if !found {
			metrics.AuthValidationsTotal.WithLabelValues("no_token").Inc()
			span.SetAttributes(attribute.String("auth.outcome", "no_token"))
			m.writeNoTokenError(w)
			return
		}
		if token == "" {
			m.rejectInvalidRequest(w, span, clientIP, "empty_bearer_token")
			return
		}

		// Parse and validate JWT
		claims := &Claims{}
		parsed, err := m.parser.ParseWithClaims(token, claims, m.kf.Keyfunc)
		if err != nil {
			// Log a classified category rather than err.Error(): some jwt/v5
			// parse failures (malformed base64, JSON unmarshal errors) can
			// echo token bytes back through the error string, which would
			// then land in Loki. Classification is enough to diagnose with
			// the metrics counter providing volume; the raw error is kept
			// at Debug for local troubleshooting.
			category := classifyJWTError(err)
			slog.Warn("token rejected",
				"reason", "validation_failed",
				"category", category,
				"client_ip", clientIP,
				"jti", claims.ID,
			)
			slog.Debug("token rejected (detail)", "category", category, "error", err)
			metrics.AuthValidationsTotal.WithLabelValues("invalid_token").Inc()
			span.SetAttributes(attribute.String("auth.outcome", "invalid_token"))
			m.writeInvalidTokenError(w)
			return
		}

		// Header and binding checks the parser does not perform: crit, typ,
		// cnf. Each rejection is invalid_token with its own outcome label.
		if outcome := m.tokenShapeOutcome(parsed, claims); outcome != "" {
			typ, _ := parsed.Header["typ"].(string)
			slog.Warn("token rejected",
				"reason", outcome,
				"typ", typ,
				"client_ip", clientIP,
				"jti", claims.ID,
			)
			metrics.AuthValidationsTotal.WithLabelValues(outcome).Inc()
			span.SetAttributes(attribute.String("auth.outcome", outcome))
			m.writeInvalidTokenError(w)
			return
		}

		// Scope validation — 403, not 401
		for _, required := range m.cfg.RequiredScopes {
			if scopesSatisfy(claims.Scope, required) {
				continue
			}
			slog.Warn("token rejected",
				"reason", "insufficient_scope",
				"required", required,
				"token_scopes", strings.Join(claims.Scope, " "),
				"client_ip", clientIP,
				"jti", claims.ID,
			)
			metrics.AuthValidationsTotal.WithLabelValues("insufficient_scope").Inc()
			span.SetAttributes(attribute.String("auth.outcome", "insufficient_scope"))
			m.writeInsufficientScopeError(w)
			return
		}

		// Reject tokens without a subject — needed for audit trail integrity
		if claims.Subject == "" {
			slog.Warn("token rejected",
				"reason", "missing_sub",
				"client_ip", clientIP,
				"jti", claims.ID,
			)
			// Label matches the span attribute and the log reason. It used to
			// read "invalid_token", which made an IdP that stopped emitting
			// `sub` indistinguishable from signature failures in Prometheus —
			// the one place an operator would look. Constant string, so this
			// adds exactly one series.
			metrics.AuthValidationsTotal.WithLabelValues("missing_sub").Inc()
			span.SetAttributes(attribute.String("auth.outcome", "missing_sub"))
			m.writeInvalidTokenError(w)
			return
		}

		metrics.AuthValidationsTotal.WithLabelValues("valid").Inc()
		span.SetAttributes(
			attribute.String("auth.outcome", "valid"),
			attribute.String("auth.sub", claims.Subject),
			attribute.String("auth.jti", claims.ID),
		)

		slog.Debug("token validated",
			"sub", claims.Subject,
			"iss", claims.Issuer,
			"scopes", strings.Join(claims.Scope, " "),
			"jti", claims.ID,
			"client_ip", clientIP,
		)

		next.ServeHTTP(w, r)
	})
}

// rejectInvalidRequest records and writes the 400 invalid_request response.
// The reason goes to the log only; the metric and span carry the single
// fixed outcome so the label set stays bounded.
func (m *Middleware) rejectInvalidRequest(w http.ResponseWriter, span trace.Span, clientIP, reason string) {
	slog.Warn("request rejected",
		"reason", reason,
		"client_ip", clientIP,
	)
	metrics.AuthValidationsTotal.WithLabelValues("invalid_request").Inc()
	span.SetAttributes(attribute.String("auth.outcome", "invalid_request"))
	m.writeInvalidRequestError(w)
}

// tokenShapeOutcome applies the checks that a signature-valid, claims-valid
// token must still pass, returning the rejection outcome or "" to accept.
//
//   - crit: RFC 7515 §4.1.11 — a recipient MUST reject a JWS whose `crit`
//     header names an extension it does not understand. mcp-gate understands
//     none, and golang-jwt never reads `crit`, so any `crit` is rejected.
//   - typ: RFC 9068 §4 accepts `at+jwt` and `application/at+jwt` (RFC 7515
//     §4.1.9: compared case-insensitively, `application/` prefix optional).
//     `JWT` and an absent `typ` are accepted unless StrictTyp — a deliberate
//     interoperability default, since golang-jwt and Authentik emit `JWT`.
//     Anything else (e.g. `secevent+jwt`) is not an access token.
//   - cnf: a sender-constrained token presented as bearer; see Claims.Cnf.
func (m *Middleware) tokenShapeOutcome(parsed *jwt.Token, claims *Claims) string {
	if _, ok := parsed.Header["crit"]; ok {
		return "unsupported_crit"
	}
	if !m.typAcceptable(parsed.Header["typ"]) {
		return "wrong_typ"
	}
	if len(claims.Cnf) > 0 && string(claims.Cnf) != "null" {
		return "sender_constrained"
	}
	return ""
}

// typAcceptable reports whether a JOSE `typ` header value is an access-token
// type under the configured strictness. A non-string `typ` is malformed.
func (m *Middleware) typAcceptable(v any) bool {
	if v == nil {
		return !m.cfg.StrictTyp
	}
	typ, ok := v.(string)
	if !ok {
		return false
	}
	switch strings.ToLower(typ) {
	case "at+jwt", "application/at+jwt":
		return true
	case "jwt", "":
		return !m.cfg.StrictTyp
	default:
		return false
	}
}

// classifyJWTError maps a jwt/v5 parse/validation error to a fixed-cardinality
// category string safe to log at Warn. The jwt/v5 library's err.Error() can
// echo token bytes in some failure modes (malformed base64, JSON unmarshal);
// returning a category instead of the raw error keeps those bytes out of
// Loki. Order matters: the more specific errors come first because jwt/v5
// wraps some of them under more generic ones.
func classifyJWTError(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, jwt.ErrTokenExpired):
		return "expired"
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return "not_yet_valid"
	case errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
		return "iat_in_future"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "signature_invalid"
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return "wrong_audience"
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return "wrong_issuer"
	case errors.Is(err, jwt.ErrTokenInvalidSubject):
		return "wrong_subject"
	case errors.Is(err, jwt.ErrTokenInvalidId):
		return "wrong_jti"
	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
		return "required_claim_missing"
	case errors.Is(err, jwt.ErrTokenInvalidClaims):
		return "invalid_claims"
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		// Covers missing keyfunc, unknown kid, unsupported alg.
		return "unverifiable"
	case errors.Is(err, jwt.ErrTokenMalformed):
		return "malformed"
	default:
		return "other"
	}
}

// bearerScheme is the RFC 6750 auth-scheme. Matched case-insensitively per
// RFC 9110 §11.1; the token itself stays case-sensitive.
const bearerScheme = "Bearer"

// cutBearerPrefix splits a case-insensitive "Bearer <token>" Authorization
// header value, tolerating the additional SP that RFC 9110 §11.6.2 permits
// between scheme and credentials. It returns ok=false if the scheme does not
// match, so the caller can distinguish "no bearer credentials" from "bad
// bearer credentials" — the two produce different challenges. The bare
// scheme ("Bearer", "Bearer   ") matches with an empty token.
func cutBearerPrefix(header string) (token string, ok bool) {
	if len(header) < len(bearerScheme) ||
		!strings.EqualFold(header[:len(bearerScheme)], bearerScheme) {
		return "", false
	}
	rest := header[len(bearerScheme):]
	if rest == "" {
		return "", true
	}
	// A scheme match must be followed by whitespace, or "Bearerfoo" would
	// parse as the Bearer scheme carrying the token "foo".
	if rest[0] != ' ' && rest[0] != '\t' {
		return "", false
	}
	return strings.TrimLeft(rest, " \t"), true
}

// scopeHierarchySeparator is the conventional OAuth scope hierarchy delimiter
// (`repo:status`, `files:read`, `admin:org`). MCP does not mandate a delimiter;
// `:` is what the ecosystem uses and what RFC 6749 §3.3's "space-delimited,
// case-sensitive strings" leaves open to the AS.
const scopeHierarchySeparator = ":"

// scopesSatisfy reports whether the scopes granted in a token are sufficient
// for one required scope.
//
// MCP 2026-07-28, Authorization §Step-Up Authorization Flow: "Servers MUST
// account for scope hierarchies, where a broader scope implies narrower ones,
// when deciding whether a token is sufficient for an operation." Exact matching
// alone (the previous behaviour) does not satisfy that MUST.
//
// The implication is strictly one-directional: a granted `files` satisfies a
// required `files:read`, because the broad scope subsumes the narrow one. The
// reverse must NOT hold — a granted `files:read` does not satisfy a required
// `files`, which would be a privilege escalation rather than a hierarchy.
//
// Matching is on whole segments. A granted `file` does not satisfy a required
// `files:read`, because the separator must follow the granted prefix exactly.
//
// For an AS that issues flat scopes with no separator (Authentik issues
// `openid`, `profile`), every comparison falls through to the equality case and
// this is behaviourally identical to the exact match it replaces.
func scopesSatisfy(granted []string, required string) bool {
	return slices.ContainsFunc(granted, func(g string) bool {
		return g == required ||
			strings.HasPrefix(required, g+scopeHierarchySeparator)
	})
}

// sanitizeQuotedString escapes characters for use in RFC 7235 quoted-string
// values. In addition to escaping backslash and double-quote (the two
// characters that carry meaning inside a quoted-string), it strips CR, LF,
// NUL, and other C0 control bytes (< 0x20 except tab) as defense-in-depth
// against header-splitting if a caller ever reflects untrusted input here.
// Current call sites pass operator-controlled config only; this keeps the
// function safe for future reuse.
func sanitizeQuotedString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			b.WriteString(`\\`)
		case c == '"':
			b.WriteString(`\"`)
		case c == '\t':
			b.WriteByte(c)
		case c < 0x20 || c == 0x7f:
			// Skip C0 controls and DEL — unrepresentable in a header value.
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// setNoStore marks an auth error response uncacheable. 4xx responses are not
// heuristically cacheable (RFC 9111 §4.2.2), but a shared cache between the
// client and mcp-gate may still be configured to store them, and a cached
// challenge outlives the condition that produced it.
func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

// writeNoTokenError writes a 401 response for a request carrying no Bearer
// credentials. RFC 6750 §3.1 and OAuth 2.1 §5.3.2: when the request lacks
// authentication information the resource server "SHOULD NOT include an error
// code or other error information" — so the challenge carries no `error`
// parameter and the response has no body. (It used to send a JSON body with
// the unregistered code "unauthorized".)
func (m *Middleware) writeNoTokenError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm="%s", scope="%s", resource_metadata="%s"`,
		sanitizeQuotedString(m.cfg.Realm),
		sanitizeQuotedString(m.cfg.ScopesSupported),
		sanitizeQuotedString(m.metadataURL),
	))
	setNoStore(w)
	w.WriteHeader(http.StatusUnauthorized)
}

// writeInvalidRequestError writes a 400 response for a malformed Bearer
// request (RFC 6750 §3.1, OAuth 2.1 §5.3.2 invalid_request): several
// Authorization headers, or the Bearer scheme with no token. No `scope`: the
// client's fault is the request's shape, not its grant.
func (m *Middleware) writeInvalidRequestError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm="%s", error="invalid_request", error_description="Malformed Authorization header", resource_metadata="%s"`,
		sanitizeQuotedString(m.cfg.Realm),
		sanitizeQuotedString(m.metadataURL),
	))
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "invalid_request",
		"error_description": "Malformed Authorization header",
	})
}

// writeInvalidTokenError writes a 401 response for an invalid/expired token.
// The desc parameter is logged server-side but a generic message is returned
// to clients to prevent leaking internal details (key IDs, timing, etc.).
//
// Carries scope for the same reason the no-token challenge does: the MCP
// authorization spec asks servers to "include a scope parameter in the
// WWW-Authenticate header to indicate the scopes required for accessing the
// resource", so a client re-authorizing after expiry knows what to request
// without first fetching the metadata document. ScopesSupported rather than
// RequiredScopes, matching the no-token challenge — the client is about to
// start a fresh authorization, not step up an existing grant.
func (m *Middleware) writeInvalidTokenError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm="%s", error="invalid_token", scope="%s", error_description="The access token is invalid or expired", resource_metadata="%s"`,
		sanitizeQuotedString(m.cfg.Realm),
		sanitizeQuotedString(m.cfg.ScopesSupported),
		sanitizeQuotedString(m.metadataURL),
	))
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "invalid_token",
		"error_description": "The access token is invalid or expired",
	})
}

// writeInsufficientScopeError writes a 403 response for missing required scopes.
func (m *Middleware) writeInsufficientScopeError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm="%s", error="insufficient_scope", scope="%s", error_description="Required scope not granted", resource_metadata="%s"`,
		sanitizeQuotedString(m.cfg.Realm),
		sanitizeQuotedString(strings.Join(m.cfg.RequiredScopes, " ")),
		sanitizeQuotedString(m.metadataURL),
	))
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "insufficient_scope",
		"error_description": "Required scope not granted",
	})
}
