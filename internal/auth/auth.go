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
	Realm           string // e.g. "grafana-mcp"
	ScopesSupported string // Space-separated scopes for WWW-Authenticate
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

		// Extract Bearer token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			metrics.AuthValidationsTotal.WithLabelValues("no_token").Inc()
			span.SetAttributes(attribute.String("auth.outcome", "no_token"))
			m.writeNoTokenError(w)
			return
		}

		token, found := strings.CutPrefix(authHeader, "Bearer ")
		if !found || token == "" {
			metrics.AuthValidationsTotal.WithLabelValues("no_token").Inc()
			span.SetAttributes(attribute.String("auth.outcome", "no_token"))
			m.writeNoTokenError(w)
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

		// Check typ header (advisory per RFC 9068 §2.1).
		// - "at+jwt": preferred for access tokens, accept
		// - "JWT" or absent: standard default, accept with debug log
		// - anything else: reject (likely not an access token)
		if typ, ok := parsed.Header["typ"].(string); ok {
			typLower := strings.ToLower(typ)
			switch typLower {
			case "at+jwt":
				// Preferred — no action needed
			case "jwt", "":
				slog.Debug("JWT uses default typ header, not at+jwt", "sub", claims.Subject, "typ", typ)
			default:
				slog.Warn("token rejected",
					"reason", "wrong_typ",
					"typ", typ,
					"client_ip", clientIP,
					"jti", claims.ID,
				)
				metrics.AuthValidationsTotal.WithLabelValues("wrong_typ").Inc()
				span.SetAttributes(attribute.String("auth.outcome", "wrong_typ"))
				m.writeInvalidTokenError(w)
				return
			}
		} else {
			slog.Debug("JWT missing typ header", "sub", claims.Subject)
		}

		// Scope validation — 403, not 401
		for _, required := range m.cfg.RequiredScopes {
			if slices.Contains(claims.Scope, required) {
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
			metrics.AuthValidationsTotal.WithLabelValues("invalid_token").Inc()
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

// sanitizeQuotedString escapes characters for use in RFC 7235 quoted-string
// values. In addition to escaping backslash and double-quote (the two
// characters that carry meaning inside a quoted-string), it strips CR, LF,
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

// writeNoTokenError writes a 401 response for missing/malformed Bearer token.
// Per RFC 6750 §3.1, no error code when the request lacks authentication.
func (m *Middleware) writeNoTokenError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm="%s", scope="%s", resource_metadata="%s"`,
		sanitizeQuotedString(m.cfg.Realm),
		sanitizeQuotedString(m.cfg.ScopesSupported),
		sanitizeQuotedString(m.metadataURL),
	))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "unauthorized",
		"error_description": "Bearer token required",
	})
}

// writeInvalidTokenError writes a 401 response for an invalid/expired token.
// The desc parameter is logged server-side but a generic message is returned
// to clients to prevent leaking internal details (key IDs, timing, etc.).
func (m *Middleware) writeInvalidTokenError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm="%s", error="invalid_token", error_description="The access token is invalid or expired", resource_metadata="%s"`,
		sanitizeQuotedString(m.cfg.Realm),
		sanitizeQuotedString(m.metadataURL),
	))
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "insufficient_scope",
		"error_description": "Required scope not granted",
	})
}
