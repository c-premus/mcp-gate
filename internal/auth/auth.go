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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/c-premus/mcp-gate/internal/metrics"
	"github.com/c-premus/mcp-gate/internal/realip"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"
)

// Claims represents the JWT claims validated by this middleware.
type Claims struct {
	jwt.RegisteredClaims
	Scope string `json:"scope,omitempty"`
}

// Config holds JWT validation configuration.
type Config struct {
	Ctx              context.Context
	JWKSURI          string
	RefreshInterval  time.Duration
	ExpectedIssuer   string
	ExpectedAudience string
	RequiredScopes   []string
	ResourceURI      string       // Public URL for WWW-Authenticate resource_metadata
	Realm            string       // e.g. "grafana-mcp"
	ScopesSupported  string       // Space-separated scopes for WWW-Authenticate
	TrustedProxies   []*net.IPNet // CIDRs trusted for X-Forwarded-For / X-Real-IP
}

// Middleware validates JWT Bearer tokens against a JWKS endpoint.
type Middleware struct {
	kf      keyfunc.Keyfunc
	storage jwkset.Storage
	cfg     Config
	parser  *jwt.Parser
}

// NewMiddleware creates a new auth middleware. It performs a blocking JWKS fetch
// on startup and returns an error if the initial fetch fails.
//
// It also spawns a background goroutine bound to cfg.Ctx that polls the JWKS
// storage to update observability metrics (key count and last-key-change
// timestamp). The goroutine exits when cfg.Ctx is cancelled.
func NewMiddleware(cfg Config) (*Middleware, error) {
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

	// Wrap in aggregating client with rate-limited unknown-kid refresh
	client, err := jwkset.NewHTTPClient(jwkset.HTTPClientOptions{
		HTTPURLs:          map[string]jwkset.Storage{cfg.JWKSURI: store},
		RefreshUnknownKID: rate.NewLimiter(rate.Every(time.Minute), 1),
		RateLimitWaitMax:  time.Minute,
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

	keys, _ := client.KeyReadAll(context.Background())
	slog.Info("JWKS loaded", "key_count", len(keys), "jwks_uri", cfg.JWKSURI)

	// Prime the key-count gauge on startup. The polling goroutine below keeps
	// it updated over time.
	metrics.JWKSKeysLoaded.Set(float64(len(keys)))
	metrics.JWKSLastKeyChangeTimestamp.Set(float64(time.Now().Unix()))

	// Start the metrics polling goroutine. Sample at half the refresh
	// interval (Nyquist) but never faster than every 5 minutes to keep
	// background load trivial.
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
		kf:      kf,
		storage: client,
		cfg:     cfg,
		parser:  parser,
	}, nil
}

// pollJWKSMetrics periodically reads the JWKS storage and updates the
// mcpgate_jwks_keys_loaded gauge. When the set of key IDs changes relative
// to the previous poll, it bumps mcpgate_jwks_last_key_change_timestamp.
// The goroutine exits when ctx is cancelled.
func pollJWKSMetrics(ctx context.Context, storage jwkset.Storage, lastFingerprint string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	prev := lastFingerprint
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			keys, err := storage.KeyReadAll(ctx)
			if err != nil {
				// Errors reading storage are distinct from refresh errors —
				// the refresh goroutine reports its own failures via
				// RefreshErrorHandler. Log at debug to avoid noise.
				slog.Debug("JWKS metrics poll: storage read failed", "error", err)
				continue
			}
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

// IsReady returns true if the JWKS store has at least one key loaded.
func (m *Middleware) IsReady() bool {
	keys, err := m.storage.KeyReadAll(context.Background())
	return err == nil && len(keys) > 0
}

// KeyCount returns the number of keys currently loaded in the JWKS store.
func (m *Middleware) KeyCount() (int, error) {
	keys, err := m.storage.KeyReadAll(context.Background())
	if err != nil {
		return 0, err
	}
	return len(keys), nil
}

// Handler returns an HTTP middleware that validates JWT Bearer tokens.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span := trace.SpanFromContext(r.Context())
		clientIP := realip.Extract(r, m.cfg.TrustedProxies)

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
			slog.Warn("token rejected",
				"reason", "validation_failed",
				"client_ip", clientIP,
				"error", err,
				"jti", claims.ID,
			)
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
		tokenScopes := strings.Fields(claims.Scope)
		for _, required := range m.cfg.RequiredScopes {
			if slices.Contains(tokenScopes, required) {
				continue
			}
			slog.Warn("token rejected",
				"reason", "insufficient_scope",
				"required", required,
				"token_scopes", claims.Scope,
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
			"scopes", claims.Scope,
			"jti", claims.ID,
			"client_ip", clientIP,
		)

		next.ServeHTTP(w, r)
	})
}

// sanitizeQuotedString escapes characters for use in RFC 7235 quoted-string values.
func sanitizeQuotedString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// writeNoTokenError writes a 401 response for missing/malformed Bearer token.
// Per RFC 6750 §3.1, no error code when the request lacks authentication.
func (m *Middleware) writeNoTokenError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm="%s", scope="%s", resource_metadata="%s/.well-known/oauth-protected-resource"`,
		sanitizeQuotedString(m.cfg.Realm),
		sanitizeQuotedString(m.cfg.ScopesSupported),
		sanitizeQuotedString(m.cfg.ResourceURI),
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
		`Bearer realm="%s", error="invalid_token", error_description="The access token is invalid or expired", resource_metadata="%s/.well-known/oauth-protected-resource"`,
		sanitizeQuotedString(m.cfg.Realm),
		sanitizeQuotedString(m.cfg.ResourceURI),
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
		`Bearer realm="%s", error="insufficient_scope", scope="%s", error_description="Required scope not granted", resource_metadata="%s/.well-known/oauth-protected-resource"`,
		sanitizeQuotedString(m.cfg.Realm),
		sanitizeQuotedString(strings.Join(m.cfg.RequiredScopes, " ")),
		sanitizeQuotedString(m.cfg.ResourceURI),
	))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "insufficient_scope",
		"error_description": "Required scope not granted",
	})
}
