// Package auth provides JWT validation middleware using JWKS.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
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
	ResourceURI      string // Public URL for WWW-Authenticate resource_metadata
	Realm            string // e.g. "grafana-mcp"
	ScopesSupported  string // Space-separated scopes for WWW-Authenticate
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
func NewMiddleware(cfg Config) (*Middleware, error) {
	// Build per-URL storage with blocking initial fetch
	store, err := jwkset.NewStorageFromHTTP(cfg.JWKSURI, jwkset.HTTPClientStorageOptions{
		Ctx:             cfg.Ctx,
		RefreshInterval: cfg.RefreshInterval,
		RefreshErrorHandler: func(ctx context.Context, err error) {
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

// IsReady returns true if the JWKS store has at least one key loaded.
func (m *Middleware) IsReady() bool {
	keys, err := m.storage.KeyReadAll(context.Background())
	return err == nil && len(keys) > 0
}

// Handler returns an HTTP middleware that validates JWT Bearer tokens.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract Bearer token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.writeNoTokenError(w)
			return
		}

		token, found := strings.CutPrefix(authHeader, "Bearer ")
		if !found || token == "" {
			m.writeNoTokenError(w)
			return
		}

		// Parse and validate JWT
		claims := &Claims{}
		parsed, err := m.parser.ParseWithClaims(token, claims, m.kf.Keyfunc)
		if err != nil {
			slog.Warn("token rejected",
				"reason", "validation_failed",
				"remote_addr", r.RemoteAddr,
				"error", err,
				"jti", claims.ID,
			)
			m.writeInvalidTokenError(w, err.Error())
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
					"remote_addr", r.RemoteAddr,
					"jti", claims.ID,
				)
				m.writeInvalidTokenError(w, "wrong token type")
				return
			}
		} else {
			slog.Debug("JWT missing typ header", "sub", claims.Subject)
		}

		// Scope validation — 403, not 401
		tokenScopes := strings.Fields(claims.Scope)
		for _, required := range m.cfg.RequiredScopes {
			if !slices.Contains(tokenScopes, required) {
				slog.Warn("token rejected",
					"reason", "insufficient_scope",
					"required", required,
					"token_scopes", claims.Scope,
					"remote_addr", r.RemoteAddr,
					"jti", claims.ID,
				)
				m.writeInsufficientScopeError(w)
				return
			}
		}

		slog.Debug("token validated",
			"sub", claims.Subject,
			"iss", claims.Issuer,
			"scopes", claims.Scope,
			"jti", claims.ID,
			"remote_addr", r.RemoteAddr,
		)

		next.ServeHTTP(w, r)
	})
}

// writeNoTokenError writes a 401 response for missing/malformed Bearer token.
// Per RFC 6750 §3.1, no error code when the request lacks authentication.
func (m *Middleware) writeNoTokenError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm="%s", scope="%s", resource_metadata="%s/.well-known/oauth-protected-resource"`,
		m.cfg.Realm, m.cfg.ScopesSupported, m.cfg.ResourceURI,
	))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "unauthorized",
		"error_description": "Bearer token required",
	})
}

// writeInvalidTokenError writes a 401 response for an invalid/expired token.
func (m *Middleware) writeInvalidTokenError(w http.ResponseWriter, desc string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm="%s", error="invalid_token", error_description="%s", resource_metadata="%s/.well-known/oauth-protected-resource"`,
		m.cfg.Realm, desc, m.cfg.ResourceURI,
	))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "invalid_token",
		"error_description": desc,
	})
}

// writeInsufficientScopeError writes a 403 response for missing required scopes.
func (m *Middleware) writeInsufficientScopeError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm="%s", error="insufficient_scope", scope="%s", error_description="Required scope not granted", resource_metadata="%s/.well-known/oauth-protected-resource"`,
		m.cfg.Realm, strings.Join(m.cfg.RequiredScopes, " "), m.cfg.ResourceURI,
	))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "insufficient_scope",
		"error_description": "Required scope not granted",
	})
}
