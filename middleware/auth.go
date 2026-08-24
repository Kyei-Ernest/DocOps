package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	authsvc "github.com/Kyei-Ernest/DocOps/services/auth"
	"github.com/golang-jwt/jwt/v5"
)

// authsvcAPIKeyPrefix aliases the crypto-package prefix without importing the
// crypto package here — middleware needs only the literal for branch detection.
const authsvcAPIKeyPrefix = "docops_sk_"

// contextKey is an unexported type for all context keys in this package.
// Using a named struct (rather than a plain string) prevents any other package
// from constructing the same key and reading values they shouldn't.
type contextKey struct{ name string }

var (
	// KEKKey is the context key under which the session KEK ([]byte) is stored.
	KEKKey = &contextKey{"kek"}

	// UserIDKey is the context key under which the authenticated user ID (string) is stored.
	UserIDKey = &contextKey{"userID"}
)

// Claims mirrors the JWT payload from the auth handler.
// Duplicating it here (rather than importing from handlers) keeps the packages
// decoupled — middleware depends only on services/auth, not on handlers.
type Claims struct {
	SessionToken string `json:"session_token"`
	jwt.RegisteredClaims
}

// SessionReader is the minimal session capability the auth middleware needs.
// Declaring it here (consumer side) keeps middleware decoupled from the concrete
// in-memory store and lets tests substitute any implementation that can resolve
// opaque tokens to Sessions.
type SessionReader interface {
	Get(token string) (*authsvc.Session, bool)
}

// BearerAuthenticator validates machine credentials ("docops_sk_…") statelessly.
// Implemented by *authsvc.APIKeyStore; declared here so middleware depends on
// behaviour, not the concrete store.
type BearerAuthenticator interface {
	Authenticate(ctx context.Context, presented string) (userID string, masterKey []byte, ok bool)
}

// Auth returns an HTTP middleware that:
//  1. Reads the access_token HttpOnly cookie
//  2. Validates the JWT signature and expiry
//  3. Resolves the session_token claim to a live server-side Session
//  4. Attaches the KEK and UserID to the request context
//
// Any failure at any step results in 401 with no diagnostic detail — callers
// intentionally cannot distinguish "bad JWT" from "expired session" from
// "no cookie at all".
func Auth(sessions SessionReader, jwtSecret []byte) func(http.Handler) http.Handler {
	return AuthWithAPIKeys(sessions, jwtSecret, nil)
}

// AuthWithAPIKeys is Auth with an optional machine-credential path. When a
// request carries `Authorization: Bearer docops_sk_…`, authentication runs
// entirely against the API key store — no session lookup, no RAM state — so
// machine traffic survives restarts and scales horizontally. Humans continue
// through the unchanged cookie path. Both paths inject identical context
// values, so downstream handlers never know which one authenticated.
//
// A malformed or invalid bearer key fails immediately with the same detail-free
// 401 as every other failure: no cookie fallback for presented-but-wrong keys,
// so probing cannot distinguish "bad key" from "bad anything".
func AuthWithAPIKeys(sessions SessionReader, jwtSecret []byte, keys BearerAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ── Machine path ────────────────────────────────────────
			if authz := r.Header.Get("Authorization"); keys != nil && strings.HasPrefix(authz, "Bearer "+authsvcAPIKeyPrefix) {
				userID, masterKey, ok := keys.Authenticate(r.Context(), strings.TrimPrefix(authz, "Bearer "))
				if !ok {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				ctx := context.WithValue(r.Context(), KEKKey, masterKey)
				ctx = context.WithValue(ctx, UserIDKey, userID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// ── Human path (unchanged) ──────────────────────────────
			cookie, err := r.Cookie("access_token")
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			claims, err := parseJWT(cookie.Value, jwtSecret)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			session, ok := sessions.Get(claims.SessionToken)
			if !ok {
				// Token was valid JWT but session is expired or already deleted
				// (e.g. post-logout). Treat identically to a bad JWT.
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), KEKKey, session.KEK)
			ctx = context.WithValue(ctx, UserIDKey, session.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// KEKFromContext retrieves the KEK attached by the Auth middleware.
// Returns (nil, false) if the context was not populated — callers should
// treat this as an internal error (it means a protected route was registered
// without the middleware).
func KEKFromContext(ctx context.Context) ([]byte, bool) {
	kek, ok := ctx.Value(KEKKey).([]byte)
	return kek, ok
}

// UserIDFromContext retrieves the user ID attached by the Auth middleware.
// Returns ("", false) if not present — same caveat as KEKFromContext.
func UserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(UserIDKey).(string)
	return id, ok
}

func parseJWT(tokenStr string, secret []byte) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}
