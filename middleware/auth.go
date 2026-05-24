package middleware

import (
	"context"
	"fmt"
	"net/http"

	authsvc "github.com/Kyei-Ernest/DocOps/services/auth"
	"github.com/golang-jwt/jwt/v5"
)

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

// Auth returns an HTTP middleware that:
//  1. Reads the access_token HttpOnly cookie
//  2. Validates the JWT signature and expiry
//  3. Resolves the session_token claim to a live server-side Session
//  4. Attaches the KEK and UserID to the request context
//
// Any failure at any step results in 401 with no diagnostic detail — callers
// intentionally cannot distinguish "bad JWT" from "expired session" from
// "no cookie at all".
func Auth(sessions *authsvc.SessionStore, jwtSecret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
