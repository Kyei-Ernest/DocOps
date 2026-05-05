package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Kyei-Ernest/DocOps/middleware"
	authsvc "github.com/Kyei-Ernest/DocOps/services/auth"
	"github.com/golang-jwt/jwt/v5"
)

var testSecret = []byte("test-secret-not-for-production")

// ── Helpers ───────────────────────────────────────────────────────────────────

func newSession(kek []byte, userID string, ttl time.Duration) (*authsvc.SessionStore, string) {
	sessions := authsvc.NewSessionStore()
	token := "test-session-token-abc123"
	sessions.Save(token, &authsvc.Session{
		UserID:    userID,
		KEK:       kek,
		ExpiresAt: time.Now().Add(ttl),
	})
	return sessions, token
}

// signJWT produces a signed access JWT carrying sessionToken.
func signJWT(t *testing.T, sessionToken string, secret []byte, expiry time.Time) string {
	t.Helper()
	claims := middleware.Claims{
		SessionToken: sessionToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signed
}

// probeHandler is the downstream handler used to assert what the middleware
// placed in context — it writes 200 and a body only when context values are present.
func probeHandler(t *testing.T, wantUserID string, wantKEK []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kek, ok := middleware.KEKFromContext(r.Context())
		if !ok {
			t.Error("KEK not found in context")
		} else if string(kek) != string(wantKEK) {
			t.Errorf("KEK mismatch: want %x got %x", wantKEK, kek)
		}

		userID, ok := middleware.UserIDFromContext(r.Context())
		if !ok {
			t.Error("UserID not found in context")
		} else if userID != wantUserID {
			t.Errorf("UserID mismatch: want %q got %q", wantUserID, userID)
		}

		w.WriteHeader(http.StatusOK)
	}
}

func withCookie(r *http.Request, name, value string) *http.Request {
	r.AddCookie(&http.Cookie{Name: name, Value: value})
	return r
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestAuth_ValidTokenAttachesContext(t *testing.T) {
	kek := []byte("32-byte-test-kek-for-unit-tests!")
	userID := "user-123"
	sessions, sessionToken := newSession(kek, userID, 15*time.Minute)

	signed := signJWT(t, sessionToken, testSecret, time.Now().Add(15*time.Minute))

	req := withCookie(httptest.NewRequest(http.MethodGet, "/", nil), "access_token", signed)
	rr := httptest.NewRecorder()

	handler := middleware.Auth(sessions, testSecret)(probeHandler(t, userID, kek))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
}

func TestAuth_NoCookie(t *testing.T) {
	sessions := authsvc.NewSessionStore()

	req := httptest.NewRequest(http.MethodGet, "/", nil) // no cookie
	rr := httptest.NewRecorder()

	handler := middleware.Auth(sessions, testSecret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream handler should not be called")
	}))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestAuth_MalformedJWT(t *testing.T) {
	sessions := authsvc.NewSessionStore()

	req := withCookie(httptest.NewRequest(http.MethodGet, "/", nil), "access_token", "not.a.jwt")
	rr := httptest.NewRecorder()

	middleware.Auth(sessions, testSecret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream handler should not be called")
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestAuth_ExpiredJWT(t *testing.T) {
	kek := []byte("32-byte-test-kek-for-unit-tests!")
	sessions, sessionToken := newSession(kek, "user-123", 15*time.Minute)

	// Sign with an expiry in the past
	signed := signJWT(t, sessionToken, testSecret, time.Now().Add(-1*time.Minute))

	req := withCookie(httptest.NewRequest(http.MethodGet, "/", nil), "access_token", signed)
	rr := httptest.NewRecorder()

	middleware.Auth(sessions, testSecret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream handler should not be called")
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestAuth_WrongSigningKey(t *testing.T) {
	kek := []byte("32-byte-test-kek-for-unit-tests!")
	sessions, sessionToken := newSession(kek, "user-123", 15*time.Minute)

	// Sign with a different secret than the middleware uses
	signed := signJWT(t, sessionToken, []byte("wrong-secret"), time.Now().Add(15*time.Minute))

	req := withCookie(httptest.NewRequest(http.MethodGet, "/", nil), "access_token", signed)
	rr := httptest.NewRecorder()

	middleware.Auth(sessions, testSecret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream handler should not be called")
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestAuth_ValidJWTButExpiredSession(t *testing.T) {
	kek := []byte("32-byte-test-kek-for-unit-tests!")

	// Session is already expired in the SessionStore
	sessions, sessionToken := newSession(kek, "user-123", -1*time.Minute)

	// JWT itself is still valid
	signed := signJWT(t, sessionToken, testSecret, time.Now().Add(15*time.Minute))

	req := withCookie(httptest.NewRequest(http.MethodGet, "/", nil), "access_token", signed)
	rr := httptest.NewRecorder()

	middleware.Auth(sessions, testSecret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream handler should not be called")
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: JWT valid but session expired should still reject", rr.Code)
	}
}

func TestAuth_ValidJWTButDeletedSession(t *testing.T) {
	kek := []byte("32-byte-test-kek-for-unit-tests!")
	sessions, sessionToken := newSession(kek, "user-123", 15*time.Minute)

	signed := signJWT(t, sessionToken, testSecret, time.Now().Add(15*time.Minute))

	// Simulate logout — session deleted before request arrives
	sessions.Delete(sessionToken)

	req := withCookie(httptest.NewRequest(http.MethodGet, "/", nil), "access_token", signed)
	rr := httptest.NewRecorder()

	middleware.Auth(sessions, testSecret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream handler should not be called")
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: post-logout token must not work", rr.Code)
	}
}

// TestAuth_ContextHelpers confirms the exported helper functions work correctly
// and that an unprotected handler calling them gets (zero, false) — not a panic.
func TestAuth_ContextHelpers_MissingValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if kek, ok := middleware.KEKFromContext(req.Context()); ok || kek != nil {
		t.Error("want (nil, false) from empty context")
	}
	if id, ok := middleware.UserIDFromContext(req.Context()); ok || id != "" {
		t.Error("want (\"\", false) from empty context")
	}
}