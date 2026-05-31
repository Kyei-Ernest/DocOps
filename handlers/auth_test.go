package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyei-Ernest/DocOps/models"
	authsvc "github.com/Kyei-Ernest/DocOps/services/auth"
	"github.com/Kyei-Ernest/DocOps/services/metadata"
	_ "github.com/mattn/go-sqlite3"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

// testParams uses intentionally cheap Argon2id settings so tests run fast.
// Never use these values in production — they provide no real security.
var testParams = &models.Argon2Config{
	Memory:      64 * 1024,
	Iterations:  1,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

var testJWTSecret = []byte("test-secret-not-for-production")

// newTestHandler wires up an AuthHandler backed by an in-memory SQLite DB.
func newTestHandler(t *testing.T) *AuthHandler {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	users, err := authsvc.NewUserStore(db)
	if err != nil {
		t.Fatalf("new user store: %v", err)
	}

	sessions := authsvc.NewSessionStore()

	metaStore, err := metadata.New(":memory:")
	if err != nil {
		t.Fatalf("new metadata store: %v", err)
	}
	t.Cleanup(func() { metaStore.Close() })

	return NewAuthHandler(users, sessions, metaStore, testParams, testJWTSecret)
}

// postJSON fires a POST request with a JSON body and returns the recorder.
func postJSON(t *testing.T, h http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

// postJSONWithCookies fires a POST with a JSON body and attaches the provided
// cookies (used for Refresh and Logout which read cookies from the request).
func postJSONWithCookies(t *testing.T, h http.HandlerFunc, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

// getCookies returns all cookies set on the recorder response by name.
func getCookies(rr *httptest.ResponseRecorder) map[string]*http.Cookie {
	result := make(map[string]*http.Cookie)
	// Parse Set-Cookie headers via a throwaway http.Response
	resp := &http.Response{Header: http.Header{"Set-Cookie": rr.Header()["Set-Cookie"]}}
	for _, c := range resp.Cookies() {
		result[c.Name] = c
	}
	return result
}

// ── Register tests ────────────────────────────────────────────────────────────

func TestRegister_Success(t *testing.T) {
	h := newTestHandler(t)

	rr := postJSON(t, h.Register, map[string]string{
		"email":    "alice@example.com",
		"password": "hunter2",
	})

	if rr.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	cookies := getCookies(rr)

	if _, ok := cookies["access_token"]; !ok {
		t.Error("want access_token cookie, got none")
	}
	if _, ok := cookies["refresh_token"]; !ok {
		t.Error("want refresh_token cookie, got none")
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	h := newTestHandler(t)

	body := map[string]string{"email": "alice@example.com", "password": "hunter2"}
	postJSON(t, h.Register, body) // first registration

	rr := postJSON(t, h.Register, body) // duplicate
	if rr.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d", rr.Code)
	}
}

func TestRegister_MissingFields(t *testing.T) {
	h := newTestHandler(t)

	cases := []map[string]string{
		{"email": "", "password": "hunter2"},
		{"email": "alice@example.com", "password": ""},
		{},
	}
	for _, body := range cases {
		rr := postJSON(t, h.Register, body)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("body %v: want 400, got %d", body, rr.Code)
		}
	}
}

func TestRegister_InvalidJSON(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("not-json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rr.Code)
	}
}

// ── Login tests ───────────────────────────────────────────────────────────────

func TestLogin_Success(t *testing.T) {
	h := newTestHandler(t)

	// Register first so the user exists
	postJSON(t, h.Register, map[string]string{
		"email":    "bob@example.com",
		"password": "correct-horse",
	})

	rr := postJSON(t, h.Login, map[string]string{
		"email":    "bob@example.com",
		"password": "correct-horse",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	cookies := getCookies(rr)
	if _, ok := cookies["access_token"]; !ok {
		t.Error("want access_token cookie, got none")
	}
	if _, ok := cookies["refresh_token"]; !ok {
		t.Error("want refresh_token cookie, got none")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	h := newTestHandler(t)

	postJSON(t, h.Register, map[string]string{
		"email":    "bob@example.com",
		"password": "correct-horse",
	})

	rr := postJSON(t, h.Login, map[string]string{
		"email":    "bob@example.com",
		"password": "wrong-password",
	})

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestLogin_UnknownEmail(t *testing.T) {
	h := newTestHandler(t)

	rr := postJSON(t, h.Login, map[string]string{
		"email":    "ghost@example.com",
		"password": "doesntmatter",
	})

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

// TestLogin_SameErrorForBadEmailAndBadPassword asserts that the response body
// is identical for "no such user" and "wrong password" — no user enumeration.
func TestLogin_SameErrorForBadEmailAndBadPassword(t *testing.T) {
	h := newTestHandler(t)

	postJSON(t, h.Register, map[string]string{
		"email":    "real@example.com",
		"password": "realpassword",
	})

	badEmail := postJSON(t, h.Login, map[string]string{
		"email":    "fake@example.com",
		"password": "doesntmatter",
	})
	badPass := postJSON(t, h.Login, map[string]string{
		"email":    "real@example.com",
		"password": "wrongpassword",
	})

	if badEmail.Body.String() != badPass.Body.String() {
		t.Errorf("error bodies differ — user enumeration possible\ngot (bad email): %q\ngot (bad pass):  %q",
			badEmail.Body.String(), badPass.Body.String())
	}
}

// ── Refresh tests ─────────────────────────────────────────────────────────────

func TestRefresh_Success(t *testing.T) {
	h := newTestHandler(t)

	// Register to get initial cookies
	rr := postJSON(t, h.Register, map[string]string{
		"email":    "carol@example.com",
		"password": "secret",
	})
	cookies := getCookies(rr)
	refreshCookie := cookies["refresh_token"]
	if refreshCookie == nil {
		t.Fatal("no refresh_token cookie from Register")
	}

	rr2 := postJSONWithCookies(t, h.Refresh, nil, []*http.Cookie{refreshCookie})
	if rr2.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr2.Code, rr2.Body.String())
	}

	if _, ok := getCookies(rr2)["access_token"]; !ok {
		t.Error("want new access_token cookie after refresh, got none")
	}
}

func TestRefresh_MissingCookie(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rr := httptest.NewRecorder()
	h.Refresh(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestRefresh_InvalidToken(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "totally-fake-token"})
	rr := httptest.NewRecorder()
	h.Refresh(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

// ── Logout tests ──────────────────────────────────────────────────────────────

func TestLogout_ClearsCookies(t *testing.T) {
	h := newTestHandler(t)

	rr := postJSON(t, h.Register, map[string]string{
		"email":    "dave@example.com",
		"password": "secret",
	})
	cookies := getCookies(rr)

	logoutReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	for _, c := range cookies {
		logoutReq.AddCookie(c)
	}
	logoutRR := httptest.NewRecorder()
	h.Logout(logoutRR, logoutReq)

	if logoutRR.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", logoutRR.Code)
	}

	// Both cookies must be present in the response with MaxAge=-1 (cleared)
	cleared := getCookies(logoutRR)
	for _, name := range []string{"access_token", "refresh_token"} {
		c, ok := cleared[name]
		if !ok {
			t.Errorf("want %s cookie cleared, not present in response", name)
			continue
		}
		if c.MaxAge != -1 {
			t.Errorf("%s: want MaxAge=-1, got %d", name, c.MaxAge)
		}
	}
}

// TestLogout_RefreshTokenInvalidatedAfterLogout confirms the server-side
// refresh session is deleted — a refresh attempt after logout must fail.
func TestLogout_RefreshTokenInvalidatedAfterLogout(t *testing.T) {
	h := newTestHandler(t)

	rr := postJSON(t, h.Register, map[string]string{
		"email":    "eve@example.com",
		"password": "secret",
	})
	cookies := getCookies(rr)
	refreshCookie := cookies["refresh_token"]

	// Logout
	logoutReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	for _, c := range cookies {
		logoutReq.AddCookie(c)
	}
	logoutRR := httptest.NewRecorder()
	h.Logout(logoutRR, logoutReq)

	// Attempt refresh with the now-invalidated token — must be rejected
	rr2 := postJSONWithCookies(t, h.Refresh, nil, []*http.Cookie{refreshCookie})
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 after logout, got %d", rr2.Code)
	}
}

// TestLogout_NoopWithoutCookies confirms Logout is safe to call with no session.
func TestLogout_NoopWithoutCookies(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	rr := httptest.NewRecorder()
	h.Logout(rr, req.WithContext(context.Background()))

	if rr.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", rr.Code)
	}
}
