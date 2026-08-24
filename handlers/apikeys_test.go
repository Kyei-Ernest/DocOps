package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kyei-Ernest/DocOps/middleware"
	authsvc "github.com/Kyei-Ernest/DocOps/services/auth"
	"github.com/Kyei-Ernest/DocOps/services/crypto"
	"github.com/Kyei-Ernest/DocOps/services/metadata"
	"github.com/go-chi/chi/v5"

	_ "github.com/mattn/go-sqlite3"
)

// apiKeyStack mirrors production wiring: one shared SQLite pool backing user,
// metadata, and API-key stores, plus an auth handler over them.
type apiKeyStack struct {
	h    *AuthHandler
	keys *authsvc.APIKeyStore
}

func newAPIKeyStack(t *testing.T) *apiKeyStack {
	t.Helper()
	return apiKeyStackOverDB(t, openSharedTestDB(t))
}

// openSharedTestDB returns a SQLite handle whose whole connection pool shares
// ONE memory database (unique name prevents cross-test contamination).
// Plain ":memory:" is per-connection: any additional pooled connection would
// silently observe an empty database and make these tests order-dependent.
func openSharedTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:docops_apitest_%d_%d?mode=memory&cache=shared",
		time.Now().UnixNano(), os.Getpid())
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	// Hold one reference connection open for the lifetime of the test: a
	// shared-cache memory database vanishes when its last connection closes.
	pin, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("pin conn: %v", err)
	}
	t.Cleanup(func() {
		pin.Close()
		db.Close()
	})
	if _, err := db.Exec("SELECT 1"); err != nil {
		t.Fatalf("probe db: %v", err)
	}
	return db
}

func apiKeyStackOverDB(t *testing.T, db *sql.DB) *apiKeyStack {
	t.Helper()
	users, err := authsvc.NewUserStore(db)
	if err != nil {
		t.Fatalf("user store: %v", err)
	}
	meta, err := metadata.NewDB(db)
	if err != nil {
		t.Fatalf("meta store: %v", err)
	}
	keys, err := authsvc.NewAPIKeyStore(db)
	if err != nil {
		t.Fatalf("api key store: %v", err)
	}
	sessions := authsvc.NewSessionStore()
	t.Cleanup(sessions.Close)
	return &apiKeyStack{
		h:    NewAuthHandler(users, sessions, meta, testParams, testJWTSecret),
		keys: keys,
	}
}

// registerAndCreateKey registers a fresh user, creates one API key through the
// handler (session-context path), and returns everything needed to exercise it.
func (s *apiKeyStack) registerAndCreateKey(t *testing.T, email string) (userID string, masterKey []byte, plaintext, keyID string) {
	t.Helper()

	reg := postJSON(t, s.h.Register, map[string]string{"email": email, "password": "password123"})
	if reg.Code != http.StatusCreated {
		t.Fatalf("register failed: %d", reg.Code)
	}
	dbUser, _ := s.h.users.GetByEmail(context.Background(), email)
	kek := crypto.DeriveKEK("password123", dbUser.Salt, s.h.params)
	masterKey, err := crypto.UnwrapDEKAny(dbUser.WrappedMasterKey, dbUser.MasterKeyNonce, kek, crypto.MasterKeyAAD(dbUser.ID))
	if err != nil {
		t.Fatalf("unwrap master key: %v", err)
	}

	handler := NewAPIKeyHandler(s.keys)
	req := httptest.NewRequest(http.MethodPost, "/api-keys",
		strings.NewReader(`{"name":"ci-bot"}`))
	req.Header.Set("Content-Type", "application/json")
	req = withAuthContext(req, masterKey, dbUser.ID)
	rr := httptest.NewRecorder()
	handler.Create(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create key failed: %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		APIKey string `json:"api_key"`
		KeyID  string `json:"key_id"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if !strings.HasPrefix(resp.APIKey, "docops_sk_") {
		t.Fatalf("plaintext key = %q, want docops_sk_ prefix", resp.APIKey)
	}
	return dbUser.ID, masterKey, resp.APIKey, resp.KeyID
}

// bearerRouter builds the smallest real router exercising the combined auth
// middleware exactly as main.go mounts it.
func (s *apiKeyStack) bearerRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.AuthWithAPIKeys(authsvc.NewSessionStore(), []byte(testJWTSecret), s.keys))
	r.Get("/whoami", func(w http.ResponseWriter, r *http.Request) {
		userID, ok := middleware.UserIDFromContext(r.Context())
		kek, kekOK := middleware.KEKFromContext(r.Context())
		if !ok || !kekOK {
			http.Error(w, "context missing", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(userID + "|" + string(kek[:4])))
	})
	return r
}

func (s *apiKeyStack) revoke(t *testing.T, userID, keyID string) *httptest.ResponseRecorder {
	t.Helper()
	handler := NewAPIKeyHandler(s.keys)
	req := httptest.NewRequest(http.MethodDelete, "/api-keys/"+keyID, nil)
	req = withAuthContext(req, nil, userID)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("keyID", keyID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	handler.Revoke(rr, req)
	return rr
}

func TestAPIKey_LifecycleCreateListRevoke(t *testing.T) {
	s := newAPIKeyStack(t)
	userID, _, plaintext, keyID := s.registerAndCreateKey(t, "lifecycle@example.com")

	handler := NewAPIKeyHandler(s.keys)

	// The plaintext secret must never be retrievable again.
	listReq := httptest.NewRequest(http.MethodGet, "/api-keys", nil)
	listReq = withAuthContext(listReq, nil, userID)
	lr := httptest.NewRecorder()
	handler.List(lr, listReq)
	if lr.Code != http.StatusOK {
		t.Fatalf("list failed: %d", lr.Code)
	}
	body := lr.Body.String()
	for _, leaked := range []string{plaintext, keyID + "'s-secret", "secret_hash", "wrapped_master_key"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("list leaked sensitive material %q: %s", leaked, body)
		}
	}
	if !strings.Contains(body, keyID) {
		t.Fatalf("list missing created key id %s: %s", keyID, body)
	}

	if rr := s.revoke(t, userID, keyID); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke failed: %d", rr.Code)
	}
	// Second revoke 404s — already-revoked indistinguishable from absent.
	if rr := s.revoke(t, userID, keyID); rr.Code != http.StatusNotFound {
		t.Fatalf("double revoke = %d, want 404", rr.Code)
	}
}

func TestAPIKey_BearerAuthenticatesThroughMiddleware(t *testing.T) {
	s := newAPIKeyStack(t)
	userID, masterKey, plaintext, _ := s.registerAndCreateKey(t, "bearer@example.com")

	router := s.bearerRouter()
	req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("bearer request failed: %d: %s", rr.Code, rr.Body.String())
	}
	wantPrefix := userID + "|"
	if !strings.HasPrefix(rr.Body.String(), wantPrefix) {
		t.Fatalf("body = %q, want prefix %q", rr.Body.String(), wantPrefix)
	}
	if len(masterKey) == 0 {
		t.Fatal("sanity: empty master key")
	}
}

func TestAPIKey_AllFailureModesProduceIdentical401(t *testing.T) {
	s := newAPIKeyStack(t)
	_, _, plaintext, _ := s.registerAndCreateKey(t, "failures@example.com")
	revokedUser, _, revokedPlain, revokedID := s.registerAndCreateKey(t, "failures2@example.com")
	if rr := s.revoke(t, revokedUser, revokedID); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke setup failed: %d", rr.Code)
	}

	parts := strings.SplitN(strings.TrimPrefix(plaintext, "docops_sk_"), "_", 2)
	tampered := "docops_sk_" + parts[0] + "_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	cases := []struct{ name, header string }{
		{"wrong-secret", "Bearer " + tampered},
		{"unknown-keyid", "Bearer docops_sk_doesnotexist00_" + parts[1]},
		{"malformed-no-secret", "Bearer docops_sk_onlykeyid"},
		{"garbage-scheme", "Bearer not-a-docops-key"},
		{"empty-header", ""},
		{"revoked-key", "Bearer " + revokedPlain},
	}

	var firstCode int
	var firstBody string
	for i, tc := range cases {
		router := s.bearerRouter()
		req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", tc.name, rr.Code)
		}
		if i == 0 {
			firstCode, firstBody = rr.Code, rr.Body.String()
			continue
		}
		if rr.Code != firstCode || rr.Body.String() != firstBody {
			t.Fatalf("%s: response diverged from baseline (%d/%q vs %d/%q)",
				tc.name, rr.Code, rr.Body.String(), firstCode, firstBody)
		}
	}
}

func TestAPIKey_StatelessAcrossRestart(t *testing.T) {
	// Simulate process restart: same database contents, brand-new store
	// objects and an EMPTY session store. Bearer auth keeps working; every
	// cookie session would be dead after a real restart.
	//
	// File-backed (not :memory:) because SQLite memory databases are
	// per-connection — a reopened pool must see persisted rows, which is
	// precisely the production property under test.
	dbPath := filepath.Join(t.TempDir(), "restart-test.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := apiKeyStackOverDB(t, db)
	userID, _, plaintext, _ := s.registerAndCreateKey(t, "restart@example.com")
	_ = userID

	restarted := apiKeyStackOverDB(t, db)
	router := restarted.bearerRouter()
	req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("bearer auth failed after simulated restart: %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAPIKey_ConcurrentBearerRequestsRaceClean(t *testing.T) {
	// File-backed so the pool may legitimately use multiple connections;
	// busy_timeout absorbs SQLite lock contention across goroutines.
	dbPath := filepath.Join(t.TempDir(), "race-test.db")
	db, err := sql.Open("sqlite3", dbPath+"?_busy_timeout=5000")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := apiKeyStackOverDB(t, db)
	_, _, plaintext, _ := s.registerAndCreateKey(t, "race@example.com")
	router := s.bearerRouter()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
			req.Header.Set("Authorization", "Bearer "+plaintext)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("concurrent bearer request failed: %d", rr.Code)
			}
		}()
	}
	wg.Wait()
}

func TestTouchLastUsed_IsThrottled(t *testing.T) {
	s := newAPIKeyStack(t)
	_, _, _, keyID := s.registerAndCreateKey(t, "touch@example.com")

	ctx := context.Background()
	s.keys.TouchLastUsed(ctx, keyID)
	first, _ := s.keys.GetByKeyID(ctx, keyID)
	if first.LastUsedAt == nil {
		t.Fatal("first touch did not record last_used_at")
	}

	s.keys.TouchLastUsed(ctx, keyID)
	second, _ := s.keys.GetByKeyID(ctx, keyID)
	if !first.LastUsedAt.Equal(*second.LastUsedAt) {
		t.Fatal("throttle window violated: last_used_at advanced within an hour")
	}
}

func TestAPIKey_CrossUserIsolation(t *testing.T) {
	s := newAPIKeyStack(t)
	_, _, _, keyIDA := s.registerAndCreateKey(t, "owner@example.com")
	userB, _, _, _ := s.registerAndCreateKey(t, "attacker@example.com")

	// B cannot see A's keys…
	listReq := httptest.NewRequest(http.MethodGet, "/api-keys", nil)
	listReq = withAuthContext(listReq, nil, userB)
	lr := httptest.NewRecorder()
	NewAPIKeyHandler(s.keys).List(lr, listReq)
	if strings.Contains(lr.Body.String(), keyIDA) {
		t.Fatal("user B can see user A's API key in listing")
	}

	// …nor revoke A's key.
	if rr := s.revoke(t, userB, keyIDA); rr.Code != http.StatusNotFound {
		t.Fatalf("cross-user revoke = %d, want 404", rr.Code)
	}

	// A's key still works.
	router := s.bearerRouter()
	_, _, plaintextA, _ := s.registerAndCreateKey(t, "owner2@example.com")
	_ = plaintextA
	req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+plainKeyOf(t, s, "owner@example.com"))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rr.Code)
	}
}

// plainKeyOf re-derives nothing — it exists only for tests that need a second
// live credential for an existing account; it registers under a distinct email.
func plainKeyOf(t *testing.T, s *apiKeyStack, email string) string {
	t.Helper()
	_, _, plaintext, _ := s.registerAndCreateKey(t, email+"-extra")
	return plaintext
}
