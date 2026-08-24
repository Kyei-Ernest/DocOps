package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authsvc "github.com/Kyei-Ernest/DocOps/services/auth"
)

func TestRefreshTokenStore_RoundTripAndStates(t *testing.T) {
	db := openSharedTestDB(t)
	store, err := authsvc.NewRefreshTokenStore(db)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	ctx := context.Background()

	token := "test-refresh-token-value"
	if err := store.Save(ctx, token, "user-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("save: %v", err)
	}

	rec, err := store.GetValid(ctx, token)
	if err != nil || rec == nil {
		t.Fatalf("get valid: %v %v", rec, err)
	}
	if rec.UserID != "user-1" {
		t.Fatalf("user_id = %q", rec.UserID)
	}

	// At-rest form must be the hash only — the plaintext token never lands
	// in the table.
	var count int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM refresh_tokens WHERE token_hash = ?`,
		[]byte(token)).Scan(&count); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if count != 0 {
		t.Fatal("plaintext refresh token found in storage")
	}
	if got := authsvc.HashRefreshToken(token); !strings.EqualFold(string(got[:4]), string(rec.TokenHash[:4])) {
		t.Fatal("record hash mismatch")
	}

	// Revocation kills it.
	if err := store.Revoke(ctx, token); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if rec, _ := store.GetValid(ctx, token); rec != nil {
		t.Fatal("revoked token still resolves")
	}
	// Idempotent.
	if err := store.Revoke(ctx, token); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
}

func TestRefreshTokenStore_ExpiredIsInvalid(t *testing.T) {
	db := openSharedTestDB(t)
	store, _ := authsvc.NewRefreshTokenStore(db)
	ctx := context.Background()

	token := "expired-token"
	if err := store.Save(ctx, token, "user-2", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("save: %v", err)
	}
	if rec, _ := store.GetValid(ctx, token); rec != nil {
		t.Fatal("expired token resolved as valid")
	}

	// Recently-expired rows stay put (24h audit grace).
	if n, err := store.PurgeExpired(ctx); err != nil || n != 0 {
		t.Fatalf("grace purge = %d, %v; want 0", n, err)
	}

	// Long-dead rows are collected.
	old := "ancient-token"
	if err := store.Save(ctx, old, "user-2", time.Now().Add(-25*time.Hour)); err != nil {
		t.Fatalf("save ancient: %v", err)
	}
	n, err := store.PurgeExpired(ctx)
	if err != nil || n == 0 {
		t.Fatalf("purge = %d, %v", n, err)
	}
}

// TestLogout_RevokesDurableRefreshToken proves the restart-survival property:
// after logout, the durable record is dead even for a freshly-reopened store.
func TestLogout_RevokesDurableRefreshToken(t *testing.T) {
	db := openSharedTestDB(t)
	stack := apiKeyStackOverDB(t, db)

	refresh, err := authsvc.NewRefreshTokenStore(db)
	if err != nil {
		t.Fatalf("refresh store: %v", err)
	}
	h := NewAuthHandlerWithRefresh(stack.h.users, stack.h.sessions, stack.h.metaStore, refresh, testParams, testJWTSecret)

	regRR := postJSON(t, h.Register, map[string]string{
		"email":    "durable@example.com",
		"password": "password123",
	})
	if regRR.Code != http.StatusCreated {
		t.Fatalf("register failed: %d", regRR.Code)
	}

	// Pull the issued refresh cookie from the register response.
	var rawCookie string
	for _, c := range regRR.Result().Cookies() {
		if c.Name == "refresh_token" {
			rawCookie = c.Value
		}
	}
	if rawCookie == "" {
		t.Fatal("no refresh_token cookie issued at register")
	}
	if rec, _ := refresh.GetValid(context.Background(), rawCookie); rec == nil {
		t.Fatal("durable record missing right after issue")
	}

	logoutReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logoutReq.AddCookie(&http.Cookie{Name: "refresh_token", Value: rawCookie})
	lrr := httptest.NewRecorder()
	h.Logout(lrr, logoutReq)
	if lrr.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", lrr.Code)
	}

	// Reopen the store — simulating a later process lifetime.
	reopened, err := authsvc.NewRefreshTokenStore(db)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if rec, _ := reopened.GetValid(context.Background(), rawCookie); rec != nil {
		t.Fatal("revoked refresh token still valid after store reopen")
	}
}
