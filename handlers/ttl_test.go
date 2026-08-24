package handlers

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Kyei-Ernest/DocOps/models"
)

func saveDocWithExpiry(t *testing.T, h *AuthHandler, userID, id string, expires *time.Time) {
	t.Helper()
	doc := &models.Document{
		ID: id, UserID: userID, Name: id + ".txt", FileType: "text/plain",
		Provider: "local", StorageKey: "sk-" + id, Encrypted: true,
		EncryptedDEK: []byte("irrelevant-when-expired"),
		DEKNonce:     []byte("123456789012"),
		FileNonce:    []byte("123456789012"),
		ExpiresAt:    expires,
	}
	if err := h.metaStore.Save(context.Background(), doc); err != nil {
		t.Fatalf("save %s: %v", id, err)
	}
}

func TestDownload_ExpiredDocumentIs404(t *testing.T) {
	h := newTestHandler(t)
	postJSON(t, h.Register, map[string]string{"email": "ttl@example.com", "password": "password123"})
	dbUser, _ := h.users.GetByEmail(context.Background(), "ttl@example.com")

	past := time.Now().Add(-time.Hour)
	saveDocWithExpiry(t, h, dbUser.ID, "doc_expired_ttl", &past)
	future := time.Now().Add(time.Hour)
	saveDocWithExpiry(t, h, dbUser.ID, "doc_live_ttl", &future)
	saveDocWithExpiry(t, h, dbUser.ID, "doc_never_ttl", nil)

	dl := NewDownloadHandler(newMockConnector(), h.metaStore)

	req, rr := downloadRequest(t, "doc_expired_ttl", []byte("anykek"), dbUser.ID)
	dl.Download(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expired doc = %d, want 404 (existence-hiding)", rr.Code)
	}

	req2, rr2 := downloadRequest(t, "doc_never_ttl", []byte("anykek"), dbUser.ID)
	dl.Download(rr2, req2)
	// Non-expired row proceeds past the TTL gate; it fails later on the
	// unwrap (bogus key material here) — anything other than the TTL 404
	// proves the gate opened.
	if rr2.Code == http.StatusNotFound {
		t.Fatal("non-expired document was wrongly rejected by TTL gate")
	}
	_ = future
}
