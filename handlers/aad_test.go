package handlers

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Kyei-Ernest/DocOps/models"
	"github.com/Kyei-Ernest/DocOps/services/crypto"
)

// streamForTest encrypts plaintext under dek and returns the base file nonce.
func streamForTest(t *testing.T, plaintext []byte, dek []byte) []byte {
	t.Helper()
	nonce, err := crypto.EncryptStream(bytes.NewReader(plaintext), io.Discard, dek)
	if err != nil {
		t.Fatalf("encrypt stream: %v", err)
	}
	return nonce
}

// TestDownload_RejectsSwappedWrappedDEK plants doc2's wrapped DEK into doc1's
// row (both owned by the same user — no cross-user privilege needed) and
// asserts the download fails instead of serving plaintext. This is the
// attack AAD binding exists to kill.
func TestDownload_RejectsSwappedWrappedDEK(t *testing.T) {
	h := newTestHandler(t)

	reg := postJSON(t, h.Register, map[string]string{"email": "swap@example.com", "password": "password123"})
	if reg.Code != http.StatusCreated {
		t.Fatalf("register failed: %d", reg.Code)
	}
	dbUser, _ := h.users.GetByEmail(context.Background(), "swap@example.com")
	kek := crypto.DeriveKEK("password123", dbUser.Salt, h.params)
	masterKey, err := crypto.UnwrapDEKAny(dbUser.WrappedMasterKey, dbUser.MasterKeyNonce, kek, crypto.MasterKeyAAD(dbUser.ID))
	if err != nil {
		t.Fatalf("unwrap master key: %v", err)
	}

	saveDoc := func(id string) *models.Document {
		t.Helper()
		dek, _ := crypto.GenerateDEK()
		fileNonce := streamForTest(t, []byte("secret contents of "+id), dek)
		encDEK, dekNonce, _ := crypto.WrapDEKBound(dek, masterKey, crypto.DEKAAD(dbUser.ID, id))
		doc := &models.Document{
			ID: id, UserID: dbUser.ID, Name: id + ".txt", FileType: "text/plain",
			Provider: "local", StorageKey: "sk-" + id, Encrypted: true,
			SizeBytes:    10,
			EncryptedDEK: encDEK, DEKNonce: dekNonce, FileNonce: fileNonce,
		}
		if err := h.metaStore.Save(context.Background(), doc); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
		return doc
	}
	doc1 := saveDoc("doc_swap_1")
	doc2 := saveDoc("doc_swap_2")

	// Swap: plant doc2's wrapped DEK into doc1's row.
	if err := h.metaStore.UpdateDEK(context.Background(), doc1.ID, dbUser.ID, doc2.EncryptedDEK, doc2.DEKNonce); err != nil {
		t.Fatalf("plant swap: %v", err)
	}

	dl := NewDownloadHandler(newMockConnector(), h.metaStore)
	req, rr := downloadRequest(t, doc1.ID, masterKey, dbUser.ID)
	dl.Download(rr, req)

	// Bound wrap carries doc2's AAD; opening under doc1's context must fail
	// closed rather than decrypting to doc2's plaintext under doc1's name.
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (unwrap failure); body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "secret contents") {
		t.Fatal("plaintext leaked despite swapped wrapped DEK")
	}
}

// TestDownload_LegacyUnboundDEKStillOpens pins the migration contract: rows
// written before AAD binding shipped must remain downloadable until rotation
// upgrades them.
func TestDownload_LegacyUnboundDEKStillOpens(t *testing.T) {
	h := newTestHandler(t)

	postJSON(t, h.Register, map[string]string{"email": "legacy@example.com", "password": "password123"})
	dbUser, _ := h.users.GetByEmail(context.Background(), "legacy@example.com")
	kek := crypto.DeriveKEK("password123", dbUser.Salt, h.params)
	masterKey, err := crypto.UnwrapDEKAny(dbUser.WrappedMasterKey, dbUser.MasterKeyNonce, kek, crypto.MasterKeyAAD(dbUser.ID))
	if err != nil {
		t.Fatalf("unwrap master key: %v", err)
	}

	const secret = "legacy plaintext payload"
	dek, _ := crypto.GenerateDEK()

	// Encrypt exactly once — the framed ciphertext AND its base nonce must
	// come from the same sealing pass or decryption cannot succeed.
	var ct bytes.Buffer
	fileNonce, err := crypto.EncryptStream(bytes.NewReader([]byte(secret)), &ct, dek)
	if err != nil {
		t.Fatalf("build ciphertext: %v", err)
	}

	// Deliberately use the LEGACY unbound wrap (pre-P0-4 row shape).
	encDEK, dekNonce, _ := crypto.WrapDEK(dek, masterKey)
	doc := &models.Document{
		ID: "doc_legacy_1", UserID: dbUser.ID, Name: "old.txt", FileType: "text/plain",
		Provider: "local", StorageKey: "sk-legacy", Encrypted: true,
		EncryptedDEK: encDEK, DEKNonce: dekNonce, FileNonce: fileNonce,
	}
	if err := h.metaStore.Save(context.Background(), doc); err != nil {
		t.Fatalf("save legacy doc: %v", err)
	}
	mc := newMockConnector()
	mc.uploaded[doc.StorageKey] = ct.Bytes()
	dl := NewDownloadHandler(mc, h.metaStore)
	req, rr := downloadRequest(t, doc.ID, masterKey, dbUser.ID)
	dl.Download(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for legacy row: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), secret) {
		t.Fatal("legacy document did not round-trip its plaintext")
	}
}
