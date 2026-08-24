package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyei-Ernest/DocOps/middleware"
	"github.com/Kyei-Ernest/DocOps/models"
	"github.com/Kyei-Ernest/DocOps/services/crypto"
)

// TestRotateMasterKey_RollsBackAtomically injects a mid-loop failure (a
// corrupted wrapped DEK on the second document) and asserts the whole
// rotation rolls back: every DEK wrap and the user key row keep their
// pre-rotation values, and the old Master Key remains authoritative.
func TestRotateMasterKey_RollsBackAtomically(t *testing.T) {
	h := newTestHandler(t)

	regRR := postJSON(t, h.Register, map[string]string{
		"email":    "atomic@example.com",
		"password": "password123",
	})
	if regRR.Code != http.StatusCreated {
		t.Fatalf("register failed: %d", regRR.Code)
	}

	dbUser, err := h.users.GetByEmail(context.Background(), "atomic@example.com")
	if err != nil {
		t.Fatalf("fetch user: %v", err)
	}
	kek := crypto.DeriveKEK("password123", dbUser.Salt, h.params)
	oldMasterKey, err := crypto.UnwrapDEKAny(dbUser.WrappedMasterKey, dbUser.MasterKeyNonce, kek, crypto.MasterKeyAAD(dbUser.ID))
	if err != nil {
		t.Fatalf("unwrap master key: %v", err)
	}

	// doc1 wraps a real DEK under the current master key; doc2 carries a
	// corrupted blob that fails GCM authentication — unwrapping it mid-tx
	// aborts the rotation after doc1's UPDATE has already been applied.
	dek1, _ := crypto.GenerateDEK()
	enc1, nonce1, _ := crypto.WrapDEK(dek1, oldMasterKey)

	save := func(id string, enc, nonce []byte) {
		t.Helper()
		doc := &models.Document{
			ID:           id,
			UserID:       dbUser.ID,
			Name:         id + ".txt",
			FileType:     "text/plain",
			Provider:     "local",
			StorageKey:   "sk-" + id,
			Encrypted:    true,
			EncryptedDEK: enc,
			DEKNonce:     nonce,
			FileNonce:    []byte("filenonce123"),
		}
		if err := h.metaStore.Save(context.Background(), doc); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	save("doc_ok_1", enc1, nonce1)
	corruptWrap := []byte("definitely-not-a-valid-gcm-ciphertext!!")
	corruptNonce := []byte("123456789012") // 12 bytes, well-formed length
	save("doc_corrupt_2", corruptWrap, corruptNonce)

	// Capture pre-rotation state.
	beforeUser, _ := h.users.GetByEmail(context.Background(), "atomic@example.com")
	beforeDoc1, err := h.metaStore.GetByID(context.Background(), "doc_ok_1", dbUser.ID)
	if err != nil {
		t.Fatalf("fetch doc1: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"password": "password123"})
	req := httptest.NewRequest(http.MethodPost, "/rotate-master-key", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), middleware.KEKKey, oldMasterKey)
	ctx = context.WithValue(ctx, middleware.UserIDKey, dbUser.ID)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.RotateMasterKey(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}

	// User key row must be untouched.
	afterUser, _ := h.users.GetByEmail(context.Background(), "atomic@example.com")
	if !bytes.Equal(beforeUser.WrappedMasterKey, afterUser.WrappedMasterKey) ||
		!bytes.Equal(beforeUser.MasterKeyNonce, afterUser.MasterKeyNonce) ||
		!bytes.Equal(beforeUser.RecoveryWrappedMasterKey, afterUser.RecoveryWrappedMasterKey) ||
		string(beforeUser.PasswordHash) != string(afterUser.PasswordHash) ||
		string(beforeUser.Salt) != string(afterUser.Salt) {
		t.Fatal("user key row changed despite rolled-back rotation")
	}

	// Every document wrap must be untouched — including doc1, whose UPDATE
	// ran before the abort. This is the property the non-transactional
	// implementation could not guarantee.
	for _, id := range []string{"doc_ok_1", "doc_corrupt_2"} {
		after, err := h.metaStore.GetByID(context.Background(), id, dbUser.ID)
		if err != nil {
			t.Fatalf("fetch %s post-rollback: %v", id, err)
		}
		if !bytes.Equal(after.EncryptedDEK, corruptOr(beforeDoc1.EncryptedDEK, corruptWrap, id)) {
			t.Fatalf("%s encrypted_dek changed despite rollback", id)
		}
	}

	// The system is still fully usable with the OLD master key.
	got, err := crypto.UnwrapDEK(beforeDoc1.EncryptedDEK, beforeDoc1.DEKNonce, oldMasterKey)
	if err != nil {
		t.Fatalf("old master key no longer unwraps doc DEK after rollback: %v", err)
	}
	if !bytes.Equal(got, dek1) {
		t.Fatal("unwrapped DEK mismatch after rollback")
	}

	// And a subsequent healthy rotation succeeds from the consistent state.
	// First remove the corrupted document (an operator repairing the row
	// that caused the abort), then rotate again.
	if err := h.metaStore.Delete(context.Background(), "doc_corrupt_2", dbUser.ID); err != nil {
		t.Fatalf("remove corrupt doc: %v", err)
	}
	retryBody, _ := json.Marshal(map[string]string{"password": "password123"})
	retryReq := httptest.NewRequest(http.MethodPost, "/rotate-master-key", bytes.NewReader(retryBody))
	retryCtx := context.WithValue(retryReq.Context(), middleware.KEKKey, oldMasterKey)
	retryCtx = context.WithValue(retryCtx, middleware.UserIDKey, dbUser.ID)
	retryReq = retryReq.WithContext(retryCtx)
	retryRR := httptest.NewRecorder()
	h.RotateMasterKey(retryRR, retryReq)
	if retryRR.Code != http.StatusOK {
		t.Fatalf("retry rotation failed: %d: %s", retryRR.Code, retryRR.Body.String())
	}
}

// corruptOr returns the expected pre-rotation blob for the given document id.
// The corrupted document's expected value is its injected garbage itself.
func corruptOr(validBlob, corruptBlob []byte, id string) []byte {
	if id == "doc_corrupt_2" {
		return corruptBlob
	}
	return validBlob
}
