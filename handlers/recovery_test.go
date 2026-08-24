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
	_ "github.com/mattn/go-sqlite3"
)

func TestRecover_Success(t *testing.T) {
	h := newTestHandler(t)

	// 1. Register a user
	regRR := postJSON(t, h.Register, map[string]string{
		"email":    "recover@example.com",
		"password": "oldpassword123",
	})
	if regRR.Code != http.StatusCreated {
		t.Fatalf("Register failed: %d", regRR.Code)
	}

	var regResp map[string]string
	json.NewDecoder(regRR.Body).Decode(&regResp)
	recoveryKey := regResp["recovery_key"]
	if recoveryKey == "" {
		t.Fatal("expected recovery key in register response, got empty")
	}

	// 2. Recover password
	recoverRR := postJSON(t, h.Recover, map[string]string{
		"email":        "recover@example.com",
		"recovery_key": recoveryKey,
		"new_password": "newpassword123",
	})
	if recoverRR.Code != http.StatusOK {
		t.Fatalf("Recover failed: %d: %s", recoverRR.Code, recoverRR.Body.String())
	}

	// 3. Try login with old password - should fail
	loginOldRR := postJSON(t, h.Login, map[string]string{
		"email":    "recover@example.com",
		"password": "oldpassword123",
	})
	if loginOldRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected login with old password to fail, got %d", loginOldRR.Code)
	}

	// 4. Try login with new password - should succeed
	loginNewRR := postJSON(t, h.Login, map[string]string{
		"email":    "recover@example.com",
		"password": "newpassword123",
	})
	if loginNewRR.Code != http.StatusOK {
		t.Fatalf("Login with new password failed: %d", loginNewRR.Code)
	}
}

func TestRecover_InvalidKey(t *testing.T) {
	h := newTestHandler(t)

	// Register a user
	postJSON(t, h.Register, map[string]string{
		"email":    "recover_fail@example.com",
		"password": "password123",
	})

	// Recover with wrong key
	recoverRR := postJSON(t, h.Recover, map[string]string{
		"email":        "recover_fail@example.com",
		"recovery_key": "docops_rec_invalid_recovery_key_here_12345",
		"new_password": "newpassword123",
	})
	if recoverRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected recover with wrong key to be unauthorized, got %d", recoverRR.Code)
	}
}

func TestChangePassword_Success(t *testing.T) {
	h := newTestHandler(t)

	// 1. Register a user
	postJSON(t, h.Register, map[string]string{
		"email":    "change@example.com",
		"password": "oldpassword123",
	})

	// 2. Fetch user to get ID and master key
	dbUser, err := h.users.GetByEmail(context.Background(), "change@example.com")
	if err != nil {
		t.Fatalf("failed to fetch user: %v", err)
	}

	// Unwrap master key to simulate middleware context
	kek := crypto.DeriveKEK("oldpassword123", dbUser.Salt, h.params)
	masterKey, err := crypto.UnwrapDEKAny(dbUser.WrappedMasterKey, dbUser.MasterKeyNonce, kek, crypto.MasterKeyAAD(dbUser.ID))
	if err != nil {
		t.Fatalf("failed to unwrap master key: %v", err)
	}

	// 3. Call change password
	body, _ := json.Marshal(map[string]string{
		"old_password": "oldpassword123",
		"new_password": "newpassword123",
	})
	req := httptest.NewRequest(http.MethodPost, "/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// inject auth context
	ctx := context.WithValue(req.Context(), middleware.KEKKey, masterKey)
	ctx = context.WithValue(ctx, middleware.UserIDKey, dbUser.ID)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.ChangePassword(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("ChangePassword failed: %d: %s", rr.Code, rr.Body.String())
	}

	// 4. Test login with new password
	loginRR := postJSON(t, h.Login, map[string]string{
		"email":    "change@example.com",
		"password": "newpassword123",
	})
	if loginRR.Code != http.StatusOK {
		t.Fatalf("Login with new password failed: %d", loginRR.Code)
	}
}

func TestRotateMasterKey_Success(t *testing.T) {
	h := newTestHandler(t)

	// 1. Register Alice
	regRR := postJSON(t, h.Register, map[string]string{
		"email":    "alice@example.com",
		"password": "password123",
	})
	if regRR.Code != http.StatusCreated {
		t.Fatalf("register failed: %d", regRR.Code)
	}
	var regResp map[string]string
	json.NewDecoder(regRR.Body).Decode(&regResp)
	oldRecoveryKey := regResp["recovery_key"]

	dbUser, _ := h.users.GetByEmail(context.Background(), "alice@example.com")
	kek := crypto.DeriveKEK("password123", dbUser.Salt, h.params)
	oldMasterKey, _ := crypto.UnwrapDEKAny(dbUser.WrappedMasterKey, dbUser.MasterKeyNonce, kek, crypto.MasterKeyAAD(dbUser.ID))

	// 2. Upload a document for Alice
	docID := "doc_rotation_test"
	dek, _ := crypto.GenerateDEK()
	encryptedDEK, dekNonce, _ := crypto.WrapDEK(dek, oldMasterKey)
	doc := &models.Document{
		ID:           docID,
		UserID:       dbUser.ID,
		Name:         "secret.txt",
		FileType:     "text/plain",
		Provider:     "local",
		StorageKey:   "secret-key",
		Encrypted:    true,
		EncryptedDEK: encryptedDEK,
		DEKNonce:     dekNonce,
		FileNonce:    []byte("filenonce123"),
	}
	if err := h.metaStore.Save(context.Background(), doc); err != nil {
		t.Fatalf("failed to save doc: %v", err)
	}

	// 3. Rotate Alice's Master Key
	body, _ := json.Marshal(map[string]string{
		"password": "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/rotate-master-key", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), middleware.KEKKey, oldMasterKey)
	ctx = context.WithValue(ctx, middleware.UserIDKey, dbUser.ID)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.RotateMasterKey(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("RotateMasterKey failed: %d: %s", rr.Code, rr.Body.String())
	}

	var rotResp map[string]string
	json.NewDecoder(rr.Body).Decode(&rotResp)
	newRecoveryKey := rotResp["recovery_key"]
	if newRecoveryKey == "" || newRecoveryKey == oldRecoveryKey {
		t.Fatalf("expected new distinct recovery key, got: %q", newRecoveryKey)
	}

	// 4. Verify we can still decrypt the document DEK with the NEW Master Key
	// Fetch updated user to get the new wrapped master key
	dbUserUpdated, _ := h.users.GetByEmail(context.Background(), "alice@example.com")
	newKek := crypto.DeriveKEK("password123", dbUserUpdated.Salt, h.params)
	newMasterKey, err := crypto.UnwrapDEKAny(dbUserUpdated.WrappedMasterKey, dbUserUpdated.MasterKeyNonce, newKek, crypto.MasterKeyAAD(dbUserUpdated.ID))
	if err != nil {
		t.Fatalf("failed to decrypt new master key: %v", err)
	}

	// Fetch updated doc metadata
	updatedDoc, err := h.metaStore.GetByID(context.Background(), docID, dbUser.ID)
	if err != nil {
		t.Fatalf("failed to fetch doc: %v", err)
	}

	// Unwrap document DEK using the NEW Master Key
	unwrappedDEK, err := crypto.UnwrapDEKAny(updatedDoc.EncryptedDEK, updatedDoc.DEKNonce, newMasterKey,
		crypto.DEKAAD(dbUser.ID, docID))
	if err != nil {
		t.Fatalf("failed to decrypt document DEK using new rotated master key: %v", err)
	}

	if string(unwrappedDEK) != string(dek) {
		t.Error("decrypted DEK mismatch after master key rotation!")
	}

	// 5. Verify the old recovery key fails and the new recovery key succeeds
	recoverOldRR := postJSON(t, h.Recover, map[string]string{
		"email":        "alice@example.com",
		"recovery_key": oldRecoveryKey,
		"new_password": "recoveredpassword",
	})
	if recoverOldRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected recovery with old recovery key to fail, got %d", recoverOldRR.Code)
	}

	recoverNewRR := postJSON(t, h.Recover, map[string]string{
		"email":        "alice@example.com",
		"recovery_key": newRecoveryKey,
		"new_password": "recoveredpassword",
	})
	if recoverNewRR.Code != http.StatusOK {
		t.Fatalf("recovery with new recovery key failed: %d: %s", recoverNewRR.Code, recoverNewRR.Body.String())
	}
}
