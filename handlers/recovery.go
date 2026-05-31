package handlers

import (
	"crypto/rand"
	"encoding/json"
	"net/http"

	"github.com/Kyei-Ernest/DocOps/middleware"
	"github.com/Kyei-Ernest/DocOps/services/crypto"
)

type recoverRequest struct {
	Email       string `json:"email"`
	RecoveryKey string `json:"recovery_key"`
	NewPassword string `json:"new_password"`
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type rotateMasterKeyRequest struct {
	Password string `json:"password"`
}

// Recover handles password recovery using the offline Recovery Key.
// POST /v0.1/auth/recover
func (h *AuthHandler) Recover(w http.ResponseWriter, r *http.Request) {
	var req recoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.RecoveryKey == "" || req.NewPassword == "" {
		http.Error(w, "email, recovery key, and new password are required", http.StatusBadRequest)
		return
	}

	user, err := h.users.GetByEmail(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		// Avoid user enumeration: return same generic status
		http.Error(w, "invalid credentials or recovery key", http.StatusUnauthorized)
		return
	}

	// 1. Derive recovery KEK from recovery key
	recoveryKEK := crypto.DeriveKEK(req.RecoveryKey, user.RecoverySalt, h.params)

	// 2. Decrypt (unwrap) the Master Key using the recovery KEK
	masterKey, err := crypto.UnwrapDEK(user.RecoveryWrappedMasterKey, user.RecoveryMasterKeyNonce, recoveryKEK)
	if err != nil {
		http.Error(w, "invalid credentials or recovery key", http.StatusUnauthorized)
		return
	}

	// 3. Derive new password-derived KEK & wrap the Master Key
	newPasswordHash, err := crypto.HashPassword(req.NewPassword, h.params)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newSalt, err := crypto.GenerateSalt()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newKEK := crypto.DeriveKEK(req.NewPassword, newSalt, h.params)
	newWrappedMasterKey, newMasterKeyNonce, err := crypto.WrapDEK(masterKey, newKEK)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 4. Update the user record
	user.PasswordHash = newPasswordHash
	user.Salt = newSalt
	user.WrappedMasterKey = newWrappedMasterKey
	user.MasterKeyNonce = newMasterKeyNonce

	if err := h.users.UpdateUserKeys(r.Context(), user); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password recovered successfully",
	})
}

// ChangePassword handles password changes for authenticated users.
// POST /v0.1/auth/change-password
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.OldPassword == "" || req.NewPassword == "" {
		http.Error(w, "old and new passwords are required", http.StatusBadRequest)
		return
	}

	// Active session MasterKey and UserID from context
	masterKey, ok := middleware.KEKFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Verify old password
	if _, err := crypto.VerifyPassword(req.OldPassword, user.PasswordHash); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Derive new password-derived KEK & wrap the Master Key
	newPasswordHash, err := crypto.HashPassword(req.NewPassword, h.params)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newSalt, err := crypto.GenerateSalt()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newKEK := crypto.DeriveKEK(req.NewPassword, newSalt, h.params)
	newWrappedMasterKey, newMasterKeyNonce, err := crypto.WrapDEK(masterKey, newKEK)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Update user record
	user.PasswordHash = newPasswordHash
	user.Salt = newSalt
	user.WrappedMasterKey = newWrappedMasterKey
	user.MasterKeyNonce = newMasterKeyNonce

	if err := h.users.UpdateUserKeys(r.Context(), user); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password changed successfully",
	})
}

// RotateMasterKey handles Master Key rotation.
// POST /v0.1/auth/rotate-master-key
func (h *AuthHandler) RotateMasterKey(w http.ResponseWriter, r *http.Request) {
	var req rotateMasterKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		http.Error(w, "password is required for key rotation", http.StatusBadRequest)
		return
	}

	oldMasterKey, ok := middleware.KEKFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Verify password to ensure we can derive KEK to re-wrap new master key
	if _, err := crypto.VerifyPassword(req.Password, user.PasswordHash); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// 1. Generate new Master Key
	newMasterKey := make([]byte, 32)
	if _, err := rand.Read(newMasterKey); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 2. Fetch all documents for this user
	docs, err := h.metaStore.ListAllForUser(r.Context(), userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 3. For each document: unwrap DEK with old master key, wrap with new master key
	for _, doc := range docs {
		if doc.EncryptedDEK != nil {
			dek, err := crypto.UnwrapDEK(doc.EncryptedDEK, doc.DEKNonce, oldMasterKey)
			if err != nil {
				http.Error(w, "failed to decrypt document key during rotation", http.StatusInternalServerError)
				return
			}
			newEncryptedDEK, newDEKNonce, err := crypto.WrapDEK(dek, newMasterKey)
			if err != nil {
				http.Error(w, "failed to encrypt document key during rotation", http.StatusInternalServerError)
				return
			}
			if err := h.metaStore.UpdateDEK(r.Context(), doc.ID, userID, newEncryptedDEK, newDEKNonce); err != nil {
				http.Error(w, "failed to update document key during rotation", http.StatusInternalServerError)
				return
			}
		}
	}

	// 4. Wrap new Master Key with password KEK
	kek := crypto.DeriveKEK(req.Password, user.Salt, h.params)
	newWrappedMasterKey, newMasterKeyNonce, err := crypto.WrapDEK(newMasterKey, kek)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 5. Generate new Recovery Key, derive KEK_recovery, and wrap new Master Key
	newRecoveryKey, err := generateRecoveryKey()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newRecoverySalt, err := crypto.GenerateSalt()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newRecoveryKEK := crypto.DeriveKEK(newRecoveryKey, newRecoverySalt, h.params)
	newRecoveryWrappedMasterKey, newRecoveryMasterKeyNonce, err := crypto.WrapDEK(newMasterKey, newRecoveryKEK)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 6. Update user record
	user.WrappedMasterKey = newWrappedMasterKey
	user.MasterKeyNonce = newMasterKeyNonce
	user.RecoverySalt = newRecoverySalt
	user.RecoveryWrappedMasterKey = newRecoveryWrappedMasterKey
	user.RecoveryMasterKeyNonce = newRecoveryMasterKeyNonce

	if err := h.users.UpdateUserKeys(r.Context(), user); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 7. Update current session in RAM to use the new master key!
	if cookie, err := r.Cookie("access_token"); err == nil {
		if claims, err := h.parseJWT(cookie.Value); err == nil {
			if session, ok := h.sessions.Get(claims.SessionToken); ok {
				session.KEK = newMasterKey // update KEK (which represents the Master Key) in RAM
				h.sessions.Save(claims.SessionToken, session)
			}
		}
	}
	if cookie, err := r.Cookie("refresh_token"); err == nil {
		if session, ok := h.sessions.Get(cookie.Value); ok {
			session.KEK = newMasterKey
			h.sessions.Save(cookie.Value, session)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"recovery_key": newRecoveryKey,
		"message":      "Master Key rotated successfully. Please store your new recovery key.",
	})
}
