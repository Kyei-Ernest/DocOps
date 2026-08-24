package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/Kyei-Ernest/DocOps/middleware"
	authsvc "github.com/Kyei-Ernest/DocOps/services/auth"
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
		audit(r, "recover_failed", "email", req.Email, "reason", "unknown_user")
		http.Error(w, "invalid credentials or recovery key", http.StatusUnauthorized)
		return
	}

	// 1. Derive recovery KEK from recovery key using the parameters captured
	//    at wrap time — live config may have moved on since registration.
	recoveryKEK := crypto.DeriveKEK(req.RecoveryKey, user.RecoverySalt, kekParamsFor(user, h.params, "recovery"))

	// 2. Decrypt (unwrap) the Master Key using the recovery KEK
	masterKey, err := crypto.UnwrapDEKAny(user.RecoveryWrappedMasterKey, user.RecoveryMasterKeyNonce, recoveryKEK, crypto.RecoveryKeyAAD(user.ID))
	if err != nil {
		audit(r, "recover_failed", "user_id", user.ID, "reason", "unwrap_failed")
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
	newWrappedMasterKey, newMasterKeyNonce, err := crypto.WrapDEKBound(masterKey, newKEK, crypto.MasterKeyAAD(user.ID))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 4. Update the user record
	user.PasswordHash = newPasswordHash
	user.Salt = newSalt
	user.WrappedMasterKey = newWrappedMasterKey
	user.MasterKeyNonce = newMasterKeyNonce
	user.KEKParams = authsvc.FormatArgon2Params(h.params) // fresh wrap under current config

	if err := h.users.UpdateUserKeys(r.Context(), user); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	audit(r, "recover_success", "user_id", user.ID)
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
		audit(r, "change_password_failed", "user_id", userID, "reason", "bad_old_password")
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
	newWrappedMasterKey, newMasterKeyNonce, err := crypto.WrapDEKBound(masterKey, newKEK, crypto.MasterKeyAAD(user.ID))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Update user record
	user.PasswordHash = newPasswordHash
	user.Salt = newSalt
	user.WrappedMasterKey = newWrappedMasterKey
	user.MasterKeyNonce = newMasterKeyNonce
	user.KEKParams = authsvc.FormatArgon2Params(h.params) // fresh wrap under current config

	if err := h.users.UpdateUserKeys(r.Context(), user); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	audit(r, "change_password_success", "user_id", userID)
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
		audit(r, "rotate_master_key_failed", "user_id", userID, "reason", "bad_password")
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// 1. Generate new Master Key
	newMasterKey := make([]byte, 32)
	if _, err := rand.Read(newMasterKey); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 2. Pre-compute every wrap that does not depend on document rows —
	//    all pure crypto, so a failure here aborts before any DB write.
	kek := crypto.DeriveKEK(req.Password, user.Salt, h.params)
	newWrappedMasterKey, newMasterKeyNonce, err := crypto.WrapDEKBound(newMasterKey, kek, crypto.MasterKeyAAD(userID))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

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
	newRecoveryWrappedMasterKey, newRecoveryMasterKeyNonce, err := crypto.WrapDEKBound(newMasterKey, newRecoveryKEK, crypto.RecoveryKeyAAD(userID))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	user.WrappedMasterKey = newWrappedMasterKey
	user.MasterKeyNonce = newMasterKeyNonce
	user.RecoverySalt = newRecoverySalt
	user.RecoveryWrappedMasterKey = newRecoveryWrappedMasterKey
	user.RecoveryMasterKeyNonce = newRecoveryMasterKeyNonce
	user.KEKParams = authsvc.FormatArgon2Params(h.params)
	user.RecoveryKEKParams = authsvc.FormatArgon2Params(h.params)

	// 3. Atomic rotation: re-wrap EVERY document DEK and update the user key
	//    row inside ONE transaction. The old Master Key remains fully valid
	//    until commit, so concurrent downloads observe only the old or the
	//    new consistent state — never a half-rotated mix (ROADMAP P0-2).
	err = h.metaStore.InTx(r.Context(), func(tx *sql.Tx) error {
		docs, err := h.metaStore.ListAllForUserTx(r.Context(), tx, userID)
		if err != nil {
			return err
		}
		for _, doc := range docs {
			if doc.EncryptedDEK == nil {
				continue
			}
			dek, err := crypto.UnwrapDEKAny(doc.EncryptedDEK, doc.DEKNonce, oldMasterKey, crypto.DEKAAD(userID, doc.ID))
			if err != nil {
				return fmt.Errorf("unwrap DEK for doc %s: %w", doc.ID, err)
			}
			// Fresh wraps are always AAD-bound — rotation doubles as the
			// migration path that upgrades legacy unbound rows (ROADMAP P0-4).
			newEncryptedDEK, newDEKNonce, err := crypto.WrapDEKBound(dek, newMasterKey, crypto.DEKAAD(userID, doc.ID))
			if err != nil {
				return fmt.Errorf("wrap DEK for doc %s: %w", doc.ID, err)
			}
			if err := h.metaStore.UpdateDEKTx(r.Context(), tx, doc.ID, userID, newEncryptedDEK, newDEKNonce); err != nil {
				return fmt.Errorf("persist DEK for doc %s: %w", doc.ID, err)
			}
		}
		return h.users.UpdateUserKeysTx(r.Context(), tx, user)
	})
	if err != nil {
		// Rolled back wholesale: old wraps + old user keys remain authoritative.
		audit(r, "rotate_master_key_failed", "user_id", userID, "reason", "tx_aborted")
		slog.Error("master key rotation rolled back", "user_id", userID, "error", err)
		http.Error(w, "rotation failed; no changes were made", http.StatusInternalServerError)
		return
	}

	// 4. Update current session in RAM to use the new master key!
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
	audit(r, "rotate_master_key_success", "user_id", userID)
	json.NewEncoder(w).Encode(map[string]string{
		"recovery_key": newRecoveryKey,
		"message":      "Master Key rotated successfully. Please store your new recovery key.",
	})
}
