package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Kyei-Ernest/DocOps/middleware"
	authsvc "github.com/Kyei-Ernest/DocOps/services/auth"
	"github.com/Kyei-Ernest/DocOps/services/crypto"
	"github.com/go-chi/chi/v5"
)

// APIKeyHandler manages machine credentials for the authenticated user.
//
// Lifecycle contract mirrors the recovery key: the plaintext secret is shown
// EXACTLY ONCE at creation, stored only as a SHA-256 hash, revocable forever
// after. Keys wrap the user's current Master Key, so rotating the Master Key
// invalidates every API key's ability to unwrap new documents — rotation is a
// de-facto global key emergency brake (documented tradeoff; ROADMAP P0-1).
type APIKeyHandler struct {
	keys *authsvc.APIKeyStore
}

// NewAPIKeyHandler constructs an APIKeyHandler.
func NewAPIKeyHandler(keys *authsvc.APIKeyStore) *APIKeyHandler {
	return &APIKeyHandler{keys: keys}
}

type createAPIKeyRequest struct {
	Name string `json:"name"`
}

// Create handles POST /v0.1/auth/api-keys.
// Requires an authenticated human or machine session: the new key wraps the
// Master Key found in request context.
func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	masterKey, ok := middleware.KEKFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	generated, err := crypto.GenerateAPIKey()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hkdfSalt, err := crypto.GenerateSalt()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	wrapKey, err := crypto.DeriveAPIWrapKey(generated.Secret, hkdfSalt)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	wrappedMasterKey, masterKeyNonce, err := crypto.WrapDEKBound(masterKey, wrapKey, crypto.APIKeyAAD(userID, generated.KeyID))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	key := &authsvc.APIKey{
		KeyID:            generated.KeyID,
		UserID:           userID,
		Name:             req.Name,
		SecretHash:       crypto.HashAPISecret(generated.Secret),
		HKDFSalt:         hkdfSalt,
		WrappedMasterKey: wrappedMasterKey,
		MasterKeyNonce:   masterKeyNonce,
		CreatedAt:        time.Now().UTC(),
	}
	if err := h.keys.Create(r.Context(), key); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	audit(r, "api_key_created", "user_id", userID, "key_id", generated.KeyID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"api_key": generated.Plaintext, // shown exactly once — never stored, never logged
		"key_id":  generated.KeyID,
		"name":    key.Name,
	})
}

// List handles GET /v0.1/auth/api-keys.
// Returns metadata only — secret hashes and wraps never leave the server.
func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	keys, err := h.keys.ListByUser(r.Context(), userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		item := map[string]any{
			"key_id":     k.KeyID,
			"name":       k.Name,
			"created_at": k.CreatedAt,
			"revoked":    k.RevokedAt != nil,
		}
		if k.LastUsedAt != nil {
			item["last_used_at"] = k.LastUsedAt
		}
		out = append(out, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// Revoke handles DELETE /v0.1/auth/api-keys/{keyID}.
func (h *APIKeyHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	keyID := chi.URLParam(r, "keyID")
	if keyID == "" {
		http.Error(w, "missing key id", http.StatusBadRequest)
		return
	}

	if err := h.keys.Revoke(r.Context(), userID, keyID); err != nil {
		// Not-found and already-revoked collapse to one generic 404 — no
		// existence oracle for other users' key IDs.
		http.Error(w, "api key not found", http.StatusNotFound)
		return
	}

	audit(r, "api_key_revoked", "user_id", userID, "key_id", keyID)
	w.WriteHeader(http.StatusNoContent)
}
