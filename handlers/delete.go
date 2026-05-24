package handlers

import (
	"log"
	"net/http"

	"github.com/Kyei-Ernest/DocOps/connectors"
	"github.com/Kyei-Ernest/DocOps/middleware"
	"github.com/Kyei-Ernest/DocOps/services/metadata"
	"github.com/go-chi/chi/v5"
)

// DeleteHandler holds the dependencies the delete handler needs.
// These are injected at startup — the handler itself never creates or
// manages these, it just uses them.
type DeleteHandler struct {
	connector connectors.StorageConnector // deletes file from storage
	store     *metadata.Store             // deletes document record
}

// NewDeleteHandler constructs a DeleteHandler with its dependencies.
func NewDeleteHandler(c connectors.StorageConnector, s *metadata.Store) *DeleteHandler {
	return &DeleteHandler{
		connector: c,
		store:     s,
	}
}

// Delete handles DELETE /v1/docs/{docID}
//
// Flow:
//  1. Extract doc ID from URL
//  2. Pull UserID from context (set by auth middleware)
//  3. Load document metadata and verify ownership
//  4. Delete the encrypted file from storage
//  5. Delete the metadata record from the database
//  6. Return 204 No Content
//
// Ordering rationale: we look up the document first to get the storage key
// and to confirm ownership. We delete from storage before metadata so that
// if the metadata delete fails we have an orphaned DB row (recoverable)
// rather than an orphaned file (harder to find and clean up).
func (d *DeleteHandler) Delete(w http.ResponseWriter, r *http.Request) {
	// ── Step 1: Get doc ID from URL params ───────────────────────
	docID := chi.URLParam(r, "docID")
	if docID == "" {
		http.Error(w, "missing doc id", http.StatusBadRequest)
		return
	}

	// ── Step 2: Get UserID from context ──────────────────────────
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// ── Step 3: Load document metadata and verify ownership ──────
	// GetByID filters by user_id so a user can never delete another
	// user's document — it simply looks like "not found".
	doc, err := d.store.GetByID(r.Context(), docID, userID)
	if err != nil {
		http.Error(w, "document not found", http.StatusNotFound)
		return
	}

	// ── Step 4: Delete the encrypted file from storage ───────────
	if err := d.connector.Delete(r.Context(), doc.StorageKey); err != nil {
		log.Printf("failed to delete storage object %s for doc %s: %v",
			doc.StorageKey, docID, err)
		http.Error(w, "failed to delete file from storage", http.StatusInternalServerError)
		return
	}

	// ── Step 5: Delete the metadata record ───────────────────────
	// The AFTER DELETE trigger (documents_ad) automatically purges
	// the corresponding FTS index entry.
	if err := d.store.Delete(r.Context(), docID, userID); err != nil {
		// Storage file is already gone — log the inconsistency.
		log.Printf("storage deleted but metadata delete failed for doc %s: %v", docID, err)
		http.Error(w, "failed to delete document record", http.StatusInternalServerError)
		return
	}

	// ── Step 6: Return 204 No Content ────────────────────────────
	w.WriteHeader(http.StatusNoContent)
}
