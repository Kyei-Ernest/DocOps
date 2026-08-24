package handlers

import (
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Kyei-Ernest/DocOps/connectors"
	"github.com/Kyei-Ernest/DocOps/middleware"
	"github.com/Kyei-Ernest/DocOps/services/crypto"
	"github.com/Kyei-Ernest/DocOps/services/metadata"
	"github.com/go-chi/chi/v5"
)

type DownloadHandler struct {
	connector connectors.StorageConnector
	store     *metadata.Store
}

// NewDownloadHandler constructs a DownloadHandler with its dependencies.
func NewDownloadHandler(c connectors.StorageConnector, s *metadata.Store) *DownloadHandler {
	return &DownloadHandler{
		connector: c,
		store:     s,
	}
}

// Download handles GET /v1/docs/{docID}/download
//
// Flow:
//  1. Extract doc ID from URL
//  2. Pull KEK and UserID from context (set by auth middleware)
//  3. Load document metadata from the store
//  4. Verify ownership — return 404 if mismatch
//  5. Stream the encrypted file from storage
//  6. Unwrap the per-document DEK using the user's KEK
//  7. Create a streaming decryptor and pipe plaintext to the client
func (d *DownloadHandler) Download(w http.ResponseWriter, r *http.Request) {
	// 1. Get doc ID from URL params
	docID := chi.URLParam(r, "docID")
	if docID == "" {
		http.Error(w, "missing doc id", http.StatusBadRequest)
		return
	}

	// 2. Get KEK from context
	kek, ok := middleware.KEKFromContext(r.Context())
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 3. Get UserID from context
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// 4. Load document metadata and verify ownership
	doc, err := d.store.GetByID(r.Context(), docID, userID)
	if err != nil {
		http.Error(w, "document not found", http.StatusNotFound)
		return
	}

	// 4b. TTL enforcement: an expired document is indistinguishable from a
	//     nonexistent one — consistent with the 404-uniformity that hides
	//     document existence from non-owners.
	if doc.ExpiresAt != nil && time.Now().After(*doc.ExpiresAt) {
		http.Error(w, "document not found", http.StatusNotFound)
		return
	}

	// 6. Stream encrypted file from storage
	dataStream, err := d.connector.Download(r.Context(), doc.StorageKey)
	if err != nil {
		http.Error(w, "failed to download file", http.StatusInternalServerError)
		return
	}
	defer dataStream.Close()

	// 7. Unwrap the per-document DEK. Bound wraps require the exact
	//    (userID, docID) context they were sealed under; legacy unbound rows
	//    still open via the fallback inside UnwrapDEKAny.
	dek, err := crypto.UnwrapDEKAny(doc.EncryptedDEK, doc.DEKNonce, kek, crypto.DEKAAD(userID, docID))
	if err != nil {
		http.Error(w, "failed to unwrap key", http.StatusInternalServerError)
		return
	}

	// 8. Create a streaming decryptor — DecryptStream reads one 64 KB
	//    GCM chunk at a time, verifies its auth tag, and yields plaintext.
	//    No buffering of the full file in memory.
	decryptedReader, err := crypto.DecryptStream(dataStream, doc.FileNonce, dek)
	if err != nil {
		http.Error(w, "failed to decrypt", http.StatusInternalServerError)
		return
	}

	// Set response headers before streaming
	w.Header().Set("Content-Type", doc.FileType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+doc.Name+"\"")

	// Stream directly to client — constant memory usage
	if _, err := io.Copy(w, decryptedReader); err != nil {
		// headers already sent so we can't change status code
		// but log it for visibility
		slog.Error("stream copy failed", "doc_id", docID, "error", err)
	}
}
