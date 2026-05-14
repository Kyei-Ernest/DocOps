package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Kyei-Ernest/DocOps/connectors"
	"github.com/Kyei-Ernest/DocOps/middleware"
	"github.com/Kyei-Ernest/DocOps/models"
	"github.com/Kyei-Ernest/DocOps/services/crypto"
	"github.com/Kyei-Ernest/DocOps/services/metadata"

	"github.com/google/uuid"
)

// UploadHandler holds the dependencies the upload handler needs.
// These are injected at startup in main.go — the handler itself
// never creates or manages these, it just uses them.
type UploadHandler struct {
	connector connectors.StorageConnector // writes file to storage
	store     *metadata.Store            // saves document record
}

// NewUploadHandler constructs an UploadHandler with its dependencies.
func NewUploadHandler(c connectors.StorageConnector, s *metadata.Store) *UploadHandler {
	return &UploadHandler{
		connector: c,
		store:     s,
	}
}

// Upload handles POST /v1/docs/upload
//
// Expected request: multipart/form-data with:
//   - "file"  → the document being uploaded
//   - "tags"  → optional comma-separated tags e.g. "legal,2026"
//
// What this handler does in order:
//  1. Pull KEK and UserID from context (middleware already attached both)
//  2. Parse the multipart form to get the file stream and its metadata
//  3. Generate a fresh DEK for this specific file
//  4. Generate a UUID — this becomes the filename on disk
//  5. Stream-encrypt the file with the DEK (64 KB chunks, constant memory)
//  6. Encrypt the DEK with the KEK (envelope encryption)
//  7. Write the encrypted stream to storage via the connector
//  8. Save the document metadata record to SQLite
//  9. Return the document reference to the client
func (h *UploadHandler) Upload(w http.ResponseWriter, r *http.Request) {
	// ── Step 1: Pull KEK and UserID from context ─────────────────
	// The auth middleware already validated the JWT and attached
	// both values to the request context before this handler ran.
	// If either is missing the request should not have reached here
	// but we guard defensively anyway.
	kek, ok := middleware.KEKFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// ── Step 2: Parse the multipart form ─────────────────────────
	// 10 << 20 = 10MB max memory for the form.
	// Files larger than this are spilled to temp files on disk
	// automatically by Go — we never buffer the whole thing.
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// FormFile returns:
	//   file   → io.ReadCloser stream of the file content
	//   header → name, size, content-type of the uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file field in form", http.StatusBadRequest)
		return
	}
	defer file.Close() // always close the multipart file when done

	// pull optional tags from the form
	// e.g. "legal,2026" — empty string is fine, tags are optional
	tags := r.FormValue("tags")

	// ── Step 3: Generate a fresh DEK for this file ───────────────
	// Every file gets its own unique DEK.
	// If one DEK is ever compromised, only that one file is affected.
	dek, err := crypto.GenerateDEK()
	if err != nil {
		http.Error(w, "failed to generate encryption key", http.StatusInternalServerError)
		return
	}

	// ── Step 4: Generate UUID storage key ────────────────────────
	// This UUID becomes the filename on disk.
	// Using UUID means no two files ever collide regardless of their
	// original names, and the filename reveals nothing about content.
	storageKey := uuid.NewString()

	// ── Step 5: Stream-encrypt the file with the DEK ─────────────
	// We use an io.Pipe so EncryptStream can write chunked ciphertext
	// into the pipe writer while the connector reads from the pipe
	// reader concurrently. Memory usage stays at one 64 KB chunk.
	pr, pw := io.Pipe()

	var fileNonce []byte
	var encryptErr error

	// Run encryption in a goroutine — it writes to pw while the
	// connector reads from pr below.
	go func() {
		defer pw.Close()
		fileNonce, encryptErr = crypto.EncryptStream(file, pw, dek)
		if encryptErr != nil {
			pw.CloseWithError(fmt.Errorf("encrypt stream: %w", encryptErr))
		}
	}()

	// ── Step 6: Encrypt the DEK with the KEK ─────────────────────
	// This is envelope encryption — the DEK is wrapped by the KEK.
	// We store the encrypted DEK in the DB, never the plaintext DEK.
	// The plaintext DEK exists only in memory during this request.
	encryptedDEK, dekNonce, err := crypto.WrapDEK(dek, kek)
	if err != nil {
		http.Error(w, "failed to encrypt document key", http.StatusInternalServerError)
		return
	}

	// ── Step 7: Write encrypted stream to storage ────────────────
	// The connector reads from the pipe — encrypted bytes stream
	// directly to disk without ever existing fully in memory.
	uploadReq := models.UploadRequest{
		Key:         storageKey,
		Content:     pr, // pipe reader: encrypted stream
		ContentType: header.Header.Get("Content-Type"),
		SizeBytes:   -1, // unknown upfront with streaming
	}

	uploadRef, err := h.connector.Upload(r.Context(), uploadReq)
	if err != nil {
		http.Error(w, "failed to store file", http.StatusInternalServerError)
		return
	}

	// Check if encryption goroutine encountered an error
	if encryptErr != nil {
		h.connector.Delete(r.Context(), storageKey)
		http.Error(w, "failed to encrypt file", http.StatusInternalServerError)
		return
	}

	// ── Step 8: Save metadata record ─────────────────────────────
	// This is the only thing that permanently lives on DocOps servers.
	// The file itself lives at the storage provider (local for now).
	doc := &models.Document{
		ID:           "doc_" + uuid.NewString(), // unique document ID
		Name:         header.Filename,
		FileType:     header.Header.Get("Content-Type"),
		Provider:     "local",
		StorageKey:   storageKey,
		Encrypted:    true,
		SizeBytes:    uploadRef.SizeBytes, // encrypted size from connector
		Tags:         tags,
		ExtractedText: "",        // text extraction comes in a later stage
		EncryptedDEK: encryptedDEK,
		DEKNonce:     dekNonce,
		FileNonce:    fileNonce,
		UserID:       userID,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    nil,
	}

	if err := h.store.Save(r.Context(), doc); err != nil {
		// file was written to storage but metadata save failed
		// clean up the orphaned file so storage stays consistent
		h.connector.Delete(r.Context(), storageKey)
		http.Error(w, "failed to save document record", http.StatusInternalServerError)
		return
	}

	// ── Step 9: Return document reference ────────────────────────
	// We return only the safe metadata fields.
	// Never the DEK, never any nonce, never the storage key.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated) // 201 — resource was created

	json.NewEncoder(w).Encode(map[string]any{
		"id":         doc.ID,
		"name":       doc.Name,
		"file_type":  doc.FileType,
		"size_bytes": doc.SizeBytes,
		"encrypted":  doc.Encrypted,
		"tags":       doc.Tags,
		"created_at": doc.CreatedAt,
	})
}