package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Kyei-Ernest/DocOps/connectors"
	"github.com/Kyei-Ernest/DocOps/middleware"
	"github.com/Kyei-Ernest/DocOps/services/metadata"
)

// SearchHandler holds the dependencies the search handler needs.
// The connector is included for consistency with other handlers, though
// search only queries the metadata store — it never touches file storage.
type SearchHandler struct {
	connector connectors.StorageConnector
	store     *metadata.Store
}

// NewSearchHandler constructs a SearchHandler with its dependencies.
func NewSearchHandler(c connectors.StorageConnector, s *metadata.Store) *SearchHandler {
	return &SearchHandler{
		connector: c,
		store:     s,
	}
}

// Search handles GET /v1/docs/search?q=<query>
//
// Expected request: query parameter "q" containing an FTS5 match expression
// (e.g. "invoice", "legal AND 2026").
//
// What this handler does in order:
//  1. Extract and validate the "q" query parameter
//  2. Pull UserID from context (set by auth middleware)
//  3. Run full-text search against the metadata store, scoped to the user
//  4. Return matching documents as a JSON array
//
// The response intentionally omits sensitive columns (extracted_text,
// encryption blobs, storage_key) — the store.Search method handles that.
func (s *SearchHandler) Search(w http.ResponseWriter, r *http.Request) {
	// ── Step 1: Extract and validate the search query ─────────────
	// The "q" parameter is required. Blank queries are rejected upfront
	// rather than passed to FTS5, which would return a syntax error.
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		http.Error(w, "missing or empty query parameter 'q'", http.StatusBadRequest)
		return
	}

	// ── Step 2: Pull UserID from context ─────────────────────────
	// The auth middleware already validated the JWT and attached the
	// user ID. If it's missing, the request should not have reached
	// here — guard defensively anyway.
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// ── Step 3: Full-text search scoped to this user ─────────────
	// The store joins the FTS5 index with the documents table and
	// filters by user_id, so results never leak across tenants.
	results, err := s.store.Search(r.Context(), userID, query)
	if err != nil {
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}

	// ── Step 4: Return results ───────────────────────────────────
	// Build a curated response that only includes safe fields.
	// The Document model has json tags on StorageKey/Provider that we
	// don't want to expose, so we map to explicit response objects
	// (same pattern the upload handler uses).
	response := make([]map[string]any, 0, len(results))
	for _, doc := range results {
		response = append(response, map[string]any{
			"id":         doc.ID,
			"name":       doc.Name,
			"file_type":  doc.FileType,
			"encrypted":  doc.Encrypted,
			"size_bytes": doc.SizeBytes,
			"tags":       doc.Tags,
			"created_at": doc.CreatedAt,
			"expires_at": doc.ExpiresAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}