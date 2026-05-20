package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Kyei-Ernest/DocOps/middleware"
	"github.com/Kyei-Ernest/DocOps/models"
	"github.com/Kyei-Ernest/DocOps/services/metadata"
	_ "github.com/mattn/go-sqlite3"
)

// ── Search test helpers ─────────────────────────────────────────────────────

const searchTestUserID = "user-search-test-001"

// searchTestHarness bundles a SearchHandler with its backing store and mock
// connector, plus a convenience method to seed documents directly into the
// metadata store (no encryption needed since search only queries metadata).
type searchTestHarness struct {
	handler *SearchHandler
	store   *metadata.Store
	mc      *mockConnector
}

// newSearchTestHarness creates a SearchHandler backed by an in-memory SQLite
// metadata store and the shared mock connector.
func newSearchTestHarness(t *testing.T) *searchTestHarness {
	t.Helper()
	mc := newMockConnector()
	store, err := metadata.New(":memory:")
	if err != nil {
		t.Fatalf("new metadata store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return &searchTestHarness{
		handler: NewSearchHandler(mc, store),
		store:   store,
		mc:      mc,
	}
}

// seedDoc inserts a document directly into the metadata store with the given
// fields. This bypasses the upload flow because search only needs metadata
// rows — no encrypted files on disk.
func (h *searchTestHarness) seedDoc(t *testing.T, id, name, tags, extractedText, userID string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	doc := &models.Document{
		ID:            id,
		UserID:        userID,
		Name:          name,
		FileType:      "application/pdf",
		Provider:      "local",
		StorageKey:    "local/" + id,
		Encrypted:     true,
		SizeBytes:     1024,
		Tags:          tags,
		ExtractedText: extractedText,
		EncryptedDEK:  []byte("fake-dek"),
		DEKNonce:      []byte("fake-nonce------"),
		FileNonce:     []byte("fake-file-nonce-"),
		CreatedAt:     now,
		ExpiresAt:     nil,
	}
	if err := h.store.Save(context.Background(), doc); err != nil {
		t.Fatalf("seed document %q: %v", id, err)
	}
}

// searchRequest builds a GET request for the search endpoint with the given
// query parameter and auth context attached.
func searchRequest(t *testing.T, query string, userID string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	target := "/v1/docs/search"
	if query != "" {
		target += "?q=" + query
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)

	// Attach UserID to context — search doesn't need KEK since it only
	// queries metadata, not file content.
	ctx := context.WithValue(req.Context(), middleware.UserIDKey, userID)
	req = req.WithContext(ctx)

	return req, httptest.NewRecorder()
}

// parseSearchResponse decodes the JSON array from the response body into
// a slice of maps for easy field-level assertions.
func parseSearchResponse(t *testing.T, rr *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	var results []map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&results); err != nil {
		t.Fatalf("decode search response: %v", err)
	}
	return results
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestSearch_Success_ByName(t *testing.T) {
	h := newSearchTestHarness(t)
	h.seedDoc(t, "doc_s001", "quarterly-report.pdf", "finance,2026", "revenue grew by 15%", searchTestUserID)

	req, rr := searchRequest(t, "quarterly", searchTestUserID)
	h.handler.Search(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	results := parseSearchResponse(t, rr)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0]["id"] != "doc_s001" {
		t.Errorf("unexpected result ID: %v", results[0]["id"])
	}
}

func TestSearch_Success_ByTag(t *testing.T) {
	h := newSearchTestHarness(t)
	h.seedDoc(t, "doc_s002", "contract.pdf", "legal,2026", "service agreement", searchTestUserID)

	req, rr := searchRequest(t, "legal", searchTestUserID)
	h.handler.Search(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	results := parseSearchResponse(t, rr)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestSearch_Success_ByExtractedText(t *testing.T) {
	h := newSearchTestHarness(t)
	h.seedDoc(t, "doc_s003", "invoice.pdf", "billing", "payment due within 30 days", searchTestUserID)

	req, rr := searchRequest(t, "payment", searchTestUserID)
	h.handler.Search(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	results := parseSearchResponse(t, rr)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0]["id"] != "doc_s003" {
		t.Errorf("unexpected result ID: %v", results[0]["id"])
	}
}

func TestSearch_MultipleResults(t *testing.T) {
	h := newSearchTestHarness(t)
	h.seedDoc(t, "doc_s010", "report-q1.pdf", "finance", "quarterly earnings report Q1", searchTestUserID)
	h.seedDoc(t, "doc_s011", "report-q2.pdf", "finance", "quarterly earnings report Q2", searchTestUserID)
	h.seedDoc(t, "doc_s012", "contract.pdf", "legal", "service agreement terms", searchTestUserID)

	req, rr := searchRequest(t, "quarterly", searchTestUserID)
	h.handler.Search(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	results := parseSearchResponse(t, rr)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestSearch_NoResults(t *testing.T) {
	h := newSearchTestHarness(t)
	h.seedDoc(t, "doc_s020", "report.pdf", "finance", "revenue numbers", searchTestUserID)

	req, rr := searchRequest(t, "xyznotfound", searchTestUserID)
	h.handler.Search(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 even with no results, got %d", rr.Code)
	}

	results := parseSearchResponse(t, rr)
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestSearch_EmptyQuery(t *testing.T) {
	h := newSearchTestHarness(t)

	req, rr := searchRequest(t, "", searchTestUserID)
	h.handler.Search(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for empty query, got %d", rr.Code)
	}
}

func TestSearch_WhitespaceOnlyQuery(t *testing.T) {
	h := newSearchTestHarness(t)

	// Build request manually with whitespace-only query
	req := httptest.NewRequest(http.MethodGet, "/v1/docs/search?q=+++", nil)
	ctx := context.WithValue(req.Context(), middleware.UserIDKey, searchTestUserID)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.handler.Search(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for whitespace-only query, got %d", rr.Code)
	}
}

func TestSearch_NoUserIDInContext(t *testing.T) {
	h := newSearchTestHarness(t)

	// Build request without any auth context
	req := httptest.NewRequest(http.MethodGet, "/v1/docs/search?q=test", nil)
	rr := httptest.NewRecorder()
	h.handler.Search(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 when UserID is missing, got %d", rr.Code)
	}
}

func TestSearch_CrossUserIsolation(t *testing.T) {
	h := newSearchTestHarness(t)

	// Seed a document owned by user A
	h.seedDoc(t, "doc_s030", "secret.pdf", "classified", "top secret information", searchTestUserID)

	// Search as user B — should find nothing
	attackerID := "user-search-test-ATTACKER"
	req, rr := searchRequest(t, "secret", attackerID)
	h.handler.Search(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}

	results := parseSearchResponse(t, rr)
	if len(results) != 0 {
		t.Fatalf("expected 0 results for wrong user, got %d — tenant isolation broken", len(results))
	}
}

func TestSearch_OnlyMatchingDocReturned(t *testing.T) {
	h := newSearchTestHarness(t)
	h.seedDoc(t, "doc_s040", "report.pdf", "finance", "quarterly earnings", searchTestUserID)
	h.seedDoc(t, "doc_s041", "contract.pdf", "legal", "service agreement", searchTestUserID)

	req, rr := searchRequest(t, "earnings", searchTestUserID)
	h.handler.Search(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}

	results := parseSearchResponse(t, rr)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0]["id"] != "doc_s040" {
		t.Errorf("wrong document returned: want doc_s040, got %v", results[0]["id"])
	}
}

func TestSearch_ResponseSetsContentType(t *testing.T) {
	h := newSearchTestHarness(t)
	h.seedDoc(t, "doc_s050", "doc.pdf", "misc", "some text", searchTestUserID)

	req, rr := searchRequest(t, "text", searchTestUserID)
	h.handler.Search(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("want Content-Type application/json, got %q", ct)
	}
}

func TestSearch_ResponseExcludesSensitiveFields(t *testing.T) {
	h := newSearchTestHarness(t)
	h.seedDoc(t, "doc_s060", "secret.pdf", "classified", "sensitive extracted text", searchTestUserID)

	req, rr := searchRequest(t, "sensitive", searchTestUserID)
	h.handler.Search(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}

	results := parseSearchResponse(t, rr)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// The store.Search method omits sensitive columns. Verify the JSON
	// response doesn't expose them either (they are tagged json:"-" on
	// the model, so they should be excluded by json.Encoder).
	forbidden := []string{"extracted_text", "encrypted_dek", "dek_nonce", "file_nonce", "storage_key"}
	for _, field := range forbidden {
		if _, ok := results[0][field]; ok {
			t.Errorf("response must not contain sensitive field %q", field)
		}
	}
}

func TestSearch_EmptyStoreReturnsEmptyArray(t *testing.T) {
	h := newSearchTestHarness(t)

	// No documents seeded — search should return [] not null
	req, rr := searchRequest(t, "anything", searchTestUserID)
	h.handler.Search(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}

	// Verify the body is a valid empty JSON array
	results := parseSearchResponse(t, rr)
	if results == nil {
		t.Fatal("response decoded as nil — want empty array")
	}
	if len(results) != 0 {
		t.Fatalf("expected empty array, got %d results", len(results))
	}
}

func TestSearch_MissingQParam(t *testing.T) {
	h := newSearchTestHarness(t)

	// Request with no query parameter at all
	req := httptest.NewRequest(http.MethodGet, "/v1/docs/search", nil)
	ctx := context.WithValue(req.Context(), middleware.UserIDKey, searchTestUserID)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.handler.Search(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing q param, got %d", rr.Code)
	}
}
