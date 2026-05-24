package handlers

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyei-Ernest/DocOps/middleware"
	"github.com/Kyei-Ernest/DocOps/services/metadata"
	"github.com/go-chi/chi/v5"
	_ "github.com/mattn/go-sqlite3"
)

// ── Delete test helpers ──────────────────────────────────────────────────────

// deleteTestKEK is a 32-byte key used for all delete tests.
var deleteTestKEK = []byte("32-byte-test-kek-for-deletions!!")

const deleteTestUserID = "user-delete-test-001"

// deleteTestHarness bundles the upload and delete handlers that share the same
// in-memory metadata store and mock connector — an upload via one handler
// is immediately visible to the other.
type deleteTestHarness struct {
	upload *UploadHandler
	delete *DeleteHandler
	mc     *mockConnector
	store  *metadata.Store
}

// newDeleteTestHarness creates a matched pair of upload/delete handlers backed
// by the same in-memory SQLite store and mock connector.
func newDeleteTestHarness(t *testing.T) *deleteTestHarness {
	t.Helper()
	mc := newMockConnector()
	store, err := metadata.New(":memory:")
	if err != nil {
		t.Fatalf("new metadata store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return &deleteTestHarness{
		upload: NewUploadHandler(mc, store),
		delete: NewDeleteHandler(mc, store),
		mc:     mc,
		store:  store,
	}
}

// uploadDocForDelete performs a real upload through the upload handler and
// returns the document ID. This gives us a properly encrypted file in the
// mock connector plus a valid metadata row in the store.
func (h *deleteTestHarness) uploadDoc(t *testing.T, filename string, content []byte, kek []byte, userID string) string {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write file content: %v", err)
	}
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/docs/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req = withAuthContext(req, kek, userID)

	rr := httptest.NewRecorder()
	h.upload.Upload(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("upload: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	return extractJSONField(t, body, "id")
}

// deleteRequest builds a DELETE request for the delete endpoint with chi URL
// params and auth context attached.
func deleteRequest(t *testing.T, docID string, userID string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/v1/docs/"+docID, nil)

	// Attach UserID to context (Delete handler only needs UserID, not KEK)
	ctx := context.WithValue(req.Context(), middleware.UserIDKey, userID)

	// Inject chi URL param
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("docID", docID)
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

	req = req.WithContext(ctx)
	return req, httptest.NewRecorder()
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestDelete_Success(t *testing.T) {
	h := newDeleteTestHarness(t)

	docID := h.uploadDoc(t, "to-delete.pdf", []byte("ephemeral content"), deleteTestKEK, deleteTestUserID)

	// Verify file exists in storage before delete
	if len(h.mc.uploaded) != 1 {
		t.Fatalf("want 1 file in storage before delete, got %d", len(h.mc.uploaded))
	}

	req, rr := deleteRequest(t, docID, deleteTestUserID)
	h.delete.Delete(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify file is gone from storage
	if len(h.mc.uploaded) != 0 {
		t.Errorf("want 0 files in storage after delete, got %d", len(h.mc.uploaded))
	}

	// Verify metadata record is gone
	_, err := h.store.GetByID(context.Background(), docID, deleteTestUserID)
	if err == nil {
		t.Error("document metadata should be deleted but GetByID returned nil error")
	}
}

func TestDelete_ReturnsEmptyBody(t *testing.T) {
	h := newDeleteTestHarness(t)

	docID := h.uploadDoc(t, "doc.pdf", []byte("content"), deleteTestKEK, deleteTestUserID)

	req, rr := deleteRequest(t, docID, deleteTestUserID)
	h.delete.Delete(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", rr.Code)
	}

	// 204 No Content should have an empty body
	if rr.Body.Len() != 0 {
		t.Errorf("want empty body for 204, got %q", rr.Body.String())
	}
}

func TestDelete_MissingDocID(t *testing.T) {
	h := newDeleteTestHarness(t)

	req, rr := deleteRequest(t, "", deleteTestUserID)
	h.delete.Delete(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing doc ID, got %d", rr.Code)
	}
}

func TestDelete_NoUserIDInContext(t *testing.T) {
	h := newDeleteTestHarness(t)

	docID := h.uploadDoc(t, "doc.pdf", []byte("content"), deleteTestKEK, deleteTestUserID)

	// Build request with chi URL params but no UserID in context
	req := httptest.NewRequest(http.MethodDelete, "/v1/docs/"+docID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("docID", docID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	h.delete.Delete(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 when UserID is missing, got %d", rr.Code)
	}
}

func TestDelete_DocumentNotFound(t *testing.T) {
	h := newDeleteTestHarness(t)

	req, rr := deleteRequest(t, "doc_nonexistent-id", deleteTestUserID)
	h.delete.Delete(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404 for non-existent document, got %d", rr.Code)
	}
}

func TestDelete_WrongUserCannotDelete(t *testing.T) {
	h := newDeleteTestHarness(t)

	// Upload as user A
	docID := h.uploadDoc(t, "secret.pdf", []byte("user-A-only"), deleteTestKEK, deleteTestUserID)

	// Attempt delete as user B
	attacker := "user-delete-test-ATTACKER"
	req, rr := deleteRequest(t, docID, attacker)
	h.delete.Delete(rr, req)

	// The metadata store filters by user_id, so this should be 404
	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404 when another user tries to delete, got %d", rr.Code)
	}

	// Verify the file is still in storage — attacker should not have deleted it
	if len(h.mc.uploaded) != 1 {
		t.Error("file should still be in storage after failed delete by wrong user")
	}
}

func TestDelete_StorageDeleteFailure(t *testing.T) {
	h := newDeleteTestHarness(t)

	docID := h.uploadDoc(t, "doc.pdf", []byte("content"), deleteTestKEK, deleteTestUserID)

	// Configure the mock connector to fail on Delete
	h.mc.deleteErr = fmt.Errorf("simulated storage delete failure")

	req, rr := deleteRequest(t, docID, deleteTestUserID)
	h.delete.Delete(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 on storage delete failure, got %d", rr.Code)
	}

	// Metadata should still exist since storage delete failed
	_, err := h.store.GetByID(context.Background(), docID, deleteTestUserID)
	if err != nil {
		t.Error("metadata should still exist when storage delete fails")
	}
}

func TestDelete_Idempotency(t *testing.T) {
	h := newDeleteTestHarness(t)

	docID := h.uploadDoc(t, "doc.pdf", []byte("content"), deleteTestKEK, deleteTestUserID)

	// First delete should succeed
	req1, rr1 := deleteRequest(t, docID, deleteTestUserID)
	h.delete.Delete(rr1, req1)

	if rr1.Code != http.StatusNoContent {
		t.Fatalf("first delete: want 204, got %d", rr1.Code)
	}

	// Second delete of the same doc should return 404
	req2, rr2 := deleteRequest(t, docID, deleteTestUserID)
	h.delete.Delete(rr2, req2)

	if rr2.Code != http.StatusNotFound {
		t.Fatalf("second delete: want 404 (already deleted), got %d", rr2.Code)
	}
}

func TestDelete_MultipleDocsOnlyTargetIsRemoved(t *testing.T) {
	h := newDeleteTestHarness(t)

	// Upload three documents
	doc1 := h.uploadDoc(t, "file1.pdf", []byte("content one"), deleteTestKEK, deleteTestUserID)
	doc2 := h.uploadDoc(t, "file2.pdf", []byte("content two"), deleteTestKEK, deleteTestUserID)
	doc3 := h.uploadDoc(t, "file3.pdf", []byte("content three"), deleteTestKEK, deleteTestUserID)

	if len(h.mc.uploaded) != 3 {
		t.Fatalf("want 3 files in storage, got %d", len(h.mc.uploaded))
	}

	// Delete only doc2
	req, rr := deleteRequest(t, doc2, deleteTestUserID)
	h.delete.Delete(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", rr.Code)
	}

	// Verify only 2 files remain in storage
	if len(h.mc.uploaded) != 2 {
		t.Errorf("want 2 files in storage after deleting one, got %d", len(h.mc.uploaded))
	}

	// Verify doc1 and doc3 are still accessible
	_, err1 := h.store.GetByID(context.Background(), doc1, deleteTestUserID)
	if err1 != nil {
		t.Errorf("doc1 should still exist: %v", err1)
	}
	_, err3 := h.store.GetByID(context.Background(), doc3, deleteTestUserID)
	if err3 != nil {
		t.Errorf("doc3 should still exist: %v", err3)
	}

	// Verify doc2 is gone
	_, err2 := h.store.GetByID(context.Background(), doc2, deleteTestUserID)
	if err2 == nil {
		t.Error("doc2 should be deleted but GetByID returned nil error")
	}
}
