package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyei-Ernest/DocOps/middleware"
	"github.com/Kyei-Ernest/DocOps/models"
	"github.com/Kyei-Ernest/DocOps/services/metadata"
	_ "github.com/mattn/go-sqlite3"
)

// ── Mock connector ───────────────────────────────────────────────────────────

// mockConnector implements connectors.StorageConnector for testing.
// Each method records that it was called and can be configured to return errors.
type mockConnector struct {
	uploaded   map[string][]byte // key → content stored
	uploadErr  error             // if set, Upload returns this error
	deleteErr  error             // if set, Delete returns this error
	deletedKey string            // last key passed to Delete
}

func newMockConnector() *mockConnector {
	return &mockConnector{uploaded: make(map[string][]byte)}
}

func (m *mockConnector) Upload(_ context.Context, r models.UploadRequest) (models.FileRef, error) {
	if m.uploadErr != nil {
		return models.FileRef{}, m.uploadErr
	}
	data, _ := io.ReadAll(r.Content)
	m.uploaded[r.Key] = data
	return models.FileRef{Key: r.Key, SizeBytes: int64(len(data)), ContentType: r.ContentType}, nil
}

func (m *mockConnector) Download(_ context.Context, key string) (io.ReadCloser, error) {
	data, ok := m.uploaded[key]
	if !ok {
		return nil, fmt.Errorf("file not found: %s", key)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *mockConnector) Delete(_ context.Context, key string) error {
	m.deletedKey = key
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.uploaded, key)
	return nil
}

func (m *mockConnector) Ping(_ context.Context) error { return nil }

// ── Test helpers ─────────────────────────────────────────────────────────────

// testKEK is a 32-byte key used for all upload tests.
var testKEK = []byte("32-byte-test-kek-for-unit-tests!")

const testUserID = "user-upload-test-001"

// newTestUploadHandler creates an UploadHandler backed by an in-memory SQLite
// metadata store and the given mock connector.
func newTestUploadHandler(t *testing.T, mc *mockConnector) *UploadHandler {
	t.Helper()
	store, err := metadata.New(":memory:")
	if err != nil {
		t.Fatalf("new metadata store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return NewUploadHandler(mc, store)
}

// withAuthContext attaches KEK and UserID to the request context,
// simulating what the auth middleware does in production.
func withAuthContext(r *http.Request, kek []byte, userID string) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.KEKKey, kek)
	ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
	return r.WithContext(ctx)
}

// newMultipartUpload builds a multipart/form-data request with a file field
// and optional tags. Returns the request ready to be served.
func newMultipartUpload(t *testing.T, filename string, content []byte, tags string) *http.Request {
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

	if tags != "" {
		if err := writer.WriteField("tags", tags); err != nil {
			t.Fatalf("write tags field: %v", err)
		}
	}
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/docs/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestUpload_Success(t *testing.T) {
	mc := newMockConnector()
	h := newTestUploadHandler(t, mc)

	content := []byte("hello docops - this is my document")
	req := newMultipartUpload(t, "report.pdf", content, "legal,2026")
	req = withAuthContext(req, testKEK, testUserID)

	rr := httptest.NewRecorder()
	h.Upload(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// Parse response JSON
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Verify expected fields are present
	for _, field := range []string{"id", "name", "file_type", "size_bytes", "encrypted", "tags", "created_at"} {
		if _, ok := resp[field]; !ok {
			t.Errorf("response missing field %q", field)
		}
	}

	if resp["name"] != "report.pdf" {
		t.Errorf("want name %q, got %q", "report.pdf", resp["name"])
	}
	if resp["tags"] != "legal,2026" {
		t.Errorf("want tags %q, got %q", "legal,2026", resp["tags"])
	}
	if resp["encrypted"] != true {
		t.Errorf("want encrypted=true, got %v", resp["encrypted"])
	}
	// size_bytes should match the original plaintext size, not the encrypted size
	if int64(resp["size_bytes"].(float64)) != int64(len(content)) {
		t.Errorf("want size_bytes=%d, got %v", len(content), resp["size_bytes"])
	}
}

func TestUpload_FileIsEncryptedInStorage(t *testing.T) {
	mc := newMockConnector()
	h := newTestUploadHandler(t, mc)

	plaintext := []byte("sensitive document content — must not appear in storage")
	req := newMultipartUpload(t, "secret.txt", plaintext, "")
	req = withAuthContext(req, testKEK, testUserID)

	rr := httptest.NewRecorder()
	h.Upload(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// The connector should have received exactly one file
	if len(mc.uploaded) != 1 {
		t.Fatalf("want 1 file in storage, got %d", len(mc.uploaded))
	}

	// The stored bytes must NOT match the plaintext — they should be encrypted
	for key, storedBytes := range mc.uploaded {
		if bytes.Equal(storedBytes, plaintext) {
			t.Errorf("file %q was stored as plaintext — encryption not applied", key)
		}
		// Encrypted output should be larger than plaintext (nonce + auth tag overhead)
		if len(storedBytes) <= len(plaintext) {
			t.Errorf("stored bytes (%d) not larger than plaintext (%d) — expected GCM overhead",
				len(storedBytes), len(plaintext))
		}
	}
}

func TestUpload_NoKEKInContext(t *testing.T) {
	mc := newMockConnector()
	h := newTestUploadHandler(t, mc)

	content := []byte("some file")
	req := newMultipartUpload(t, "doc.pdf", content, "")
	// Attach UserID but NOT KEK — simulates a broken middleware chain
	ctx := context.WithValue(req.Context(), middleware.UserIDKey, testUserID)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.Upload(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 when KEK is missing, got %d", rr.Code)
	}
	if len(mc.uploaded) != 0 {
		t.Error("no file should be uploaded when KEK is missing")
	}
}

func TestUpload_NoUserIDInContext(t *testing.T) {
	mc := newMockConnector()
	h := newTestUploadHandler(t, mc)

	content := []byte("some file")
	req := newMultipartUpload(t, "doc.pdf", content, "")
	// Attach KEK but NOT UserID
	ctx := context.WithValue(req.Context(), middleware.KEKKey, testKEK)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.Upload(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 when UserID is missing, got %d", rr.Code)
	}
}

func TestUpload_NoAuthContext(t *testing.T) {
	mc := newMockConnector()
	h := newTestUploadHandler(t, mc)

	content := []byte("some file")
	req := newMultipartUpload(t, "doc.pdf", content, "")
	// No context values at all

	rr := httptest.NewRecorder()
	h.Upload(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 with no auth context, got %d", rr.Code)
	}
}

func TestUpload_MissingFileField(t *testing.T) {
	mc := newMockConnector()
	h := newTestUploadHandler(t, mc)

	// Build a multipart form with tags but no file
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("tags", "orphan-tags")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/docs/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req = withAuthContext(req, testKEK, testUserID)

	rr := httptest.NewRecorder()
	h.Upload(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing file field, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestUpload_InvalidContentType(t *testing.T) {
	mc := newMockConnector()
	h := newTestUploadHandler(t, mc)

	// Send a plain JSON body instead of multipart — should fail at ParseMultipartForm
	req := httptest.NewRequest(http.MethodPost, "/v1/docs/upload",
		bytes.NewBufferString(`{"file":"not-multipart"}`))
	req.Header.Set("Content-Type", "application/json")
	req = withAuthContext(req, testKEK, testUserID)

	rr := httptest.NewRecorder()
	h.Upload(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for non-multipart body, got %d", rr.Code)
	}
}

func TestUpload_ConnectorUploadFailure(t *testing.T) {
	mc := newMockConnector()
	mc.uploadErr = fmt.Errorf("simulated storage failure")
	h := newTestUploadHandler(t, mc)

	req := newMultipartUpload(t, "doc.pdf", []byte("content"), "")
	req = withAuthContext(req, testKEK, testUserID)

	rr := httptest.NewRecorder()
	h.Upload(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 on storage failure, got %d", rr.Code)
	}
}

func TestUpload_WithoutTags(t *testing.T) {
	mc := newMockConnector()
	h := newTestUploadHandler(t, mc)

	req := newMultipartUpload(t, "no-tags.pdf", []byte("content without tags"), "")
	req = withAuthContext(req, testKEK, testUserID)

	rr := httptest.NewRecorder()
	h.Upload(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp["tags"] != "" {
		t.Errorf("want empty tags, got %q", resp["tags"])
	}
}

func TestUpload_ResponseExcludesSensitiveFields(t *testing.T) {
	mc := newMockConnector()
	h := newTestUploadHandler(t, mc)

	req := newMultipartUpload(t, "secret.pdf", []byte("classified"), "top-secret")
	req = withAuthContext(req, testKEK, testUserID)

	rr := httptest.NewRecorder()
	h.Upload(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d", rr.Code)
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)

	// These fields must never appear in the API response
	forbidden := []string{"storage_key", "encrypted_dek", "dek_nonce", "file_nonce", "user_id"}
	for _, field := range forbidden {
		if _, ok := resp[field]; ok {
			t.Errorf("response must not contain sensitive field %q", field)
		}
	}
}

func TestUpload_EachFileGetsDifferentStorageKey(t *testing.T) {
	mc := newMockConnector()
	h := newTestUploadHandler(t, mc)

	// Upload two files
	for i, name := range []string{"file1.pdf", "file2.pdf"} {
		req := newMultipartUpload(t, name, []byte(fmt.Sprintf("content-%d", i)), "")
		req = withAuthContext(req, testKEK, testUserID)
		rr := httptest.NewRecorder()
		h.Upload(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("upload %d: want 201, got %d", i, rr.Code)
		}
	}

	// The connector should have two distinct keys
	if len(mc.uploaded) != 2 {
		t.Fatalf("want 2 distinct storage keys, got %d", len(mc.uploaded))
	}
}

func TestUpload_EachFileGetsDifferentEncryption(t *testing.T) {
	mc := newMockConnector()
	h := newTestUploadHandler(t, mc)

	// Upload the same content twice — encrypted output must differ (unique DEK + nonce)
	content := []byte("identical content for both uploads")
	var ciphertexts [][]byte

	for i := 0; i < 2; i++ {
		req := newMultipartUpload(t, fmt.Sprintf("file%d.pdf", i), content, "")
		req = withAuthContext(req, testKEK, testUserID)
		rr := httptest.NewRecorder()
		h.Upload(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("upload %d: want 201, got %d", i, rr.Code)
		}
	}

	for _, data := range mc.uploaded {
		ciphertexts = append(ciphertexts, data)
	}

	if len(ciphertexts) != 2 {
		t.Fatalf("expected 2 ciphertexts, got %d", len(ciphertexts))
	}

	if bytes.Equal(ciphertexts[0], ciphertexts[1]) {
		t.Error("two uploads of identical content produced identical ciphertext — DEK or nonce reuse detected")
	}
}
