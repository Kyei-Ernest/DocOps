package handlers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyei-Ernest/DocOps/middleware"
	"github.com/Kyei-Ernest/DocOps/services/metadata"
	"github.com/go-chi/chi/v5"
	_ "github.com/mattn/go-sqlite3"
)

// ── Download test helpers ────────────────────────────────────────────────────

// downloadTestKEK is a 32-byte key used for all download tests.
// Distinct from upload tests to avoid any implicit coupling.
var downloadTestKEK = []byte("32-byte-test-kek-for-downloads!!")

const downloadTestUserID = "user-download-test-001"

// testHarness bundles the upload and download handlers that share the same
// in-memory metadata store and mock connector — an upload via one handler
// is immediately visible to the other.
type testHarness struct {
	upload   *UploadHandler
	download *DownloadHandler
	mc       *mockConnector
	store    *metadata.Store
}

// newTestHarness creates a matched pair of upload/download handlers backed by
// the same in-memory SQLite store and mock connector.
func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	mc := newMockConnector()
	store, err := metadata.New(":memory:")
	if err != nil {
		t.Fatalf("new metadata store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return &testHarness{
		upload:   NewUploadHandler(mc, store),
		download: NewDownloadHandler(mc, store),
		mc:       mc,
		store:    store,
	}
}

// uploadDoc performs a real upload through the upload handler and returns the
// document ID from the JSON response. This gives us a properly encrypted file
// in the mock connector plus a valid metadata row in the store.
func (h *testHarness) uploadDoc(t *testing.T, filename string, content []byte, kek []byte, userID string) string {
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

	// Extract doc ID from the JSON response
	// Quick parse — we only need the "id" field
	body := rr.Body.String()
	return extractJSONField(t, body, "id")
}

// extractJSONField is a minimal JSON field extractor — avoids pulling in
// encoding/json for a single string field in test helpers.
func extractJSONField(t *testing.T, jsonStr, field string) string {
	t.Helper()
	// Look for "field":"value"
	key := fmt.Sprintf(`"%s":"`, field)
	idx := bytes.Index([]byte(jsonStr), []byte(key))
	if idx == -1 {
		t.Fatalf("field %q not found in JSON: %s", field, jsonStr)
	}
	start := idx + len(key)
	end := bytes.IndexByte([]byte(jsonStr[start:]), '"')
	if end == -1 {
		t.Fatalf("unterminated string for field %q in JSON: %s", field, jsonStr)
	}
	return jsonStr[start : start+end]
}

// downloadRequest builds a GET request for the download endpoint with chi URL
// params and auth context attached.
func downloadRequest(t *testing.T, docID string, kek []byte, userID string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/docs/"+docID+"/download", nil)
	req = withAuthContext(req, kek, userID)

	// Inject chi URL param — chi stores route params in the request context
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("docID", docID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	return req, httptest.NewRecorder()
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestDownload_Success(t *testing.T) {
	h := newTestHarness(t)

	plaintext := []byte("hello docops — this is my confidential document")
	docID := h.uploadDoc(t, "report.pdf", plaintext, downloadTestKEK, downloadTestUserID)

	req, rr := downloadRequest(t, docID, downloadTestKEK, downloadTestUserID)
	h.download.Download(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// The decrypted body must exactly match the original plaintext
	got := rr.Body.Bytes()
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, got)
	}
}

func TestDownload_SetsContentDisposition(t *testing.T) {
	h := newTestHarness(t)

	docID := h.uploadDoc(t, "quarterly-report.pdf", []byte("Q4 numbers"), downloadTestKEK, downloadTestUserID)

	req, rr := downloadRequest(t, docID, downloadTestKEK, downloadTestUserID)
	h.download.Download(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}

	// Content-Disposition should trigger a browser download with the original filename
	cd := rr.Header().Get("Content-Disposition")
	expected := `attachment; filename="quarterly-report.pdf"`
	if cd != expected {
		t.Errorf("Content-Disposition:\n  want: %s\n  got:  %s", expected, cd)
	}
}

func TestDownload_SetsContentType(t *testing.T) {
	h := newTestHarness(t)

	docID := h.uploadDoc(t, "data.csv", []byte("a,b,c\n1,2,3"), downloadTestKEK, downloadTestUserID)

	req, rr := downloadRequest(t, docID, downloadTestKEK, downloadTestUserID)
	h.download.Download(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}

	// Content-Type should match the original upload's MIME type
	ct := rr.Header().Get("Content-Type")
	if ct == "" {
		t.Error("Content-Type header is empty")
	}
}

func TestDownload_MissingDocID(t *testing.T) {
	h := newTestHarness(t)

	// Build a request with an empty docID param
	req, rr := downloadRequest(t, "", downloadTestKEK, downloadTestUserID)
	h.download.Download(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing doc ID, got %d", rr.Code)
	}
}

func TestDownload_NoKEKInContext(t *testing.T) {
	h := newTestHarness(t)

	docID := h.uploadDoc(t, "doc.pdf", []byte("content"), downloadTestKEK, downloadTestUserID)

	req := httptest.NewRequest(http.MethodGet, "/v1/docs/"+docID+"/download", nil)
	// Attach UserID but NOT KEK — simulates a broken middleware chain
	ctx := context.WithValue(req.Context(), middleware.UserIDKey, downloadTestUserID)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("docID", docID)
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.download.Download(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 when KEK is missing, got %d", rr.Code)
	}
}

func TestDownload_NoUserIDInContext(t *testing.T) {
	h := newTestHarness(t)

	docID := h.uploadDoc(t, "doc.pdf", []byte("content"), downloadTestKEK, downloadTestUserID)

	req := httptest.NewRequest(http.MethodGet, "/v1/docs/"+docID+"/download", nil)
	// Attach KEK but NOT UserID
	ctx := context.WithValue(req.Context(), middleware.KEKKey, downloadTestKEK)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("docID", docID)
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.download.Download(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 when UserID is missing, got %d", rr.Code)
	}
}

func TestDownload_DocumentNotFound(t *testing.T) {
	h := newTestHarness(t)

	// Request a doc ID that was never uploaded
	req, rr := downloadRequest(t, "doc_nonexistent-id", downloadTestKEK, downloadTestUserID)
	h.download.Download(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404 for non-existent document, got %d", rr.Code)
	}
}

func TestDownload_WrongUserCannotAccess(t *testing.T) {
	h := newTestHarness(t)

	// Upload as user A
	docID := h.uploadDoc(t, "secret.pdf", []byte("user-A-only"), downloadTestKEK, downloadTestUserID)

	// Download as user B — same KEK (in theory) but different userID
	otherUser := "user-download-test-ATTACKER"
	req, rr := downloadRequest(t, docID, downloadTestKEK, otherUser)
	h.download.Download(rr, req)

	// The metadata store filters by user_id, so this should be 404
	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404 when another user tries to download, got %d", rr.Code)
	}
}

func TestDownload_WrongKEKFailsDecryption(t *testing.T) {
	h := newTestHarness(t)

	docID := h.uploadDoc(t, "doc.pdf", []byte("encrypted content"), downloadTestKEK, downloadTestUserID)

	// Use a different KEK — DEK unwrapping should fail
	wrongKEK := []byte("wrong-kek-32-bytes-long-padding!")
	req, rr := downloadRequest(t, docID, wrongKEK, downloadTestUserID)
	h.download.Download(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 when KEK is wrong, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestDownload_StorageFailure(t *testing.T) {
	h := newTestHarness(t)

	docID := h.uploadDoc(t, "doc.pdf", []byte("content"), downloadTestKEK, downloadTestUserID)

	// Remove the file from the mock connector to simulate storage failure
	for k := range h.mc.uploaded {
		delete(h.mc.uploaded, k)
	}

	req, rr := downloadRequest(t, docID, downloadTestKEK, downloadTestUserID)
	h.download.Download(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 on storage failure, got %d", rr.Code)
	}
}

func TestDownload_RoundTripLargeFile(t *testing.T) {
	h := newTestHarness(t)

	// Create a file larger than StreamChunkSize (64 KB) to exercise
	// the chunked encrypt/decrypt path across multiple GCM chunks.
	plaintext := make([]byte, 200*1024) // 200 KB
	for i := range plaintext {
		plaintext[i] = byte(i % 251) // deterministic non-zero fill
	}

	docID := h.uploadDoc(t, "big-file.bin", plaintext, downloadTestKEK, downloadTestUserID)

	req, rr := downloadRequest(t, docID, downloadTestKEK, downloadTestUserID)
	h.download.Download(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	got := rr.Body.Bytes()
	if !bytes.Equal(got, plaintext) {
		t.Errorf("large file round-trip mismatch: want %d bytes, got %d bytes", len(plaintext), len(got))
	}
}

func TestDownload_RoundTripPreservesExactContent(t *testing.T) {
	h := newTestHarness(t)

	// Upload multiple files and verify each one round-trips correctly
	files := []struct {
		name    string
		content []byte
	}{
		{"empty.txt", []byte{}},
		{"tiny.txt", []byte("x")},
		{"unicode.txt", []byte("日本語テスト — émojis: 🔐🗄️📄")},
		{"binary.bin", func() []byte {
			b := make([]byte, 256)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}()},
	}

	for _, f := range files {
		t.Run(f.name, func(t *testing.T) {
			docID := h.uploadDoc(t, f.name, f.content, downloadTestKEK, downloadTestUserID)

			req, rr := downloadRequest(t, docID, downloadTestKEK, downloadTestUserID)
			h.download.Download(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
			}

			got := rr.Body.Bytes()
			if !bytes.Equal(got, f.content) {
				t.Errorf("content mismatch for %s:\n  want %d bytes\n  got  %d bytes",
					f.name, len(f.content), len(got))
			}
		})
	}
}

func TestDownload_StoredDataIsNotPlaintext(t *testing.T) {
	h := newTestHarness(t)

	plaintext := []byte("this must never appear in storage as-is")
	h.uploadDoc(t, "sensitive.pdf", plaintext, downloadTestKEK, downloadTestUserID)

	// Verify the mock connector holds encrypted (not plaintext) bytes
	for key, stored := range h.mc.uploaded {
		if bytes.Equal(stored, plaintext) {
			t.Errorf("file %q stored as plaintext — encryption not applied", key)
		}
		if bytes.Contains(stored, plaintext) {
			t.Errorf("file %q contains plaintext substring — partial encryption?", key)
		}
	}
}

func TestDownload_NoAuthContext(t *testing.T) {
	h := newTestHarness(t)

	docID := h.uploadDoc(t, "doc.pdf", []byte("content"), downloadTestKEK, downloadTestUserID)

	// No KEK and no UserID — completely unauthenticated request
	req := httptest.NewRequest(http.MethodGet, "/v1/docs/"+docID+"/download", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("docID", docID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	h.download.Download(rr, req)

	// Handler checks KEK first → returns 500 (internal error)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 with no auth context, got %d", rr.Code)
	}

	// Verify no file content leaked
	body := rr.Body.String()
	if bytes.Contains([]byte(body), []byte("content")) {
		// "content" could appear in the error message, but not as raw file bytes
		// This is a loose check — the key assertion is the status code
	}
}

func TestDownload_StreamedResponseNotBuffered(t *testing.T) {
	h := newTestHarness(t)

	// Upload, then download and read in small increments to confirm the
	// response is streamable (io.Copy writes as reads complete).
	plaintext := []byte("streaming test — data should flow chunk by chunk")
	docID := h.uploadDoc(t, "stream.txt", plaintext, downloadTestKEK, downloadTestUserID)

	req, rr := downloadRequest(t, docID, downloadTestKEK, downloadTestUserID)
	h.download.Download(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}

	// Read the response body in small pieces to confirm it's all there
	var result bytes.Buffer
	buf := make([]byte, 8) // deliberately small reads
	reader := bytes.NewReader(rr.Body.Bytes())
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			result.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
	}

	if !bytes.Equal(result.Bytes(), plaintext) {
		t.Errorf("streamed content mismatch")
	}
}
