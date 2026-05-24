package local

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/Kyei-Ernest/DocOps/models"
)

// newTestConnector creates a LocalConnector using a temporary
// directory that Go manages and cleans up after the test runs.
// t.TempDir() returns a different path for every test — tests
// are completely isolated from each other.
func newTestConnector(t *testing.T) *LocalConnector {
	t.Helper()
	c, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create test connector: %v", err)
	}
	return c
}

// testUploadRequest builds a minimal UploadRequest with
// known content so tests can verify exact byte matching.
func testUploadRequest(key string, content []byte) models.UploadRequest {
	return models.UploadRequest{
		Key:         key,
		Content:     bytes.NewReader(content),
		ContentType: "application/pdf",
		SizeBytes:   int64(len(content)),
	}
}

// TestNew_CreatesDirectory verifies that New() creates the
// storage directory if it does not already exist.
func TestNew_CreatesDirectory(t *testing.T) {
	// use a subdirectory inside TempDir that doesn't exist yet
	base := t.TempDir() + "/nested/path/files"

	_, err := New(base)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// confirm the directory was actually created
	if _, err := os.Stat(base); err != nil {
		t.Fatalf("directory was not created: %v", err)
	}
}

// TestUploadAndDownload is the core round-trip test.
// It uploads known bytes and downloads them back,
// verifying the content is identical.
func TestUploadAndDownload(t *testing.T) {
	c := newTestConnector(t)
	ctx := context.Background()

	original := []byte("this is a test document for docops")
	req := testUploadRequest("test-key-001", original)

	// upload
	ref, err := c.Upload(ctx, req)
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}
	if ref.Key != "test-key-001" {
		t.Errorf("expected key %q got %q", "test-key-001", ref.Key)
	}
	if ref.SizeBytes != int64(len(original)) {
		t.Errorf("expected %d bytes got %d", len(original), ref.SizeBytes)
	}

	// download
	rc, err := c.Download(ctx, "test-key-001")
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	defer rc.Close() // always close the ReadCloser

	downloaded, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("failed to read downloaded content: %v", err)
	}

	// verify bytes match exactly
	if !bytes.Equal(original, downloaded) {
		t.Errorf("content mismatch\nexpected: %q\ngot:      %q", original, downloaded)
	}
}

// TestDownload_FileNotFound verifies that downloading a key
// that was never uploaded returns an error, not a panic.
func TestDownload_FileNotFound(t *testing.T) {
	c := newTestConnector(t)

	_, err := c.Download(context.Background(), "does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// TestDelete verifies that after deleting a file,
// a subsequent download returns an error.
func TestDelete(t *testing.T) {
	c := newTestConnector(t)
	ctx := context.Background()

	// upload first so there is something to delete
	req := testUploadRequest("delete-me", []byte("goodbye"))
	c.Upload(ctx, req)

	// delete it
	if err := c.Delete(ctx, "delete-me"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// confirm it is gone
	_, err := c.Download(ctx, "delete-me")
	if err == nil {
		t.Fatal("file still exists after delete")
	}
}

// TestDelete_NotFound verifies that deleting a key that
// does not exist returns an error rather than silently succeeding.
func TestDelete_NotFound(t *testing.T) {
	c := newTestConnector(t)

	err := c.Delete(context.Background(), "never-uploaded")
	if err == nil {
		t.Fatal("expected error when deleting nonexistent file, got nil")
	}
}

// TestPing_Healthy verifies that Ping returns nil
// when the storage directory exists and is accessible.
func TestPing_Healthy(t *testing.T) {
	c := newTestConnector(t)

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping failed on healthy connector: %v", err)
	}
}

// TestPing_BadPath verifies that Ping returns an error
// when the storage directory has been removed after creation.
func TestPing_BadPath(t *testing.T) {
	c := newTestConnector(t)

	// remove the directory after the connector was created
	os.RemoveAll(c.basePath)

	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected Ping to fail after directory removed, got nil")
	}
}
