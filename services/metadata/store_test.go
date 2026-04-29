package metadata

import (
    "context"
    "testing"
    "time"

    "github.com/Kyei-Ernest/DocOps/models"
)

// newTestStore creates an isolated in-memory SQLite store for each test.
// The store is NOT registered for t.Cleanup — callers must defer store.Close()
// so failures in Close() are surfaced explicitly.
func newTestStore(t *testing.T) *Store {
    t.Helper()
    store, err := New(":memory:")
    if err != nil {
        t.Fatalf("failed to create test store: %v", err)
    }
    return store
}

// testDoc returns a fully-populated Document with known field values.
// Callers that need variations should mutate a copy, not this baseline.
func testDoc() *models.Document {
    // Truncate to second precision to match SQLite DATETIME round-trip.
    now := time.Now().UTC().Truncate(time.Second)
    exp := now.Add(24 * time.Hour)

    return &models.Document{
        ID:            "doc_test001",
        Name:          "contract.pdf",
        FileType:      "application/pdf",
        Provider:      "local",
        StorageKey:    "local/path/contract.pdf",
        Encrypted:     true,
        SizeBytes:     204800,
        Tags:          "legal,2026",
        ExtractedText: "this agreement is between two parties",
        EncryptedDEK:  []byte("fake-encrypted-dek"),
        DEKNonce:      []byte("fake-dek-nonce--"),
        FileNonce:     []byte("fake-file-nonce-"),
        CreatedAt:     now,
        ExpiresAt:     &exp, // pointer — mirrors nullable DATETIME in schema
    }
}

// mustSave calls store.Save and fails the test immediately on error.
// Use this in tests where Save is a precondition, not the subject under test.
func mustSave(t *testing.T, store *Store, doc *models.Document) {
    t.Helper()
    if err := store.Save(context.Background(), doc); err != nil {
        t.Fatalf("precondition failed — Save: %v", err)
    }
}

// ---------------------------------------------------------------------------
// Save + GetByID
// ---------------------------------------------------------------------------

func TestSaveAndGetByID_FullRoundTrip(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    doc := testDoc()
    mustSave(t, store, doc)

    fetched, err := store.GetByID(context.Background(), doc.ID)
    if err != nil {
        t.Fatalf("GetByID failed: %v", err)
    }

    // scalar fields
    if fetched.ID != doc.ID {
        t.Errorf("ID: want %q got %q", doc.ID, fetched.ID)
    }
    if fetched.Name != doc.Name {
        t.Errorf("Name: want %q got %q", doc.Name, fetched.Name)
    }
    if fetched.FileType != doc.FileType {
        t.Errorf("FileType: want %q got %q", doc.FileType, fetched.FileType)
    }
    if fetched.Provider != doc.Provider {
        t.Errorf("Provider: want %q got %q", doc.Provider, fetched.Provider)
    }
    if fetched.StorageKey != doc.StorageKey {
        t.Errorf("StorageKey: want %q got %q", doc.StorageKey, fetched.StorageKey)
    }
    if fetched.Encrypted != doc.Encrypted {
        t.Errorf("Encrypted: want %v got %v", doc.Encrypted, fetched.Encrypted)
    }
    if fetched.SizeBytes != doc.SizeBytes {
        t.Errorf("SizeBytes: want %d got %d", doc.SizeBytes, fetched.SizeBytes)
    }
    if fetched.Tags != doc.Tags {
        t.Errorf("Tags: want %q got %q", doc.Tags, fetched.Tags)
    }
    if fetched.ExtractedText != doc.ExtractedText {
        t.Errorf("ExtractedText: want %q got %q", doc.ExtractedText, fetched.ExtractedText)
    }

    // byte slices — bytes.Equal gives a cleaner failure than reflect.DeepEqual here
    if string(fetched.EncryptedDEK) != string(doc.EncryptedDEK) {
        t.Errorf("EncryptedDEK: want %x got %x", doc.EncryptedDEK, fetched.EncryptedDEK)
    }
    if string(fetched.DEKNonce) != string(doc.DEKNonce) {
        t.Errorf("DEKNonce: want %x got %x", doc.DEKNonce, fetched.DEKNonce)
    }
    if string(fetched.FileNonce) != string(doc.FileNonce) {
        t.Errorf("FileNonce: want %x got %x", doc.FileNonce, fetched.FileNonce)
    }

    // time fields — compare Unix seconds to avoid timezone/monotonic clock skew
    if fetched.CreatedAt.Unix() != doc.CreatedAt.Unix() {
        t.Errorf("CreatedAt: want %v got %v", doc.CreatedAt, fetched.CreatedAt)
    }
    if doc.ExpiresAt == nil {
        t.Fatal("test fixture has nil ExpiresAt — use testDocNoExpiry for that case")
    }
    if fetched.ExpiresAt == nil || fetched.ExpiresAt.Unix() != doc.ExpiresAt.Unix() {
        t.Errorf("ExpiresAt: want %v got %v", doc.ExpiresAt, fetched.ExpiresAt)
    }
}

// TestSaveAndGetByID_NullExpiry verifies that a document with no expiry
// round-trips correctly — a NULL DATETIME must scan back as a nil pointer,
// not a zero time.Time.
func TestSaveAndGetByID_NullExpiry(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    doc := testDoc()
    doc.ExpiresAt = nil
    mustSave(t, store, doc)

    fetched, err := store.GetByID(context.Background(), doc.ID)
    if err != nil {
        t.Fatalf("GetByID failed: %v", err)
    }
    if fetched.ExpiresAt != nil {
        t.Errorf("ExpiresAt: want nil, got %v", fetched.ExpiresAt)
    }
}

func TestGetByID_NotFound(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    _, err := store.GetByID(context.Background(), "nonexistent")
    if err == nil {
        t.Fatal("expected error for missing document, got nil")
    }
}

// TestSave_DuplicateID ensures a second insert with the same primary key is
// rejected. The production code relies on SQLite's PRIMARY KEY constraint
// rather than an explicit uniqueness check.
func TestSave_DuplicateID(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    doc := testDoc()
    mustSave(t, store, doc)

    if err := store.Save(context.Background(), doc); err == nil {
        t.Fatal("expected error on duplicate ID, got nil")
    }
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

func TestSearch_FindsByExtractedText(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    mustSave(t, store, testDoc())

    results, err := store.Search(context.Background(), "agreement")
    if err != nil {
        t.Fatalf("Search failed: %v", err)
    }
    if len(results) != 1 {
        t.Fatalf("expected 1 result, got %d", len(results))
    }
    if results[0].ID != "doc_test001" {
        t.Errorf("unexpected result ID: %s", results[0].ID)
    }
}

func TestSearch_FindsByTag(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    mustSave(t, store, testDoc())

    results, err := store.Search(context.Background(), "legal")
    if err != nil {
        t.Fatalf("Search failed: %v", err)
    }
    if len(results) != 1 {
        t.Fatalf("expected 1 result, got %d", len(results))
    }
}

// TestSearch_OnlyMatchingDocumentReturned inserts two documents and confirms
// that a query targeting one does not bleed through to the other.
// This catches any accidental "return all rows" bugs in the JOIN or MATCH clause.
func TestSearch_OnlyMatchingDocumentReturned(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    mustSave(t, store, testDoc()) // tags: "legal,2026", text: "agreement"

    other := testDoc()
    other.ID = "doc_test002"
    other.Tags = "finance"
    other.ExtractedText = "quarterly earnings report"
    mustSave(t, store, other)

    results, err := store.Search(context.Background(), "earnings")
    if err != nil {
        t.Fatalf("Search failed: %v", err)
    }
    if len(results) != 1 {
        t.Fatalf("expected 1 result, got %d", len(results))
    }
    if results[0].ID != "doc_test002" {
        t.Errorf("wrong document returned: %s", results[0].ID)
    }
}

func TestSearch_NoResults(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    mustSave(t, store, testDoc())

    results, err := store.Search(context.Background(), "xyznotfound")
    if err != nil {
        t.Fatalf("Search failed: %v", err)
    }
    if len(results) != 0 {
        t.Fatalf("expected no results, got %d", len(results))
    }
}

// TestSearch_EmptyStore verifies Search on an empty database returns an empty
// slice (not nil, not an error).
func TestSearch_EmptyStore(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    results, err := store.Search(context.Background(), "anything")
    if err != nil {
        t.Fatalf("Search on empty store failed: %v", err)
    }
    if len(results) != 0 {
        t.Fatalf("expected empty result, got %d", len(results))
    }
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestDelete_RemovesDocument(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    doc := testDoc()
    mustSave(t, store, doc)

    if err := store.Delete(context.Background(), doc.ID); err != nil {
        t.Fatalf("Delete failed: %v", err)
    }

    _, err := store.GetByID(context.Background(), doc.ID)
    if err == nil {
        t.Fatal("document still present after Delete")
    }
}

// TestDelete_PurgesFTSIndex confirms the AFTER DELETE trigger fires correctly:
// the deleted document must not appear in subsequent searches.
func TestDelete_PurgesFTSIndex(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    doc := testDoc()
    mustSave(t, store, doc)

    if err := store.Delete(context.Background(), doc.ID); err != nil {
        t.Fatalf("Delete failed: %v", err)
    }

    results, err := store.Search(context.Background(), "agreement")
    if err != nil {
        t.Fatalf("Search after delete failed: %v", err)
    }
    if len(results) != 0 {
        t.Fatalf("deleted document still appears in FTS index: %+v", results)
    }
}

func TestDelete_NotFound(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    err := store.Delete(context.Background(), "nonexistent")
    if err == nil {
        t.Fatal("expected error when deleting nonexistent document, got nil")
    }
}