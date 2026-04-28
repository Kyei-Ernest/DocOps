// services/metadata/store_test.go
package metadata

import (
    "context"
    "testing"
    "time"

    "github.com/Kyei-Ernest/DocOps/models"
)

// use in-memory SQLite for tests — no files created on disk
func newTestStore(t *testing.T) *Store {
    t.Helper()
    store, err := New(":memory:")
    if err != nil {
        t.Fatalf("failed to create test store: %v", err)
    }
    return store
}

func testDoc() *models.Document {
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
        CreatedAt:     time.Now(),
    }
}

func TestSaveAndGetByID(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    doc := testDoc()
    if err := store.Save(context.Background(), doc); err != nil {
        t.Fatalf("Save failed: %v", err)
    }

    fetched, err := store.GetByID(context.Background(), doc.ID)
    if err != nil {
        t.Fatalf("GetByID failed: %v", err)
    }

    if fetched.ID != doc.ID {
        t.Errorf("expected ID %s got %s", doc.ID, fetched.ID)
    }
    if fetched.Name != doc.Name {
        t.Errorf("expected Name %s got %s", doc.Name, fetched.Name)
    }
    if fetched.Provider != doc.Provider {
        t.Errorf("expected Provider %s got %s", doc.Provider, fetched.Provider)
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

func TestSearch_FindsByContent(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    store.Save(context.Background(), testDoc())

    results, err := store.Search(context.Background(), "agreement")
    if err != nil {
        t.Fatalf("Search failed: %v", err)
    }
    if len(results) == 0 {
        t.Fatal("expected search results, got none")
    }
    if results[0].ID != "doc_test001" {
        t.Errorf("unexpected result ID: %s", results[0].ID)
    }
}

func TestSearch_FindsByTag(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    store.Save(context.Background(), testDoc())

    results, err := store.Search(context.Background(), "legal")
    if err != nil {
        t.Fatalf("Search failed: %v", err)
    }
    if len(results) == 0 {
        t.Fatal("expected to find document by tag")
    }
}

func TestSearch_NoResults(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    store.Save(context.Background(), testDoc())

    results, err := store.Search(context.Background(), "xyznotfound")
    if err != nil {
        t.Fatalf("Search failed: %v", err)
    }
    if len(results) != 0 {
        t.Fatalf("expected no results, got %d", len(results))
    }
}

func TestDelete(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    doc := testDoc()
    store.Save(context.Background(), doc)

    if err := store.Delete(context.Background(), doc.ID); err != nil {
        t.Fatalf("Delete failed: %v", err)
    }

    // confirm it's gone
    _, err := store.GetByID(context.Background(), doc.ID)
    if err == nil {
        t.Fatal("document still exists after delete")
    }
}

func TestDelete_NotFound(t *testing.T) {
    store := newTestStore(t)
    defer store.Close()

    err := store.Delete(context.Background(), "nonexistent")
    if err == nil {
        t.Fatal("expected error when deleting nonexistent document")
    }
}