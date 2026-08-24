package metadata

import (
	"context"
	"testing"
	"time"

	"github.com/Kyei-Ernest/DocOps/models"
)

func TestExpiredSweep_ListsThenDeletes(t *testing.T) {
	store, err := New(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	docs := []*models.Document{
		{ID: "doc_old_1", UserID: "u1", Name: "a", Provider: "local", StorageKey: "sk-old-1",
			Encrypted: true, CreatedAt: time.Now(), ExpiresAt: &past},
		{ID: "doc_old_2", UserID: "u1", Name: "b", Provider: "local", StorageKey: "sk-old-2",
			Encrypted: true, CreatedAt: time.Now(), ExpiresAt: &past},
		{ID: "doc_new", UserID: "u1", Name: "c", Provider: "local", StorageKey: "sk-new",
			Encrypted: true, CreatedAt: time.Now(), ExpiresAt: &future},
		{ID: "doc_never", UserID: "u1", Name: "d", Provider: "local", StorageKey: "sk-never",
			Encrypted: true, CreatedAt: time.Now()},
	}
	for _, d := range docs {
		if err := store.Save(ctx, d); err != nil {
			t.Fatalf("save %s: %v", d.ID, err)
		}
	}

	keys, err := store.ExpiredStorageKeys(ctx, time.Now())
	if err != nil {
		t.Fatalf("list expired keys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expired keys = %v, want exactly the two old ones", keys)
	}

	n, err := store.DeleteExpiredRows(ctx, time.Now())
	if err != nil || n != 2 {
		t.Fatalf("deleted = %d, %v; want 2", n, err)
	}

	// Survivors intact.
	for _, id := range []string{"doc_new", "doc_never"} {
		if _, err := store.GetByID(ctx, id, "u1"); err != nil {
			t.Fatalf("%s should have survived the sweep: %v", id, err)
		}
	}

	// Second sweep is a no-op (idempotent).
	if n, _ := store.DeleteExpiredRows(ctx, time.Now()); n != 0 {
		t.Fatalf("second sweep removed %d rows, want 0", n)
	}
}
