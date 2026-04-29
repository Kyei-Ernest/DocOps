package auth

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// newTestUserStore creates an in-memory SQLite-backed UserStore for use in tests.
// It registers a cleanup-free teardown via t.Fatalf on setup failure.
func newTestUserStore(t *testing.T) *UserStore {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	store, err := NewUserStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	return store
}

// TestCreateAndGetUser verifies that a user written via CreateUser can be
// retrieved by email with all identity fields intact.
func TestCreateAndGetUser(t *testing.T) {
	store := newTestUserStore(t)
	ctx := context.Background()

	user := &User{
		ID:                "user-001",
		Email:             "test@docops.dev",
		PasswordHash:      "hashed",
		Salt:              []byte("saltsaltsaltsalt"),
		VerificationBlob:  []byte("blob"),
		VerificationNonce: []byte("nonce"),
		CreatedAt:         time.Now(),
	}

	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Fetch the user back by the email used during creation.
	got, err := store.GetByEmail(ctx, "test@docops.dev")
	if err != nil {
		t.Fatalf("GetByEmail failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected user, got nil")
	}

	// Confirm the returned record matches what was originally inserted.
	if got.ID != user.ID {
		t.Errorf("expected ID %s, got %s", user.ID, got.ID)
	}
	if got.Email != user.Email {
		t.Errorf("expected email %s, got %s", user.Email, got.Email)
	}
}

// TestDuplicateEmail verifies that inserting two users with the same email
// address is rejected — the store must enforce email uniqueness.
func TestDuplicateEmail(t *testing.T) {
	store := newTestUserStore(t)
	ctx := context.Background()

	user := &User{
		ID:                "user-001",
		Email:             "test@docops.dev",
		PasswordHash:      "hashed",
		Salt:              []byte("saltsaltsaltsalt"),
		VerificationBlob:  []byte("blob"),
		VerificationNonce: []byte("nonce"),
		CreatedAt:         time.Now(),
	}

	// Seed the store with the initial user.
	store.CreateUser(ctx, user)

	// Attempt to insert a second user sharing the same email but a different ID.
	user.ID = "user-002"
	if err := store.CreateUser(ctx, user); err == nil {
		t.Fatal("expected error on duplicate email, got nil")
	}
}