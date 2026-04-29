package auth

import (
    "context"
    "database/sql"
    "testing"
    "time"

    _ "github.com/mattn/go-sqlite3"
)

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

    got, err := store.GetByEmail(ctx, "test@docops.dev")
    if err != nil {
        t.Fatalf("GetByEmail failed: %v", err)
    }
    if got == nil {
        t.Fatal("expected user, got nil")
    }
    if got.ID != user.ID {
        t.Errorf("expected ID %s, got %s", user.ID, got.ID)
    }
    if got.Email != user.Email {
        t.Errorf("expected email %s, got %s", user.Email, got.Email)
    }
}

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

    store.CreateUser(ctx, user)

    user.ID = "user-002"
    if err := store.CreateUser(ctx, user); err == nil {
        t.Fatal("expected error on duplicate email, got nil")
    }
}