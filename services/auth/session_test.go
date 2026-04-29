package auth

import (
    "testing"
    "time"
)

func TestSessionSaveAndGet(t *testing.T) {
    store := NewSessionStore()

    session := &Session{
        UserID:    "user-001",
        KEK:       []byte("kek-32-bytes-exactly-padding-here"),
        ExpiresAt: time.Now().Add(1 * time.Hour),
    }

    store.Save("token-abc", session)

    got, ok := store.Get("token-abc")
    if !ok {
        t.Fatal("expected session, got nothing")
    }
    if got.UserID != "user-001" {
        t.Errorf("expected UserID user-001, got %s", got.UserID)
    }
}

func TestSessionExpiry(t *testing.T) {
    store := NewSessionStore()

    session := &Session{
        UserID:    "user-001",
        KEK:       []byte("kek-32-bytes-exactly-padding-here"),
        ExpiresAt: time.Now().Add(-1 * time.Minute), // already expired
    }

    store.Save("token-abc", session)

    _, ok := store.Get("token-abc")
    if ok {
        t.Fatal("expected expired session to be not found")
    }
}

func TestSessionDelete(t *testing.T) {
    store := NewSessionStore()

    session := &Session{
        UserID:    "user-001",
        KEK:       []byte("kek-32-bytes-exactly-padding-here"),
        ExpiresAt: time.Now().Add(1 * time.Hour),
    }

    store.Save("token-abc", session)
    store.Delete("token-abc")

    _, ok := store.Get("token-abc")
    if ok {
        t.Fatal("expected deleted session to be not found")
    }
}