package auth

import (
    "bytes"
    "sync"
    "testing"
    "time"
)

// ─── HELPERS ─────────────────────────────────────────────────

// testSession returns a valid, non-expired Session with a known KEK.
// Callers that need variations (expired, different user) mutate a copy.
func testSession() *Session {
    return &Session{
        UserID:    "user-001",
        KEK:       []byte("kek-32-bytes-exactly-padding-here"),
        ExpiresAt: time.Now().Add(1 * time.Hour),
    }
}

// mustGet calls store.Get and fails the test if the token is not found.
// Use this when Get is a precondition, not the subject under test.
func mustGet(t *testing.T, store *SessionStore, token string) *Session {
    t.Helper()
    session, ok := store.Get(token)
    if !ok {
        t.Fatalf("precondition failed — Get(%q) returned nothing", token)
    }
    return session
}

// ─── Save + Get ──────────────────────────────────────────────

// TestSessionSaveAndGet_FullRoundTrip verifies every field is returned
// correctly — including the KEK, which is the most sensitive value the
// session holds and must survive the store round-trip intact.
func TestSessionSaveAndGet_FullRoundTrip(t *testing.T) {
    store := NewSessionStore()
    session := testSession()
    store.Save("token-abc", session)

    got, ok := store.Get("token-abc")
    if !ok {
        t.Fatal("Get returned nothing for a saved token")
    }
    if got.UserID != session.UserID {
        t.Errorf("UserID: want %q got %q", session.UserID, got.UserID)
    }
    if !bytes.Equal(got.KEK, session.KEK) {
        t.Errorf("KEK: want %x got %x", session.KEK, got.KEK)
    }
    if !got.ExpiresAt.Equal(session.ExpiresAt) {
        t.Errorf("ExpiresAt: want %v got %v", session.ExpiresAt, got.ExpiresAt)
    }
}

// TestSessionGet_NotFound confirms that Get on an unknown token returns
// (nil, false) rather than panicking or returning a zero-value Session.
func TestSessionGet_NotFound(t *testing.T) {
    store := NewSessionStore()

    got, ok := store.Get("nonexistent-token")
    if ok {
        t.Fatal("Get returned ok=true for a token that was never saved")
    }
    if got != nil {
        t.Errorf("Get returned non-nil session for unknown token: %+v", got)
    }
}

// TestSessionSave_OverwritesExistingToken confirms that saving a new session
// under an existing token replaces it completely. This matters for token reuse
// after re-authentication — the old KEK must not linger.
func TestSessionSave_OverwritesExistingToken(t *testing.T) {
    store := NewSessionStore()

    original := testSession()
    store.Save("token-abc", original)

    replacement := &Session{
        UserID:    "user-002",
        KEK:       []byte("different-kek-32-bytes-padding--"),
        ExpiresAt: time.Now().Add(2 * time.Hour),
    }
    store.Save("token-abc", replacement)

    got := mustGet(t, store, "token-abc")

    if got.UserID != replacement.UserID {
        t.Errorf("UserID: want %q (replacement) got %q", replacement.UserID, got.UserID)
    }
    if !bytes.Equal(got.KEK, replacement.KEK) {
        t.Errorf("KEK was not replaced — old KEK may still be active")
    }
}

// ─── Expiry ──────────────────────────────────────────────────

func TestSessionGet_ExpiredToken(t *testing.T) {
    store := NewSessionStore()

    expired := &Session{
        UserID:    "user-001",
        KEK:       []byte("kek-32-bytes-exactly-padding-here"),
        ExpiresAt: time.Now().Add(-1 * time.Minute), // already in the past
    }
    store.Save("token-abc", expired)

    _, ok := store.Get("token-abc")
    if ok {
        t.Fatal("Get returned ok=true for an expired session")
    }
}

// TestSessionGet_ExpiresAtBoundary checks the exact expiry boundary.
// A session expiring right now (zero or negative duration) must be rejected,
// not treated as valid because the clock hasn't ticked yet.
func TestSessionGet_ExpiresAtBoundary(t *testing.T) {
    store := NewSessionStore()

    boundary := &Session{
        UserID:    "user-001",
        KEK:       []byte("kek-32-bytes-exactly-padding-here"),
        ExpiresAt: time.Now(), // expires this instant
    }
    store.Save("token-boundary", boundary)

    // Sleep 1ms to ensure we are definitively past ExpiresAt.
    time.Sleep(time.Millisecond)

    _, ok := store.Get("token-boundary")
    if ok {
        t.Fatal("Get returned ok=true for a session that expired at the boundary")
    }
}

// ─── Delete ──────────────────────────────────────────────────

func TestSessionDelete_RemovesSession(t *testing.T) {
    store := NewSessionStore()
    store.Save("token-abc", testSession())

    // Confirm it exists before we delete it.
    mustGet(t, store, "token-abc")

    store.Delete("token-abc")

    _, ok := store.Get("token-abc")
    if ok {
        t.Fatal("Get returned ok=true for a deleted session")
    }
}

// TestSessionDelete_NonexistentToken confirms that deleting an unknown token
// does not panic. Silent no-ops are acceptable; panics are not.
func TestSessionDelete_NonexistentToken(t *testing.T) {
    store := NewSessionStore()
    // Must not panic.
    store.Delete("never-saved-token")
}

// ─── Concurrency ─────────────────────────────────────────────

// TestSessionStore_ConcurrentAccess detects data races on the SessionStore's
// internal map. Run with: go test -race ./...
//
// If this test triggers the race detector it means Save/Get/Delete are not
// protected by a mutex — a real vulnerability in a multi-user server where
// every request runs in its own goroutine.
func TestSessionStore_ConcurrentAccess(t *testing.T) {
    store := NewSessionStore()
    const goroutines = 50

    var wg sync.WaitGroup
    wg.Add(goroutines * 3) // save + get + delete per goroutine

    for i := 0; i < goroutines; i++ {
        token := "token-" + string(rune('A'+i))
        go func(tok string) {
            defer wg.Done()
            store.Save(tok, testSession())
        }(token)

        go func(tok string) {
            defer wg.Done()
            store.Get(tok) // may or may not find it — that's fine
        }(token)

        go func(tok string) {
            defer wg.Done()
            store.Delete(tok)
        }(token)
    }

    wg.Wait()
}