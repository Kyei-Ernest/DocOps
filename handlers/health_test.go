package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func newTestHealthDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("ping sqlite: %v", err)
	}
	return db
}

// failingPingConnector wraps a mockConnector but forces Ping to fail.
type failingPingConnector struct{ *mockConnector }

var errStorageDown = errors.New("storage unreachable")

func (f *failingPingConnector) Ping(_ context.Context) error { return errStorageDown }

func TestLiveReturnsOKWithoutTouchingDependencies(t *testing.T) {
	h := NewHealthHandler(nil, nil) // nil deps must not matter for liveness

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.Live(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("body = %q, want status ok", body)
	}
}

func TestReadyAllHealthy(t *testing.T) {
	h := NewHealthHandler(newTestHealthDB(t), newMockConnector())

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Ready(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	for _, part := range []string{`"database":"ok"`, `"storage":"ok"`} {
		if !strings.Contains(rec.Body.String(), part) {
			t.Fatalf("body = %q, missing %s", rec.Body.String(), part)
		}
	}
}

func TestReadyDatabaseDown(t *testing.T) {
	db := newTestHealthDB(t)
	db.Close() // simulate an unreachable database

	h := NewHealthHandler(db, newMockConnector())
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Ready(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"database":"unavailable"`) {
		t.Fatalf("body = %q, want database unavailable", rec.Body.String())
	}
}

func TestReadyStorageDown(t *testing.T) {
	h := NewHealthHandler(newTestHealthDB(t), &failingPingConnector{newMockConnector()})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Ready(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"storage":"unavailable"`) {
		t.Fatalf("body = %q, want storage unavailable", rec.Body.String())
	}
	// The raw storage error text must not leak through the probe response.
	if strings.Contains(rec.Body.String(), errStorageDown.Error()) {
		t.Fatalf("body = %q leaks internal error detail", rec.Body.String())
	}
}

func TestReadyNilDependenciesDegradeNotPanic(t *testing.T) {
	h := NewHealthHandler(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Ready(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
