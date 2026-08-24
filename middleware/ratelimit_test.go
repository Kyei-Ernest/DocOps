package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Kyei-Ernest/DocOps/middleware"
)

func TestRateLimit_UnderLimit(t *testing.T) {
	limit := 3
	window := 100 * time.Millisecond
	rl := middleware.NewRateLimiter(limit, window)
	defer rl.Close()

	handler := rl.Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i+1, rr.Code)
		}
	}
}

func TestRateLimit_ExceedLimit(t *testing.T) {
	limit := 2
	window := 500 * time.Millisecond
	rl := middleware.NewRateLimiter(limit, window)
	defer rl.Close()

	handler := rl.Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First two requests should pass
	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i+1, rr.Code)
		}
	}

	// Third request should be blocked
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rr.Code)
	}

	retryAfterHeader := rr.Header().Get("Retry-After")
	if retryAfterHeader == "" {
		t.Error("expected Retry-After header to be set")
	} else {
		retrySecs, err := strconv.Atoi(retryAfterHeader)
		if err != nil {
			t.Errorf("invalid Retry-After value: %q", retryAfterHeader)
		} else if retrySecs <= 0 {
			t.Errorf("Retry-After should be positive, got %d", retrySecs)
		}
	}
}

func TestRateLimit_IPIsolation(t *testing.T) {
	limit := 1
	window := 200 * time.Millisecond
	rl := middleware.NewRateLimiter(limit, window)
	defer rl.Close()

	handler := rl.Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// IP 1 makes 1 request -> OK
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "1.1.1.1:1234"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("IP 1 request 1: want 200, got %d", rr1.Code)
	}

	// IP 1 makes another request -> Blocked
	rr1Block := httptest.NewRecorder()
	handler.ServeHTTP(rr1Block, req1)
	if rr1Block.Code != http.StatusTooManyRequests {
		t.Fatalf("IP 1 request 2: want 429, got %d", rr1Block.Code)
	}

	// IP 2 makes 1 request -> OK (isolated from IP 1)
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "2.2.2.2:5678"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("IP 2 request 1: want 200, got %d", rr2.Code)
	}
}

func TestRateLimit_ProxyHeadersTrustedMode(t *testing.T) {
	limit := 1
	window := 200 * time.Millisecond
	rl := middleware.NewRateLimiterWithTrust(limit, window, true)
	defer rl.Close()

	handler := rl.Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Request with X-Forwarded-For
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "127.0.0.1:9999" // gateway IP
	req1.Header.Set("X-Forwarded-For", "5.5.5.5")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr1.Code)
	}

	// Request with X-Forwarded-For from same client IP -> Blocked
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "127.0.0.1:8888" // different port/gateway IP
	req2.Header.Set("X-Forwarded-For", "5.5.5.5")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rr2.Code)
	}
}

// In the default (untrusted) mode, client-supplied proxy headers must be
// ignored entirely — otherwise an attacker rotates their apparent IP per
// request and the limit never applies.
func TestRateLimit_ProxyHeadersIgnoredByDefault(t *testing.T) {
	limit := 1
	window := 200 * time.Millisecond
	rl := middleware.NewRateLimiter(limit, window)
	defer rl.Close()

	handler := rl.Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request consumes the budget.
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "10.0.0.1:1000"
	req1.Header.Set("X-Forwarded-For", "5.5.5.5")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr1.Code)
	}

	// Second request from the SAME RemoteAddr but a DIFFERENT spoofed XFF:
	// must still count against 10.0.0.1 and be blocked, not start a fresh
	// window under the attacker-chosen identity.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.0.1:1000"
	req2.Header.Set("X-Forwarded-For", "6.6.6.6")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 despite spoofed XFF, got %d", rr2.Code)
	}
}

func TestRateLimit_ResetAfterWindow(t *testing.T) {
	limit := 1
	window := 50 * time.Millisecond
	rl := middleware.NewRateLimiter(limit, window)
	defer rl.Close()

	handler := rl.Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Request 1 -> OK
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "9.9.9.9:12345"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req)
	if rr1.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr1.Code)
	}

	// Request 2 (immediate) -> Blocked
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rr2.Code)
	}

	// Wait for window to expire
	time.Sleep(2 * window)

	// Request 3 -> OK again
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req)
	if rr3.Code != http.StatusOK {
		t.Fatalf("want 200, got %d after sleep", rr3.Code)
	}
}
