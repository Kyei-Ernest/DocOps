// Package middleware provides cross-cutting HTTP concerns for DocOps:
// authentication (session-cookie fork + stateless API-key bearer fork) with
// context injection, and IP-based rate limiting.
//
// Context keys are deliberately unexported typed structs — other packages can
// read values only through the exported accessors (KEKFromContext,
// UserIDFromContext), never by constructing keys themselves.
package middleware

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type visitor struct {
	count       int
	windowStart time.Time
}

// RateLimiter implements an IP-based, fixed-window rate limiter middleware.
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	limit    int
	window   time.Duration
	// trustProxyHeaders gates whether X-Forwarded-For / X-Real-IP may
	// override RemoteAddr. These headers are client-controlled input; when
	// false (the default) they are ignored entirely so a directly-exposed
	// server cannot be bypassed by header spoofing. Enable only behind a
	// proxy that sanitizes or overwrites them.
	trustProxyHeaders bool
	stopChan          chan struct{}
}

// NewRateLimiter creates a new RateLimiter instance and starts the background cleanup loop.
// Proxy headers are never trusted; use NewRateLimiterWithTrust behind a
// sanitizing reverse proxy.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return NewRateLimiterWithTrust(limit, window, false)
}

// NewRateLimiterWithTrust is NewRateLimiter with explicit control over proxy-header
// trust. Only pass true when requests arrive via a proxy that overwrites (not
// merely appends to) X-Forwarded-For — otherwise callers own their identity.
func NewRateLimiterWithTrust(limit int, window time.Duration, trustProxyHeaders bool) *RateLimiter {
	rl := &RateLimiter{
		visitors:          make(map[string]*visitor),
		limit:             limit,
		window:            window,
		trustProxyHeaders: trustProxyHeaders,
		stopChan:          make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Close stops the background cleanup loop.
func (rl *RateLimiter) Close() {
	close(rl.stopChan)
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopChan:
			return
		}
	}
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for ip, v := range rl.visitors {
		if now.Sub(v.windowStart) > rl.window {
			delete(rl.visitors, ip)
		}
	}
}

// Limit returns an HTTP middleware that rate-limits requests by IP address.
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// Fallback if RemoteAddr is not in host:port format
			ip = r.RemoteAddr
		}

		// Support common proxy headers for IP identification — but only when
		// explicitly configured. Unconditionally trusting these lets any
		// client rotate its apparent IP per request (bypassing the limit)
		// or pin a victim's real IP into persistent 429s.
		if rl.trustProxyHeaders {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				ip = xff
			} else if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
				ip = xrip
			}
		}

		rl.mu.Lock()
		v, exists := rl.visitors[ip]
		now := time.Now()

		if !exists || now.Sub(v.windowStart) > rl.window {
			rl.visitors[ip] = &visitor{count: 1, windowStart: now}
			rl.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		v.count++

		if v.count > rl.limit {
			retryAfter := int((rl.window - now.Sub(v.windowStart)).Seconds())
			if retryAfter <= 0 {
				retryAfter = 1
			}
			rl.mu.Unlock()
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
			return
		}

		rl.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}
