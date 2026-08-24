package handlers

import (
	"log/slog"
	"net"
	"net/http"
)

// audit emits a structured, greppable security event for every authentication-
// sensitive action (login attempts, registrations, recoveries, key lifecycle).
//
// Invariants enforced here, not at call sites:
//   - Only server-derived data is logged: the client IP comes from RemoteAddr,
//     never from X-Forwarded-For (spoofable — see models.RateLimitConfig).
//   - Callers pass identifiers only (user IDs, doc IDs). Passwords, tokens,
//     cookies, recovery keys, and any derived key material must never reach
//     this function.
func audit(r *http.Request, action string, attrs ...any) {
	args := make([]any, 0, len(attrs)+4)
	args = append(args, "action", action, "ip", clientIP(r))
	args = append(args, attrs...)
	slog.Info("security event", args...)
}

// clientIP derives the request IP from RemoteAddr only. Proxy headers are
// deliberately ignored for auditing: unlike rate limiting there is no opt-in
// here, and a spoofable identity column would poison the audit trail itself.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
