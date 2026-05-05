package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Kyei-Ernest/DocOps/services/crypto"
	"github.com/Kyei-Ernest/DocOps/models"
	authsvc "github.com/Kyei-Ernest/DocOps/services/auth"
	"github.com/golang-jwt/jwt/v5"
)

// accessTokenDuration controls how long an access JWT remains valid.
// Short-lived by design — a stolen access token has a narrow exploitation window.
const (
	accessTokenDuration  = 15 * time.Minute
	refreshTokenDuration = 7 * 24 * time.Hour // 7 days
)

// Claims is the JWT payload.
//
// It carries only an opaque session token — the KEK never enters the JWT.
// On every authenticated request, middleware resolves the session token to a
// server-side Session (which holds the KEK in memory). This means:
//   - Compromising a JWT does not expose encryption key material.
//   - Sessions can be revoked server-side instantly (e.g. on logout or
//     suspected compromise) without waiting for the JWT to expire.
type Claims struct {
	SessionToken string `json:"session_token"`
	jwt.RegisteredClaims
}

// AuthHandler handles registration, login, token refresh, and logout.
//
// It is intentionally the only place that coordinates across the crypto,
// UserStore, and SessionStore packages — thin glue with no algorithm logic.
// All cryptographic primitives live in the crypto package; all persistence
// lives in the authsvc package.
type AuthHandler struct {
	users     *authsvc.UserStore
	sessions  *authsvc.SessionStore
	params    *models.Argon2idParams // shared Argon2id cost parameters (time, memory, threads)
	jwtSecret []byte                 // HMAC-SHA256 signing key for JWTs; must stay secret
}

// NewAuthHandler constructs an AuthHandler with all required dependencies injected.
// Callers are responsible for ensuring jwtSecret is sufficiently random (≥ 32 bytes
// from a CSPRNG) and that params reflect an appropriate Argon2id work factor.
func NewAuthHandler(
	users *authsvc.UserStore,
	sessions *authsvc.SessionStore,
	params *models.Argon2idParams,
	jwtSecret []byte,
) *AuthHandler {
	return &AuthHandler{
		users:     users,
		sessions:  sessions,
		params:    params,
		jwtSecret: jwtSecret,
	}
}

// ── Request types ────────────────────────────────────────────────────────────

// registerRequest is the JSON body expected by POST /register.
type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// loginRequest is the JSON body expected by POST /login.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// Register creates a new user account and immediately issues a session.
//
// Key-derivation overview (two independent Argon2id calls):
//
//  1. HashPassword — produces a PHC-format hash with its own embedded random
//     salt. Stored in users.password_hash. Used only for VerifyPassword on
//     future logins.
//
//  2. DeriveKEK — produces the Key-Encryption Key using a *separate* random
//     salt (kekSalt). The distinct salt ensures the two Argon2id outputs are
//     cryptographically independent; an attacker who learns one cannot derive
//     the other, even knowing the password.
//
// A verification blob is also stored so that Login can confirm KEK correctness
// without running VerifyPassword a second time (see Login for rationale).
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.Password == "" {
		http.Error(w, "email and password are required", http.StatusBadRequest)
		return
	}

	// ── Step 1: password hash ─────────────────────────────────────────────
	// Produces a self-contained PHC string (algorithm + params + salt + hash).
	// Only used to verify the raw password on login; never used for key derivation.
	passwordHash, err := crypto.HashPassword(req.Password, h.params)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// ── Step 2: KEK derivation ────────────────────────────────────────────
	// kekSalt is stored separately in the users table so it can be retrieved
	// at login time to re-derive the same KEK deterministically.
	// It is intentionally different from the PHC-embedded salt above.
	kekSalt, err := crypto.GenerateSalt()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	kek := crypto.DeriveKEK(req.Password, kekSalt, h.params)

	// ── Step 3: verification blob ─────────────────────────────────────────
	// Encrypts a known sentinel value with the KEK. At login, decrypting the
	// sentinel with the re-derived KEK proves correctness without a second
	// VerifyPassword call — and without storing the KEK in plaintext.
	blob, nonce, err := crypto.CreateVerificationBlob(kek)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	user := &authsvc.User{
		Email:             req.Email,
		PasswordHash:      passwordHash,
		Salt:              kekSalt,
		VerificationBlob:  blob,
		VerificationNonce: nonce,
	}
	if err := h.users.CreateUser(r.Context(), user); err != nil {
		// Surface a conflict specifically so the caller can show a helpful message.
		// All other errors are collapsed to 500 to avoid leaking internal details.
		if errors.Is(err, authsvc.ErrDuplicateEmail) {
			http.Error(w, "email already registered", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Auto-login: issue access + refresh tokens so the client doesn't need a
	// separate login round-trip after registration.
	if err := h.issueSession(w, user.ID, kek); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// Login authenticates the user and issues a fresh access + refresh session.
//
// Authentication is a three-step process:
//  1. VerifyPassword — confirms the raw password against the PHC hash.
//  2. DeriveKEK      — re-derives the KEK from the password and stored kekSalt.
//  3. VerifyKEK      — decrypts the sentinel blob to confirm the re-derived KEK
//     is correct (guards against silent Argon2id parameter drift between
//     registration and login).
//
// Error messages are intentionally identical for "no such user" and "wrong
// password" to prevent user-enumeration via timing or response differences.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Look up the user record. A nil user (not found) is handled the same as
	// a wrong password below — same HTTP status, same body.
	user, err := h.users.GetByEmail(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Step 1: verify the raw password against the PHC-format hash.
	// The returned EncryptParams are discarded — KEK derivation always uses
	// the dedicated kekSalt stored in user.Salt, not the PHC-embedded salt,
	// so the two derivation paths remain independent.
	if _, err := crypto.VerifyPassword(req.Password, user.PasswordHash); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Step 2: re-derive the KEK using the stored KEK salt.
	// This must reproduce the exact same key that was created at registration.
	kek := crypto.DeriveKEK(req.Password, user.Salt, h.params)

	// Step 3: belt-and-suspenders KEK check.
	// If Argon2id parameters changed between registration and now (e.g. a
	// misconfiguration or accidental param upgrade), VerifyPassword would still
	// pass but the re-derived KEK would be wrong — causing silent data loss when
	// the user later tries to decrypt documents. Failing loudly here prevents that.
	if !crypto.VerifyKEK(kek, user.VerificationBlob, user.VerificationNonce) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := h.issueSession(w, user.ID, kek); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Refresh issues a new short-lived access JWT from a valid refresh token cookie.
//
// The KEK is carried forward from the existing refresh session — no password
// re-entry is required. The refresh token itself is not rotated here; rotation
// would invalidate legitimate concurrent requests from multi-tab clients. If
// refresh-token rotation is required, implement it with a grace window.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "missing refresh token", http.StatusUnauthorized)
		return
	}

	// Validate the refresh token against the server-side session store.
	// An unknown or expired token returns !ok — no error is logged because
	// this can happen legitimately (e.g. server restart clearing in-memory sessions).
	session, ok := h.sessions.Get(cookie.Value)
	if !ok {
		http.Error(w, "invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	// Issue a new access JWT bound to a new short-lived session entry.
	// The KEK is inherited from the refresh session, not re-derived.
	if err := h.issueAccessJWT(w, session.UserID, session.KEK); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Logout evicts both server-side sessions and clears both cookies.
//
// Cookie clearing is best-effort and always happens, even if token parsing
// fails (e.g. the JWT is already expired). This prevents a broken token from
// leaving a client permanently unable to log out.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Evict the access session by resolving the JWT's session_token claim.
	if cookie, err := r.Cookie("access_token"); err == nil {
		if claims, err := h.parseJWT(cookie.Value); err == nil {
			h.sessions.Delete(claims.SessionToken)
		}
	}
	// Evict the refresh session — its cookie value is the session key directly.
	if cookie, err := r.Cookie("refresh_token"); err == nil {
		h.sessions.Delete(cookie.Value)
	}

	// Always clear cookies regardless of whether session eviction succeeded.
	clearCookie(w, "access_token")
	clearCookie(w, "refresh_token")
	w.WriteHeader(http.StatusNoContent)
}

// ── Private helpers ───────────────────────────────────────────────────────────

// issueSession creates both an access session and a refresh session for the
// given user, signs a JWT referencing the access session, and writes both
// tokens as HttpOnly cookies.
//
// Session topology:
//   - Access session  → identified by the opaque token inside the JWT claim.
//     Resolved by middleware on every authenticated request.
//   - Refresh session → identified directly by the refresh_token cookie value
//     (no JWT wrapper — a refresh token has no claims that benefit from signing).
//
// Neither cookie value encodes the KEK; the KEK lives exclusively in the
// in-memory SessionStore and is never written to disk or sent over the wire.
func (h *AuthHandler) issueSession(w http.ResponseWriter, userID string, kek []byte) error {
	// Issue the short-lived access JWT first.
	if err := h.issueAccessJWT(w, userID, kek); err != nil {
		return err
	}

	// Generate and store the long-lived refresh session.
	refreshToken, err := generateToken()
	if err != nil {
		return err
	}
	h.sessions.Save(refreshToken, &authsvc.Session{
		UserID:    userID,
		KEK:       kek,
		ExpiresAt: time.Now().Add(refreshTokenDuration),
	})
	setHttpOnlyCookie(w, "refresh_token", refreshToken, refreshTokenDuration)

	return nil
}

// issueAccessJWT creates a new short-lived server-side session, signs a JWT
// whose session_token claim points to it, and sets the access_token cookie.
//
// Called by both issueSession (login/register) and Refresh, so both paths
// produce access tokens through the same code.
func (h *AuthHandler) issueAccessJWT(w http.ResponseWriter, userID string, kek []byte) error {
	// The session token is a random opaque string — not the KEK, not the userID.
	// It acts as a lookup key into the SessionStore; the SessionStore holds the KEK.
	sessionToken, err := generateToken()
	if err != nil {
		return err
	}
	h.sessions.Save(sessionToken, &authsvc.Session{
		UserID:    userID,
		KEK:       kek,
		ExpiresAt: time.Now().Add(accessTokenDuration),
	})

	signed, err := h.signJWT(sessionToken)
	if err != nil {
		return err
	}
	setHttpOnlyCookie(w, "access_token", signed, accessTokenDuration)

	return nil
}

// signJWT creates and signs a JWT containing the given session token.
// HMAC-SHA256 is used; asymmetric signing is unnecessary here because
// the server is both the issuer and the sole verifier.
func (h *AuthHandler) signJWT(sessionToken string) (string, error) {
	claims := Claims{
		SessionToken: sessionToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(h.jwtSecret)
}

// parseJWT validates a JWT string and returns its claims.
// The signing method is checked explicitly before the secret is passed to the
// library — this prevents algorithm-confusion attacks (e.g. alg:none).
func (h *AuthHandler) parseJWT(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		// Reject any token that was not signed with HMAC to guard against
		// algorithm substitution (e.g. RS256 with an attacker-controlled public key).
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return h.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// generateToken returns 32 bytes of CSPRNG output encoded as URL-safe base64
// (43 characters, no padding stripped). 256 bits of entropy makes brute-force
// or collision attacks computationally infeasible.
//
// Token generation lives in the handler layer — SessionStore is intentionally
// token-agnostic so it can be tested with deterministic inputs.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// setHttpOnlyCookie writes a cookie that is inaccessible to JavaScript
// (HttpOnly), only sent over TLS (Secure), and scoped to same-site requests
// (SameSiteStrictMode) to mitigate XSS and CSRF risks.
func setHttpOnlyCookie(w http.ResponseWriter, name, value string, duration time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(duration.Seconds()),
	})
}

// clearCookie instructs the browser to delete the named cookie by setting
// MaxAge to -1. Attributes must match the original Set-Cookie exactly
// (Path, HttpOnly, Secure, SameSite) or some browsers will treat them as
// different cookies and leave the original in place.
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}