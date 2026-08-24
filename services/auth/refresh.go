package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"
)

// RefreshTokenRecord is the durable identity of a long-lived refresh cookie.
//
// Deliberately stored WITHOUT any key material: only a SHA-256 token hash,
// owner identity, and validity window. This gives three properties the
// RAM-only design lacked — revocation that survives restarts, an audit
// surface, and groundwork for future key-recovery roots — while preserving
// the core invariant that nothing able to decrypt documents ever rests on
// disk. After a restart a durable-but-valid token still cannot mint an
// access session (the Master Key died with process memory): the holder must
// re-authenticate fully. That is a feature, not a bug.
type RefreshTokenRecord struct {
	TokenHash [32]byte
	UserID    string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

// RefreshTokenStore persists hashed refresh-token identities in SQLite.
type RefreshTokenStore struct {
	db *sql.DB
}

const refreshTokensSchema = `
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		token_hash BLOB PRIMARY KEY,
		user_id    TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		revoked_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
`

// NewRefreshTokenStore runs migrations and returns a ready store over the shared pool.
func NewRefreshTokenStore(db *sql.DB) (*RefreshTokenStore, error) {
	if _, err := db.Exec(refreshTokensSchema); err != nil {
		return nil, fmt.Errorf("refresh tokens migrate: %w", err)
	}
	return &RefreshTokenStore{db: db}, nil
}

// HashRefreshToken derives the at-rest form of a refresh cookie value.
func HashRefreshToken(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

// Save durably records a freshly issued refresh token.
func (s *RefreshTokenStore) Save(ctx context.Context, token, userID string, expiresAt time.Time) error {
	h := HashRefreshToken(token)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO refresh_tokens (token_hash, user_id, created_at, expires_at)
		VALUES (?, ?, ?, ?)`, h[:], userID, time.Now().UTC(), expiresAt)
	if err != nil {
		return fmt.Errorf("save refresh token: %w", err)
	}
	return nil
}

// GetValid resolves a presented token to its identity iff it exists, is
// unexpired, and unrevoked. Unknown/expired/revoked all return (nil, nil):
// callers emit one generic failure, leaking none of the three cases apart.
func (s *RefreshTokenStore) GetValid(ctx context.Context, token string) (*RefreshTokenRecord, error) {
	h := HashRefreshToken(token)
	row := s.db.QueryRowContext(ctx, `
		SELECT user_id, created_at, expires_at, revoked_at
		FROM refresh_tokens WHERE token_hash = ?`, h[:])

	rec := &RefreshTokenRecord{}
	var revoked sql.NullTime
	err := row.Scan(&rec.UserID, &rec.CreatedAt, &rec.ExpiresAt, &revoked)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	if revoked.Valid {
		t := revoked.Time
		rec.RevokedAt = &t
		return nil, nil
	}
	if time.Now().After(rec.ExpiresAt) {
		return nil, nil
	}
	rec.TokenHash = h
	return rec, nil
}

// Revoke kills a token by its presented (unhashed) value — used by logout.
// No-op if unknown; idempotent by construction.
func (s *RefreshTokenStore) Revoke(ctx context.Context, token string) error {
	h := HashRefreshToken(token)
	_, err := s.db.ExecContext(ctx, `
		UPDATE refresh_tokens SET revoked_at = ?
		WHERE token_hash = ? AND revoked_at IS NULL`,
		time.Now().UTC(), h[:])
	if err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
}

// PurgeExpired removes rows past their validity window. Called opportunistically
// to keep the table proportional to active remember-me sessions.
func (s *RefreshTokenStore) PurgeExpired(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM refresh_tokens WHERE expires_at < ? OR revoked_at IS NOT NULL`,
		time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		return 0, fmt.Errorf("purge refresh tokens: %w", err)
	}
	n, _ := result.RowsAffected()
	return n, nil
}
