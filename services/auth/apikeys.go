package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"time"

	"github.com/Kyei-Ernest/DocOps/services/crypto"
)

// APIKey is a machine credential wrapping the owner's Master Key. Unlike
// password sessions it carries NO server-side state at request time: every
// bearer request re-validates the presented secret from the database alone,
// which is what lets machine traffic survive restarts and horizontal scale
// while human sessions stay RAM-only.
type APIKey struct {
	KeyID            string
	UserID           string
	Name             string
	SecretHash       []byte // SHA-256 of the secret component — never the secret itself
	HKDFSalt         []byte // per-key salt; domain separation for wrap-key derivation
	WrappedMasterKey []byte // Master Key wrapped under DeriveAPIWrapKey output, AAD-bound
	MasterKeyNonce   []byte
	CreatedAt        time.Time
	LastUsedAt       *time.Time
	RevokedAt        *time.Time
}

// APIKeyStore persists API keys in SQLite alongside the users they belong to.
type APIKeyStore struct {
	db *sql.DB
}

const apiKeysSchema = `
	CREATE TABLE IF NOT EXISTS api_keys (
		key_id             TEXT PRIMARY KEY,
		user_id            TEXT NOT NULL,
		name               TEXT NOT NULL,
		secret_hash        BLOB NOT NULL,
		hkdf_salt          BLOB NOT NULL,
		wrapped_master_key BLOB NOT NULL,
		master_key_nonce   BLOB NOT NULL,
		created_at         DATETIME NOT NULL,
		last_used_at       DATETIME,
		revoked_at         DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
`

// NewAPIKeyStore runs migrations and returns a ready store over the shared pool.
func NewAPIKeyStore(db *sql.DB) (*APIKeyStore, error) {
	if _, err := db.Exec(apiKeysSchema); err != nil {
		return nil, fmt.Errorf("api keys migrate: %w", err)
	}
	return &APIKeyStore{db: db}, nil
}

// Create persists a fully-prepared key row.
func (s *APIKeyStore) Create(ctx context.Context, k *APIKey) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO api_keys (
			key_id, user_id, name, secret_hash, hkdf_salt,
			wrapped_master_key, master_key_nonce, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		k.KeyID, k.UserID, k.Name, k.SecretHash, k.HKDFSalt,
		k.WrappedMasterKey, k.MasterKeyNonce, k.CreatedAt)
	if err != nil {
		return fmt.Errorf("create api key: %w", err)
	}
	return nil
}

// GetByKeyID fetches one key row by its indexed identifier.
// Returns (nil, nil) when unknown — callers treat that identically to every
// other failure so malformed guesses get no signal.
func (s *APIKeyStore) GetByKeyID(ctx context.Context, keyID string) (*APIKey, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT key_id, user_id, name, secret_hash, hkdf_salt,
		       wrapped_master_key, master_key_nonce, created_at,
		       last_used_at, revoked_at
		FROM api_keys WHERE key_id = ?`, keyID)
	return scanAPIKey(row.Scan)
}

// ListByUser returns all of a user's keys, newest first.
func (s *APIKeyStore) ListByUser(ctx context.Context, userID string) ([]*APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT key_id, user_id, name, secret_hash, hkdf_salt,
		       wrapped_master_key, master_key_nonce, created_at,
		       last_used_at, revoked_at
		FROM api_keys WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var out []*APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Revoke marks a key revoked — fail closed on first subsequent use. Scoped by
// userID so one user can never revoke another's key; RowsAffected==0 covers
// both "not yours" and "doesn't exist" identically.
func (s *APIKeyStore) Revoke(ctx context.Context, userID, keyID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE api_keys SET revoked_at = ?
		WHERE key_id = ? AND user_id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), keyID, userID)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("api key not found or already revoked")
	}
	return nil
}

// lastUsedThrottleWindow bounds write amplification: a busy service holding
// one key must not issue an UPDATE per request.
const lastUsedThrottleWindow = time.Hour

// TouchLastUsed advances last_used_at, but only if it has fallen behind the
// throttle window. Safe to fire-and-forget after successful authentication.
func (s *APIKeyStore) TouchLastUsed(ctx context.Context, keyID string) {
	cutoff := time.Now().UTC().Add(-lastUsedThrottleWindow)
	s.db.ExecContext(ctx, `
		UPDATE api_keys SET last_used_at = ?
		WHERE key_id = ? AND (last_used_at IS NULL OR last_used_at < ?)`,
		time.Now().UTC(), keyID, cutoff)
}

// Authenticate validates a presented bearer credential ("docops_sk_…") and
// returns the owning userID plus the unwrapped Master Key — everything the
// cookie path gets from the session store, derived here statelessly instead.
//
// Every failure mode (malformed, unknown keyID, bad secret, revoked) collapses
// to ok=false; callers emit one identical 401. The secret hash comparison is
// constant-time so response timing leaks nothing about how much of a guessed
// secret was right. On success, last_used_at is refreshed asynchronously —
// never on the hot path.
func (s *APIKeyStore) Authenticate(ctx context.Context, presented string) (userID string, masterKey []byte, ok bool) {
	keyID, secret, wellFormed := crypto.ParseAPIKey(presented)
	if !wellFormed {
		return "", nil, false
	}

	key, err := s.GetByKeyID(ctx, keyID)
	if err != nil || key == nil {
		return "", nil, false
	}
	if key.RevokedAt != nil {
		return "", nil, false
	}

	// Constant-time comparison — this is exactly where a plain equality
	// check would open a byte-by-byte timing side channel.
	if subtle.ConstantTimeCompare(crypto.HashAPISecret(secret), key.SecretHash) != 1 {
		return "", nil, false
	}

	wrapKey, err := crypto.DeriveAPIWrapKey(secret, key.HKDFSalt)
	if err != nil {
		return "", nil, false
	}
	masterKey, err = crypto.UnwrapDEKAny(
		key.WrappedMasterKey, key.MasterKeyNonce, wrapKey,
		crypto.APIKeyAAD(key.UserID, key.KeyID))
	if err != nil {
		return "", nil, false
	}

	go s.TouchLastUsed(context.WithoutCancel(ctx), key.KeyID)
	return key.UserID, masterKey, true
}

type scanFn func(dest ...any) error

func scanAPIKey(scan scanFn) (*APIKey, error) {
	k := &APIKey{}
	var lastUsed, revoked sql.NullTime
	err := scan(
		&k.KeyID, &k.UserID, &k.Name, &k.SecretHash, &k.HKDFSalt,
		&k.WrappedMasterKey, &k.MasterKeyNonce, &k.CreatedAt,
		&lastUsed, &revoked)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan api key: %w", err)
	}
	if lastUsed.Valid {
		t := lastUsed.Time
		k.LastUsedAt = &t
	}
	if revoked.Valid {
		t := revoked.Time
		k.RevokedAt = &t
	}
	return k, nil
}
