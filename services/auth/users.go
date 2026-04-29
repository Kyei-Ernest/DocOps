package auth

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// User represents an authenticated user in the system.
// VerificationBlob and VerificationNonce store the encrypted TOTP/verification
// secret and its AES-GCM nonce respectively, allowing server-side decryption
// during the verification step without exposing the plaintext secret at rest.
type User struct {
	ID                string
	Email             string
	PasswordHash      string
	Salt              []byte
	VerificationBlob  []byte // AES-GCM ciphertext of the verification secret
	VerificationNonce []byte // Nonce used when encrypting VerificationBlob
	CreatedAt         time.Time
}

// UserStore wraps a SQLite database and provides user persistence operations.
type UserStore struct {
	db *sql.DB
}

// NewUserStore creates a UserStore backed by the given database connection and
// runs any pending schema migrations. Returns an error if migration fails.
func NewUserStore(db *sql.DB) (*UserStore, error) {
	store := &UserStore{db: db}
	if err := store.migrate(); err != nil {
		return nil, err
	}
	return store, nil
}

// migrate ensures the users table exists with the expected schema.
// It is safe to call on an already-migrated database (IF NOT EXISTS).
func (s *UserStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id                  TEXT PRIMARY KEY,
			email               TEXT UNIQUE NOT NULL,
			password_hash       TEXT NOT NULL,
			salt                BLOB NOT NULL,
			verification_blob   BLOB NOT NULL,
			verification_nonce  BLOB NOT NULL,
			created_at          DATETIME NOT NULL
		)
	`)
	return err
}

// CreateUser inserts a new user record into the database.
// Returns an error if the email is already taken (UNIQUE constraint) or if
// the insert fails for any other reason.
func (s *UserStore) CreateUser(ctx context.Context, u *User) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, email, password_hash, salt, verification_blob, verification_nonce, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, u.ID, u.Email, u.PasswordHash, u.Salt, u.VerificationBlob, u.VerificationNonce, u.CreatedAt)
	return err
}

// GetByEmail looks up a user by their email address.
// Returns (nil, nil) if no matching user exists, so callers must check for a
// nil user before dereferencing — a non-nil error always indicates a database
// or scanning failure rather than a simple "not found" case.
func (s *UserStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, password_hash, salt, verification_blob, verification_nonce, created_at
		FROM users WHERE email = ?
	`, email).Scan(
		&u.ID,
		&u.Email,
		&u.PasswordHash,
		&u.Salt,
		&u.VerificationBlob,
		&u.VerificationNonce,
		&u.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}