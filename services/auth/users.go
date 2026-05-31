package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/mattn/go-sqlite3"
	_ "github.com/mattn/go-sqlite3"
)

// User represents an authenticated user in the system.
type User struct {
	ID                       string
	Email                    string
	PasswordHash             string
	Salt                     []byte
	WrappedMasterKey         []byte // Master Key wrapped with password KEK
	MasterKeyNonce           []byte
	RecoverySalt             []byte // Salt for recovery KEK derivation
	RecoveryWrappedMasterKey []byte // Master Key wrapped with recovery KEK
	RecoveryMasterKeyNonce   []byte
	CreatedAt                time.Time
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
			id                            TEXT PRIMARY KEY,
			email                         TEXT UNIQUE NOT NULL,
			password_hash                 TEXT NOT NULL,
		  	salt                          BLOB NOT NULL,
			wrapped_master_key            BLOB,
			master_key_nonce              BLOB,
			recovery_salt                 BLOB,
			recovery_wrapped_master_key   BLOB,
			recovery_master_key_nonce     BLOB,
			created_at                    DATETIME NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	// For backward compatibility, if the table already existed without the new columns,
	// we alter the table to add them. We ignore errors if the columns already exist.
	s.db.Exec("ALTER TABLE users ADD COLUMN wrapped_master_key BLOB")
	s.db.Exec("ALTER TABLE users ADD COLUMN master_key_nonce BLOB")
	s.db.Exec("ALTER TABLE users ADD COLUMN recovery_salt BLOB")
	s.db.Exec("ALTER TABLE users ADD COLUMN recovery_wrapped_master_key BLOB")
	s.db.Exec("ALTER TABLE users ADD COLUMN recovery_master_key_nonce BLOB")

	return nil
}

var ErrDuplicateEmail = errors.New("email already registered")

// CreateUser inserts a new user record into the database.
// Returns an error if the email is already taken (UNIQUE constraint) or if
// the insert fails for any other reason.
func (s *UserStore) CreateUser(ctx context.Context, u *User) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO users (
			id, email, password_hash, salt, 
			wrapped_master_key, master_key_nonce, 
			recovery_salt, recovery_wrapped_master_key, recovery_master_key_nonce, 
			created_at
		)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, u.ID, u.Email, u.PasswordHash, u.Salt,
		u.WrappedMasterKey, u.MasterKeyNonce,
		u.RecoverySalt, u.RecoveryWrappedMasterKey, u.RecoveryMasterKeyNonce,
		u.CreatedAt)

	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return fmt.Errorf("createUser: %w", ErrDuplicateEmail)
		}
		return fmt.Errorf("createUser: %w", err)
	}

	return nil
}

// GetByEmail looks up a user by their email address.
// Returns (nil, nil) if no matching user exists, so callers must check for a
// nil user before dereferencing — a non-nil error always indicates a database
// or scanning failure rather than a simple "not found" case.
func (s *UserStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, password_hash, salt, 
		       wrapped_master_key, master_key_nonce, 
		       recovery_salt, recovery_wrapped_master_key, recovery_master_key_nonce, 
		       created_at
		FROM users WHERE email = ?
	`, email).Scan(
		&u.ID,
		&u.Email,
		&u.PasswordHash,
		&u.Salt,
		&u.WrappedMasterKey,
		&u.MasterKeyNonce,
		&u.RecoverySalt,
		&u.RecoveryWrappedMasterKey,
		&u.RecoveryMasterKeyNonce,
		&u.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// GetByID looks up a user by their unique ID.
func (s *UserStore) GetByID(ctx context.Context, id string) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, password_hash, salt, 
		       wrapped_master_key, master_key_nonce, 
		       recovery_salt, recovery_wrapped_master_key, recovery_master_key_nonce, 
		       created_at
		FROM users WHERE id = ?
	`, id).Scan(
		&u.ID,
		&u.Email,
		&u.PasswordHash,
		&u.Salt,
		&u.WrappedMasterKey,
		&u.MasterKeyNonce,
		&u.RecoverySalt,
		&u.RecoveryWrappedMasterKey,
		&u.RecoveryMasterKeyNonce,
		&u.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// UpdateUserKeys updates the password hash, salt, and wrapped master keys in the database.
func (s *UserStore) UpdateUserKeys(ctx context.Context, u *User) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users 
		SET password_hash = ?, salt = ?, wrapped_master_key = ?, master_key_nonce = ?,
		    recovery_salt = ?, recovery_wrapped_master_key = ?, recovery_master_key_nonce = ?
		WHERE id = ?
	`, u.PasswordHash, u.Salt, u.WrappedMasterKey, u.MasterKeyNonce,
		u.RecoverySalt, u.RecoveryWrappedMasterKey, u.RecoveryMasterKeyNonce, u.ID)
	if err != nil {
		return fmt.Errorf("updateUserKeys: %w", err)
	}
	return nil
}
