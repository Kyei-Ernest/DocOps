package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Kyei-Ernest/DocOps/models"
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
	// KEKParams / RecoveryKEKParams record the Argon2id cost parameters
	// ("m=..,t=..,p=..") used when each wrap was created. Key derivation must
	// reproduce the ORIGINAL parameters forever — deriving with newer live
	// config would produce a different KEK and permanently lose the data.
	// Empty string = legacy row created before this column existed; callers
	// fall back to current config for those.
	KEKParams         string
	RecoveryKEKParams string
	CreatedAt         time.Time
}

// FormatArgon2Params renders cost parameters in the compact form stored on user rows.
func FormatArgon2Params(p *models.Argon2Config) string {
	return fmt.Sprintf("m=%d,t=%d,p=%d", p.Memory, p.Iterations, p.Parallelism)
}

// ParseArgon2Params parses a value produced by FormatArgon2Params.
func ParseArgon2Params(s string) (*models.Argon2Config, error) {
	p := &models.Argon2Config{}
	if _, err := fmt.Sscanf(s, "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return nil, fmt.Errorf("parse argon2 params %q: %w", s, err)
	}
	return p, nil
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
	s.db.Exec("ALTER TABLE users ADD COLUMN kek_params TEXT")
	s.db.Exec("ALTER TABLE users ADD COLUMN recovery_kek_params TEXT")

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
			kek_params, recovery_kek_params,
			created_at
		)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, u.ID, u.Email, u.PasswordHash, u.Salt,
		u.WrappedMasterKey, u.MasterKeyNonce,
		u.RecoverySalt, u.RecoveryWrappedMasterKey, u.RecoveryMasterKeyNonce,
		u.KEKParams, u.RecoveryKEKParams,
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

const userColumns = `
	SELECT id, email, password_hash, salt,
	       wrapped_master_key, master_key_nonce,
	       recovery_salt, recovery_wrapped_master_key, recovery_master_key_nonce,
	       COALESCE(kek_params, '') AS kek_params,
	       COALESCE(recovery_kek_params, '') AS recovery_kek_params,
	       created_at
	FROM users
`

func scanUser(row *sql.Row) (*User, error) {
	u := &User{}
	err := row.Scan(
		&u.ID,
		&u.Email,
		&u.PasswordHash,
		&u.Salt,
		&u.WrappedMasterKey,
		&u.MasterKeyNonce,
		&u.RecoverySalt,
		&u.RecoveryWrappedMasterKey,
		&u.RecoveryMasterKeyNonce,
		&u.KEKParams,
		&u.RecoveryKEKParams,
		&u.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// GetByEmail looks up a user by their email address.
// Returns (nil, nil) if no matching user exists, so callers must check for a
// nil user before dereferencing — a non-nil error always indicates a database
// or scanning failure rather than a simple "not found" case.
func (s *UserStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userColumns+` WHERE email = ?`, email))
}

// GetByID looks up a user by their unique ID.
func (s *UserStore) GetByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userColumns+` WHERE id = ?`, id))
}

// UpdateUserKeys updates the password hash, salt, and wrapped master keys in the database.
func (s *UserStore) UpdateUserKeys(ctx context.Context, u *User) error {
	_, err := s.db.ExecContext(ctx, updateUserKeysSQL,
		u.PasswordHash, u.Salt, u.WrappedMasterKey, u.MasterKeyNonce,
		u.RecoverySalt, u.RecoveryWrappedMasterKey, u.RecoveryMasterKeyNonce,
		u.KEKParams, u.RecoveryKEKParams, u.ID)
	if err != nil {
		return fmt.Errorf("updateUserKeys: %w", err)
	}
	return nil
}

// UpdateUserKeysTx is UpdateUserKeys executed on an explicit transaction.
// It exists so flows that must mutate documents and user keys atomically
// (Master Key rotation, Argon2 parameter upgrades) can span both stores with
// one *sql.Tx on a shared connection pool.
func (s *UserStore) UpdateUserKeysTx(ctx context.Context, tx *sql.Tx, u *User) error {
	_, err := tx.ExecContext(ctx, updateUserKeysSQL,
		u.PasswordHash, u.Salt, u.WrappedMasterKey, u.MasterKeyNonce,
		u.RecoverySalt, u.RecoveryWrappedMasterKey, u.RecoveryMasterKeyNonce,
		u.KEKParams, u.RecoveryKEKParams, u.ID)
	if err != nil {
		return fmt.Errorf("updateUserKeysTx: %w", err)
	}
	return nil
}

const updateUserKeysSQL = `
	UPDATE users
	SET password_hash = ?, salt = ?, wrapped_master_key = ?, master_key_nonce = ?,
	    recovery_salt = ?, recovery_wrapped_master_key = ?, recovery_master_key_nonce = ?,
	    kek_params = ?, recovery_kek_params = ?
	WHERE id = ?
`
