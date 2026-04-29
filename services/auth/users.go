package auth

import (
    "context"
    "database/sql"
    "time"

    _ "github.com/mattn/go-sqlite3"
)

type User struct {
    ID                 string
    Email              string
    PasswordHash       string
    Salt               []byte
    VerificationBlob   []byte
    VerificationNonce  []byte
    CreatedAt          time.Time
}

type UserStore struct {
    db *sql.DB
}

func NewUserStore(db *sql.DB) (*UserStore, error) {
    store := &UserStore{db: db}
    if err := store.migrate(); err != nil {
        return nil, err
    }
    return store, nil
}

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


func (s *UserStore) CreateUser(ctx context.Context, u *User) error {
    _, err := s.db.ExecContext(ctx, `
        INSERT INTO users (id, email, password_hash, salt, verification_blob, verification_nonce, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `, u.ID, u.Email, u.PasswordHash, u.Salt, u.VerificationBlob, u.VerificationNonce, u.CreatedAt)
    return err
}

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