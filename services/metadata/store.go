// Package metadata owns the documents table: CRUD scoped by owner in SQL,
// an FTS5 external-content search index kept coherent by insert/delete
// triggers, shared-pool transactions (InTx) for multi-row mutations such as
// atomic key rotation, and TTL sweep helpers.
package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Kyei-Ernest/DocOps/models"
	_ "github.com/mattn/go-sqlite3" // SQLite driver registered as a side effect
)

// Store wraps a SQLite database connection and exposes document CRUD + search operations.
type Store struct {
	db     *sql.DB
	ownsDB bool // true when this Store opened its own connection (New); false for NewDB
}

// New opens (or creates) the SQLite database at dbPath, runs schema migrations,
// and returns a ready-to-use Store. Returns an error if the DB cannot be opened
// or the migration fails.
//
// Prefer NewDB when the application already holds a shared *sql.DB (as main.go
// does): a single pool lets transactions span the users and documents tables,
// which is what makes Master Key rotation atomic (ROADMAP P0-2).
func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}
	return &Store{db: db, ownsDB: true}, nil
}

// NewDB constructs a Store on top of an existing, caller-owned *sql.DB and runs
// schema migrations on it. The Store does NOT own the connection: Close is a
// no-op and lifecycle remains the caller's responsibility.
//
// Sharing one pool across stores is what allows a single *sql.Tx to cover
// both document and user-table writes — the mechanism behind atomic rotation.
func NewDB(db *sql.DB) (*Store, error) {
	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}
	return &Store{db: db}, nil
}

// migrate creates the core schema if it doesn't already exist:
//   - documents        – the primary record store
//   - documents_fts    – FTS5 virtual table for full-text search
//   - documents_ai     – AFTER INSERT trigger to keep the FTS index in sync
//   - documents_ad     – AFTER DELETE trigger to remove stale FTS entries
//
// All statements use IF NOT EXISTS / IF NOT EXISTS-equivalent guards so
// migrate is safe to call on an already-initialised database.
func migrate(db *sql.DB) error {
	// Primary table: one row per document, including encryption metadata
	// (encrypted_dek, dek_nonce, file_nonce) stored as BLOBs.
	_, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS documents (
            id             TEXT PRIMARY KEY,
            user_id        TEXT NOT NULL,   -- owner; every query must filter on this
            name           TEXT NOT NULL,
            file_type      TEXT,
            provider       TEXT NOT NULL,   -- storage backend (e.g. "s3", "gcs")
            storage_key    TEXT NOT NULL,   -- opaque key/path used by the provider
            encrypted      INTEGER DEFAULT 1,
            size_bytes     INTEGER,
            tags           TEXT,            -- comma-separated or JSON tags
            extracted_text TEXT,            -- plain-text content for full-text search
            encrypted_dek  BLOB,            -- encrypted data-encryption key
            dek_nonce      BLOB,            -- nonce used when encrypting the DEK
            file_nonce     BLOB,            -- nonce used when encrypting the file
            created_at     DATETIME NOT NULL,
            expires_at     DATETIME         -- NULL means the document never expires
        );
    `)
	if err != nil {
		return err
	}

	// FTS5 virtual table: mirrors the text columns we want to search.
	// content='documents' makes this a "content table" FTS index — SQLite
	// stores only the index, not a second copy of the text.
	// content_rowid='rowid' links FTS rows back to the base table.
	_, err = db.Exec(`
        CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts
        USING fts5(
            id,
            name,
            tags,
            extracted_text,
            content='documents',
            content_rowid='rowid'
        );
    `)
	if err != nil {
		return err
	}

	// AFTER INSERT trigger: whenever a new document is inserted,
	// add the corresponding entry to the FTS index so it is immediately searchable.
	_, err = db.Exec(`
        CREATE TRIGGER IF NOT EXISTS documents_ai
        AFTER INSERT ON documents BEGIN
            INSERT INTO documents_fts(rowid, id, name, tags, extracted_text)
            VALUES (new.rowid, new.id, new.name, new.tags, new.extracted_text);
        END;
    `)
	if err != nil {
		return err
	}

	// AFTER DELETE trigger: uses the special FTS5 'delete' command to remove
	// the stale entry from the index, keeping it consistent with the base table.
	_, err = db.Exec(`
        CREATE TRIGGER IF NOT EXISTS documents_ad
        AFTER DELETE ON documents BEGIN
            INSERT INTO documents_fts(documents_fts, rowid, id, name, tags, extracted_text)
            VALUES ('delete', old.rowid, old.id, old.name, old.tags, old.extracted_text);
        END;
    `)
	return err
}

// Save inserts a new document record into the database.
// It returns an error if a document with the same ID already exists or if
// the insert otherwise fails.
func (s *Store) Save(ctx context.Context, doc *models.Document) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO documents (
            id, user_id, name, file_type, provider, storage_key,
            encrypted, size_bytes, tags, extracted_text,
            encrypted_dek, dek_nonce, file_nonce,
            created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		doc.ID,
		doc.UserID,
		doc.Name,
		doc.FileType,
		doc.Provider,
		doc.StorageKey,
		doc.Encrypted,
		doc.SizeBytes,
		doc.Tags,
		doc.ExtractedText,
		doc.EncryptedDEK,
		doc.DEKNonce,
		doc.FileNonce,
		doc.CreatedAt,
		doc.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save document: %w", err)
	}
	return nil
}

// GetByID fetches a single document by its primary key, scoped to the given user.
// Returns a "document not found" error (not sql.ErrNoRows) when no row matches,
// making callers independent of the database/sql package internals.
// The userID filter ensures a user can never access another user's document.
func (s *Store) GetByID(ctx context.Context, id, userID string) (*models.Document, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT
            id, user_id, name, file_type, provider, storage_key,
            encrypted, size_bytes, tags, extracted_text,
            encrypted_dek, dek_nonce, file_nonce,
            created_at, expires_at
        FROM documents WHERE id = ? AND user_id = ?`, id, userID)

	doc := &models.Document{}
	err := row.Scan(
		&doc.ID,
		&doc.UserID,
		&doc.Name,
		&doc.FileType,
		&doc.Provider,
		&doc.StorageKey,
		&doc.Encrypted,
		&doc.SizeBytes,
		&doc.Tags,
		&doc.ExtractedText,
		&doc.EncryptedDEK,
		&doc.DEKNonce,
		&doc.FileNonce,
		&doc.CreatedAt,
		&doc.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("document not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get document: %w", err)
	}
	return doc, nil
}

// Search performs a full-text search against the FTS5 index using the provided
// query string (supports FTS5 match syntax, e.g. "invoice AND 2024").
// Results are joined back to the documents table, filtered by userID, and
// ordered by relevance rank.
// Note: sensitive columns (extracted_text, encryption blobs) are intentionally
// omitted from search results to minimise exposure.
func (s *Store) Search(ctx context.Context, userID, query string) ([]*models.Document, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT
            d.id, d.user_id, d.name, d.file_type,
            d.encrypted, d.size_bytes, d.tags,
            d.created_at, d.expires_at
        FROM documents d
        JOIN documents_fts fts ON d.id = fts.id
        WHERE documents_fts MATCH ? AND d.user_id = ?
        ORDER BY rank`, query, userID)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}
	defer rows.Close()

	var results []*models.Document
	for rows.Next() {
		doc := &models.Document{}
		err := rows.Scan(
			&doc.ID,
			&doc.UserID,
			&doc.Name,
			&doc.FileType,
			&doc.Encrypted,
			&doc.SizeBytes,
			&doc.Tags,
			&doc.CreatedAt,
			&doc.ExpiresAt,
		)
		if err != nil {
			return nil, err
		}
		results = append(results, doc)
	}
	return results, nil
}

// Delete removes the document with the given ID from the database, scoped to
// the given user. The AFTER DELETE trigger (documents_ad) automatically purges
// the corresponding FTS index entry.
// Returns a "document not found" error when no row was affected — this covers
// both genuinely missing documents and attempts to delete another user's document.
func (s *Store) Delete(ctx context.Context, id, userID string) error {
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM documents WHERE id = ? AND user_id = ?", id, userID)
	if err != nil {
		return fmt.Errorf("failed to delete document: %w", err)
	}

	// RowsAffected == 0 means the ID didn't exist or belongs to another user;
	// surface this as an error so callers can return 404.
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("document not found: %s", id)
	}
	return nil
}

// Close gracefully shuts down the underlying database connection.
// Should be deferred immediately after a successful call to New.
// When the Store was built over a caller-owned pool (NewDB), this is a no-op —
// the caller owns the connection's lifecycle.
func (s *Store) Close() error {
	if !s.ownsDB {
		return nil
	}
	return s.db.Close()
}

// InTx runs fn inside a single SQLite transaction on this store's connection
// pool. Any error returned by fn rolls the transaction back completely; a nil
// error commits. This is the primitive that makes multi-row mutations (e.g.
// Master Key rotation spanning every wrapped DEK plus the user key row)
// all-or-nothing instead of best-effort.
//
// Note: the default deferred BEGIN acquires its write lock at first write.
// Under heavy concurrent writers SQLite may surface SQLITE_BUSY; v0.x accepts
// this for a single-process deployment rather than forcing IMMEDIATE globally.
func (s *Store) InTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			// Commit/rollback already finalized (e.g. ctx cancelled mid-tx);
			// surface both so operators see the full picture.
			return fmt.Errorf("tx failed: %v (rollback also failed: %w)", err, rbErr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ListAllForUser retrieves all documents belonging to a specific user,
// including their key wrapping metadata (encrypted_dek, dek_nonce, file_nonce).
// Used during Master Key rotation.
func (s *Store) ListAllForUser(ctx context.Context, userID string) ([]*models.Document, error) {
	return listAllForUser(ctx, s.db.QueryContext, userID)
}

// ListAllForUserTx is ListAllForUser executed on an explicit transaction.
func (s *Store) ListAllForUserTx(ctx context.Context, tx *sql.Tx, userID string) ([]*models.Document, error) {
	return listAllForUser(ctx, tx.QueryContext, userID)
}

// queryContext abstracts over *sql.DB and *sql.Tx so the scan logic below is
// written exactly once for both the autocommit and transactional paths.
type queryContextFn func(ctx context.Context, query string, args ...any) (*sql.Rows, error)

func listAllForUser(ctx context.Context, q queryContextFn, userID string) ([]*models.Document, error) {
	rows, err := q(ctx, `
		SELECT
			id, user_id, name, file_type, provider, storage_key,
			encrypted, size_bytes, tags, extracted_text,
			encrypted_dek, dek_nonce, file_nonce,
			created_at, expires_at
		FROM documents WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("list all for user: %w", err)
	}
	defer rows.Close()

	var results []*models.Document
	for rows.Next() {
		doc := &models.Document{}
		err := rows.Scan(
			&doc.ID,
			&doc.UserID,
			&doc.Name,
			&doc.FileType,
			&doc.Provider,
			&doc.StorageKey,
			&doc.Encrypted,
			&doc.SizeBytes,
			&doc.Tags,
			&doc.ExtractedText,
			&doc.EncryptedDEK,
			&doc.DEKNonce,
			&doc.FileNonce,
			&doc.CreatedAt,
			&doc.ExpiresAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan document: %w", err)
		}
		results = append(results, doc)
	}
	return results, rows.Err()
}

// UpdateDEK updates the wrapped DEK and its nonce for a specific document.
// Used during Master Key rotation.
func (s *Store) UpdateDEK(ctx context.Context, docID, userID string, encryptedDEK, dekNonce []byte) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE documents
		SET encrypted_dek = ?, dek_nonce = ?
		WHERE id = ? AND user_id = ?`, encryptedDEK, dekNonce, docID, userID)
	if err != nil {
		return fmt.Errorf("update DEK: %w", err)
	}
	return nil
}

// ExpiredStorageKeys lists storage keys whose documents have passed their
// expires_at timestamp. Callers delete the underlying objects first, then call
// DeleteExpiredRows — file-before-row ordering means a mid-sweep failure leaves
// a recoverable orphaned row rather than a row pointing at nothing.
func (s *Store) ExpiredStorageKeys(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT storage_key FROM documents WHERE expires_at IS NOT NULL AND expires_at < ?`, now)
	if err != nil {
		return nil, fmt.Errorf("expired storage keys: %w", err)
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("scan storage key: %w", err)
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// DeleteExpiredRows removes every expired document row (and, via trigger, its
// FTS entry). Returns the number of rows removed.
func (s *Store) DeleteExpiredRows(ctx context.Context, now time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM documents WHERE expires_at IS NOT NULL AND expires_at < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("delete expired rows: %w", err)
	}
	n, _ := result.RowsAffected()
	return n, nil
}

// UpdateDEKTx is UpdateDEK executed on an explicit transaction.
func (s *Store) UpdateDEKTx(ctx context.Context, tx *sql.Tx, docID, userID string, encryptedDEK, dekNonce []byte) error {
	result, err := tx.ExecContext(ctx, `
		UPDATE documents
		SET encrypted_dek = ?, dek_nonce = ?
		WHERE id = ? AND user_id = ?`, encryptedDEK, dekNonce, docID, userID)
	if err != nil {
		return fmt.Errorf("update DEK: %w", err)
	}
	// Within rotation a zero-row update means the corpus shifted underneath
	// us (deleted mid-rotation). Treat as an error so the caller rolls back
	// rather than silently skipping a re-wrap.
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("update DEK: document %s not found for user", docID)
	}
	return nil
}
