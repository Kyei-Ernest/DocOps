package metadata

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Kyei-Ernest/DocOps/models"
	_ "github.com/mattn/go-sqlite3" // SQLite driver registered as a side effect
)

// Store wraps a SQLite database connection and exposes document CRUD + search operations.
type Store struct {
	db *sql.DB
}

// New opens (or creates) the SQLite database at dbPath, runs schema migrations,
// and returns a ready-to-use Store. Returns an error if the DB cannot be opened
// or the migration fails.
func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}

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
            id, name, file_type, provider, storage_key,
            encrypted, size_bytes, tags, extracted_text,
            encrypted_dek, dek_nonce, file_nonce,
            created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		doc.ID,
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

// GetByID fetches a single document by its primary key.
// Returns a "document not found" error (not sql.ErrNoRows) when no row matches,
// making callers independent of the database/sql package internals.
func (s *Store) GetByID(ctx context.Context, id string) (*models.Document, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT
            id, name, file_type, provider, storage_key,
            encrypted, size_bytes, tags, extracted_text,
            encrypted_dek, dek_nonce, file_nonce,
            created_at, expires_at
        FROM documents WHERE id = ?`, id)

	doc := &models.Document{}
	err := row.Scan(
		&doc.ID,
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
// Results are joined back to the documents table and ordered by relevance rank.
// Note: sensitive columns (extracted_text, encryption blobs) are intentionally
// omitted from search results to minimise exposure.
func (s *Store) Search(ctx context.Context, query string) ([]*models.Document, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT
            d.id, d.name, d.file_type, d.provider, d.storage_key,
            d.encrypted, d.size_bytes, d.tags, d.created_at, d.expires_at
        FROM documents d
        JOIN documents_fts fts ON d.id = fts.id
        WHERE documents_fts MATCH ?
        ORDER BY rank`, query)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}
	defer rows.Close()

	var results []*models.Document
	for rows.Next() {
		doc := &models.Document{}
		err := rows.Scan(
			&doc.ID,
			&doc.Name,
			&doc.FileType,
			&doc.Provider,
			&doc.StorageKey,
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

// Delete removes the document with the given ID from the database.
// The AFTER DELETE trigger (documents_ad) automatically purges the
// corresponding FTS index entry.
// Returns a "document not found" error when no row was affected.
func (s *Store) Delete(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM documents WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete document: %w", err)
	}

	// RowsAffected == 0 means the ID didn't exist; surface this as an error
	// so callers can distinguish a successful delete from a no-op.
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("document not found: %s", id)
	}
	return nil
}

// Close gracefully shuts down the underlying database connection.
// Should be deferred immediately after a successful call to New.
func (s *Store) Close() error {
	return s.db.Close()
}