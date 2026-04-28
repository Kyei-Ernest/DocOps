// services/metadata/store.go
package metadata

import (
    "context"
    "database/sql"
    "fmt"

    "github.com/Kyei-Ernest/DocOps/models"
    _ "github.com/mattn/go-sqlite3"
)

type Store struct {
    db *sql.DB
}

// New opens the SQLite DB and creates tables if they don't exist
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

func migrate(db *sql.DB) error {
    // main documents table
    _, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS documents (
            id             TEXT PRIMARY KEY,
            name           TEXT NOT NULL,
            file_type      TEXT,
            provider       TEXT NOT NULL,
            storage_key    TEXT NOT NULL,
            encrypted      INTEGER DEFAULT 1,
            size_bytes     INTEGER,
            tags           TEXT,
            extracted_text TEXT,
            encrypted_dek  BLOB,
            dek_nonce      BLOB,
            file_nonce     BLOB,
            created_at     DATETIME NOT NULL,
            expires_at     DATETIME
        );
    `)
    if err != nil {
        return err
    }

    // FTS5 virtual table for full text search
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

    // trigger to keep FTS index in sync on insert
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

    // trigger to keep FTS index in sync on delete
    _, err = db.Exec(`
        CREATE TRIGGER IF NOT EXISTS documents_ad
        AFTER DELETE ON documents BEGIN
            INSERT INTO documents_fts(documents_fts, rowid, id, name, tags, extracted_text)
            VALUES ('delete', old.rowid, old.id, old.name, old.tags, old.extracted_text);
        END;
    `)
    return err
}

// Save inserts a new document record
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

// GetByID fetches a single document by its ID
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

// Search queries the FTS5 index and returns matching documents
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

// Delete removes a document record by ID
func (s *Store) Delete(ctx context.Context, id string) error {
    result, err := s.db.ExecContext(ctx,
        "DELETE FROM documents WHERE id = ?", id)
    if err != nil {
        return fmt.Errorf("failed to delete document: %w", err)
    }

    rows, _ := result.RowsAffected()
    if rows == 0 {
        return fmt.Errorf("document not found: %s", id)
    }
    return nil
}

// Close shuts down the DB connection cleanly
func (s *Store) Close() error {
    return s.db.Close()
}