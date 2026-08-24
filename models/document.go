// Package models defines DocOps' data transfer objects: documents, users'
// crypto material, storage DTOs, and the YAML configuration schema.
// Sensitive fields are marked json:"-" so accidental serialization can never
// leak key material; responses are additionally whitelisted field maps at the
// handler layer (defense in two layers).
package models

import "time"

type Document struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	Name          string     `json:"name"`
	FileType      string     `json:"file_type"`
	Provider      string     `json:"provider"`
	StorageKey    string     `json:"storage_key"`
	Encrypted     bool       `json:"encrypted"`
	SizeBytes     int64      `json:"size_bytes"`
	Tags          string     `json:"tags"` // comma separated, easy to query
	ExtractedText string     `json:"-"`    // indexed for search, never returned raw
	EncryptedDEK  []byte     `json:"-"`    // never exposed via API
	DEKNonce      []byte     `json:"-"`    // never exposed via API
	FileNonce     []byte     `json:"-"`    // never exposed via API
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}
