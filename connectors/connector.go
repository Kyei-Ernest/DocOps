// Package connectors defines the storage backend abstraction: every document
// byte passes through a StorageConnector, so new backends (S3, GCS) slot in
// without touching handler or crypto code.
package connectors

import (
	"context"
	"github.com/Kyei-Ernest/DocOps/models"
	"io"
)

type StorageConnector interface {
	Upload(ctx context.Context, r models.UploadRequest) (models.FileRef, error)
	Download(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
	Ping(ctx context.Context) error
}
