package connectors

import (
	"io"
	"context"
	"github.com/Kyei-Ernest/DocOps/models"
)


type StorageConnector interface {
    Upload(ctx context.Context, r models.UploadRequest) (models.FileRef, error)
    Download(ctx context.Context, key string) (io.ReadCloser, error)
    Delete(ctx context.Context, key string) error
    Ping(ctx context.Context) error
}