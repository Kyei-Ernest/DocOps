# DocOps

DocOps is a self-hostable Go API that handles encrypted file upload, download, and search — routing to your own cloud storage provider.

- **DocOps does not store your files** — they go to your provider (S3, Google Drive, etc.)
- **DocOps does not manage users or teams** — it is a developer API, not an end-user product
- **DocOps does not replace your storage provider** — you still need S3, GCS, or similar

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Handlers                       │
│          (HTTP glue — no business logic)          │
│   auth.go ── register, login, refresh, logout    │
├─────────────────────────────────────────────────┤
│                   Services                       │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │  crypto   │  │   auth   │  │   metadata    │  │
│  │          │  │          │  │               │  │
│  │ Argon2id │  │ UserStore│  │ SQLite + FTS5 │  │
│  │ AES-GCM  │  │ Sessions │  │ Document CRUD │  │
│  └──────────┘  └──────────┘  └───────────────┘  │
├─────────────────────────────────────────────────┤
│                    Models                        │
│       Document  ·  Argon2idParams  ·  User       │
├─────────────────────────────────────────────────┤
│              Connectors (planned)                │
│           S3  ·  GCS  ·  Google Drive            │
└─────────────────────────────────────────────────┘
```

## Encryption Model

DocOps uses a **two-layer envelope encryption** scheme:

1. **KEK (Key Encryption Key)** — derived from the user's password via Argon2id with a unique salt. Held only in memory for the session lifetime; never persisted.
2. **DEK (Data Encryption Key)** — a random 256-bit AES key generated per document. Encrypted under the KEK and stored alongside document metadata.
3. **Files** are encrypted with AES-256-GCM using the DEK before being sent to the storage provider.

The JWT carries only an opaque session token — the KEK never leaves the server's memory.

## What's Built

### `services/crypto`
- Argon2id password hashing (PHC format)
- Password verification with constant-time comparison
- KEK derivation (independent salt from password hash)
- AES-256-GCM encrypt / decrypt
- DEK generation
- Verification blob (sentinel-based KEK correctness check)

### `services/auth`
- `UserStore` — SQLite-backed user persistence with schema migration
- `SessionStore` — in-memory, goroutine-safe session store with lazy expiry

### `services/metadata`
- `Store` — SQLite-backed document CRUD with FTS5 full-text search
- Trigger-synced FTS index (auto insert/delete)
- Search by document name, tags, or extracted text

### `handlers`
- `AuthHandler` — register, login, token refresh, logout
- JWT (HMAC-SHA256) with HttpOnly/Secure/SameSite cookies
- Access token (15 min) + refresh token (7 days)

### Test Coverage
- **51 tests** across all packages
- Covers: round-trips, edge cases, security properties (user enumeration, nonce reuse, tamper detection, algorithm confusion)

## What's Next

- [ ] Nonce length validation in `Decrypt` (currently panics on malformed input)
- [ ] Set `User.ID` and `CreatedAt` in `Register` handler
- [ ] Auth middleware (JWT → session → KEK resolution)
- [ ] API route definitions and HTTP mux wiring
- [ ] Storage connectors (S3, GCS, Google Drive)
- [ ] File upload/download handlers with envelope encryption
- [ ] Configuration loading from `config.yaml`

## Getting Started

```bash
# Build
make build

# Run
make run

# Run all tests
go test -tags "fts5" -v ./...

# Individual test targets
make crypto_test
make store_test
make auth_user_test
make session_test
```

## Requirements

- Go 1.25+
- CGO enabled (required for `go-sqlite3`)
- SQLite with FTS5 support
