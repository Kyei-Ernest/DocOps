<p align="center">
  <h1 align="center">🔐 DocOps</h1>
  <p align="center">
    <strong>Self-hostable encrypted document storage API</strong>
  </p>
  <p align="center">
    Encrypt, upload, and search documents through a single API — backed by your own storage provider.
  </p>
  <p align="center">
    <a href="#quickstart"><strong>Quickstart</strong></a> ·
    <a href="#features"><strong>Features</strong></a> ·
    <a href="#api-reference"><strong>API</strong></a> ·
    <a href="#configuration"><strong>Config</strong></a> ·
    <a href="#contributing"><strong>Contributing</strong></a>
  </p>
</p>

<br/>

<p align="center">
  <img alt="Go Version" src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" />
  <img alt="Tests" src="https://img.shields.io/badge/Tests-140_passing-brightgreen?style=flat-square" />
  <img alt="Status" src="https://img.shields.io/badge/Status-Alpha-orange?style=flat-square" />
</p>

---

## Why DocOps?

Most document storage solutions force you to trust a third party with your plaintext files. DocOps takes a different approach: **your files are encrypted before they ever leave the server**, using keys derived from your password that are never persisted to disk.

- **Zero-knowledge encryption** — files are encrypted with per-document keys; the server never stores your master key
- **Bring your own storage** — local disk today, S3/GCS/Google Drive on the roadmap
- **Full-text search** — search across document names, tags, and extracted text via SQLite FTS5
- **Multi-tenant by default** — every query is scoped by user; document isolation is enforced at the database layer

> [!NOTE]
> DocOps is in **active development (alpha)**. The core encryption, auth, upload/download, and storage layers are built and tested. Cloud connectors and text extraction are coming next.

---

## Features

| Feature | Status | Description |
|:---|:---:|:---|
| 🔑 Envelope encryption | ✅ | Per-document AES-256-GCM keys, wrapped by a user-derived KEK |
| 🔒 Argon2id auth | ✅ | Password hashing + KEK derivation with independent salts |
| 🍪 JWT sessions | ✅ | HttpOnly/Secure cookies with access (15m) + refresh (7d) tokens |
| 🔍 Full-text search | ✅ | SQLite FTS5 with trigger-synced index |
| 📤 File upload | ✅ | Multipart upload with chunked streaming encryption (64 KB) |
| 📥 File download | ✅ | DEK unwrap + chunked streaming decryption to client |
| 💾 Local storage | ✅ | Filesystem connector with streaming I/O |
| ⚙️ YAML config | ✅ | Sensible defaults, `.env` for secrets |
| 🛡️ Auth middleware | ✅ | JWT → session → KEK resolution per request |
| 👥 Multi-tenant | ✅ | All operations scoped by `user_id` |
| 🗑️ File deletion | ✅ | Secure delete from both storage connector and metadata DB |
| 🛡️ Rate limiting | ✅ | IP-based sliding-window rate limiting on sensitive endpoints |
| ☁️ Cloud connectors | 🚧 | S3, GCS, Google Drive |
| 📝 Text extraction | 🚧 | PDF/DOCX content extraction for search indexing |

---

## Architecture

```mermaid
graph LR
    %% Custom styles for gorgeous look
    classDef client fill:#f1f5f9,stroke:#64748b,stroke-width:2px,color:#0f172a;
    classDef router fill:#e0e7ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b;
    classDef middleware fill:#fdf2f8,stroke:#db2777,stroke-width:2px,color:#500724;
    classDef handler fill:#faf5ff,stroke:#9333ea,stroke-width:2px,color:#3b0764;
    classDef service fill:#f0fdf4,stroke:#16a34a,stroke-width:2px,color:#14532d;
    classDef storage fill:#fff7ed,stroke:#ea580c,stroke-width:2px,color:#7c2d12;
    classDef inactive fill:#fafafa,stroke:#d4d4d8,stroke-width:1px,color:#71717a,stroke-dasharray: 5 5;

    %% Nodes
    Client([🌐 Web / HTTP Client])
    
    subgraph Routing ["1. Entry & Routing"]
        Mux["🛡️ Chi Router (main.go)"]
    end
    
    subgraph Auth_MW ["2. Authentication Middleware"]
        auth_mw["🔑 Auth Middleware<br/>(middleware/auth.go)"]
    end
    
    subgraph Handlers ["3. Controllers & Handlers (handlers/)"]
        auth_h["👤 Auth Handler<br/>(auth.go)"]
        upload_h["📤 Upload Handler<br/>(upload.go)"]
        download_h["📥 Download Handler<br/>(download.go)"]
        search_h["🔍 Search Handler<br/>(search.go)"]
        delete_h["🗑️ Delete Handler<br/>(delete.go)"]
    end
    
    subgraph Services ["4. Core Services (services/)"]
        auth_s["👥 Auth Service<br/>(User & Session Stores)"]
        crypto_s["🔒 Crypto Service<br/>(Argon2id & AES-GCM)"]
        meta_s["📝 Metadata Service<br/>(SQLite + FTS5)"]
    end
    
    subgraph Storage ["5. Storage Layer (connectors/)"]
        conn_local["💾 Local Storage<br/>(local/)"]
        conn_cloud["☁️ Cloud Storage<br/>(Planned Connectors)"]
    end

    %% Connections
    Client --> Mux
    
    %% Public Routes
    Mux -->|"/v0.1/auth/*"| auth_h
    
    %% Protected Routes
    Mux -->|"/v0.1/docs/*"| auth_mw
    auth_mw -->|Injects KEK & UserID| upload_h
    auth_mw -->|Injects KEK & UserID| download_h
    auth_mw -->|Injects KEK & UserID| search_h
    auth_mw -->|Injects KEK & UserID| delete_h
    
    %% Middleware resolving session
    auth_mw -.->|Resolves Token KEK| auth_s
    
    %% Handler service interactions
    auth_h -->|Register/Login/Session| auth_s
    auth_h -->|Derive KEK via Argon2id| crypto_s
    
    upload_h -->|1. Stream Encrypt| crypto_s
    upload_h -->|2. Write File| conn_local
    upload_h -->|3. Store Metadata| meta_s
    
    download_h -->|1. Fetch Metadata| meta_s
    download_h -->|2. Read File| conn_local
    download_h -->|3. Stream Decrypt| crypto_s
    
    search_h -->|Query SQLite FTS5| meta_s
    
    delete_h -->|1. Delete Metadata| meta_s
    delete_h -->|2. Delete File| conn_local

    %% Classes
    class Client client;
    class Mux router;
    class auth_mw middleware;
    class auth_h,upload_h,download_h,search_h,delete_h handler;
    class auth_s,crypto_s,meta_s service;
    class conn_local storage;
    class conn_cloud inactive;
```

---

## Security Model

DocOps uses **two-layer envelope encryption** so that compromising any single component does not expose plaintext documents:

```mermaid
graph TD
    subgraph Ephemeral_Memory ["💻 Ephemeral Server Memory (RAM)"]
        direction TB
        
        subgraph Key_Derivation ["1. Key Derivation (At Login)"]
            Pwd([🔑 User Password]) -->|Argon2id KDF| KEK[🔑 Key Encrypting Key - KEK]
        end

        subgraph Envelope_Encryption ["2. Envelope Encryption (At Upload)"]
            PlainFile[📄 Plaintext Document] -->|AES-256-GCM Chunked| EncEngine{⚙️ Crypto Engine}
            DEK[🔑 Random 256-bit DEK] -->|1. File Key| EncEngine
            
            KEK -->|2. Wrap Key| WrapEngine{⚙️ Key Wrapper}
            DEK -->|Plain DEK| WrapEngine
        end
        
        style Ephemeral_Memory fill:#f0fdf4,stroke:#16a34a,stroke-width:2px;
        style Key_Derivation fill:#ffffff,stroke:#86efac,stroke-width:1px;
        style Envelope_Encryption fill:#ffffff,stroke:#86efac,stroke-width:1px;
    end

    subgraph Persistent_Storage ["💾 Persistent Storage (Disk)"]
        direction LR
        
        DB[(📝 SQLite Metadata DB)]
        Disk[💾 File Storage / Disk]
        
        style Persistent_Storage fill:#fff7ed,stroke:#ea580c,stroke-width:2px;
        style DB fill:#ffffff,stroke:#ffedd5,stroke-width:1px;
        style Disk fill:#ffffff,stroke:#ffedd5,stroke-width:1px;
    end

    %% Flows from memory to disk
    WrapEngine -->|3. Encrypted DEK| DB
    EncEngine -->|4. Encrypted Content| Disk

    %% Custom styling definitions
    classDef key fill:#ecfdf5,stroke:#059669,stroke-width:1.5px,color:#065f46;
    classDef data fill:#f0f9ff,stroke:#0284c7,stroke-width:1.5px,color:#075985;
    classDef engine fill:#faf5ff,stroke:#7c3aed,stroke-width:1.5px,color:#581c87;

    class Pwd,KEK,DEK key;
    class PlainFile data;
    class EncEngine,WrapEngine engine;
```

| Property | Guarantee |
|:---|:---|
| **KEK storage** | Never written to disk — lives in server memory for session duration only |
| **DEK uniqueness** | Fresh 256-bit random key per document |
| **Nonce reuse** | Each encryption call generates a fresh random nonce |
| **Password hash vs KEK** | Independent Argon2id derivations with separate salts |
| **JWT contents** | Opaque session token only — no key material in the token |
| **Session revocation** | Server-side session store; logout invalidates immediately |
| **Timing attacks** | Constant-time comparison for password verification |

### Chunked Streaming Protocol

To ensure constant memory usage regardless of document size, DocOps processes all document uploads and downloads via a chunked streaming envelope encryption pipeline. Plaintext data is never held fully in memory or written to disk in its raw form:

```mermaid
sequenceDiagram
    autonumber
    actor Client as 🌐 HTTP Client
    participant H as 📤 Upload Handler
    participant C as 🔒 Crypto Service
    participant S as 💾 Storage Connector
    participant DB as 📝 Metadata Store

    Client->>H: 1. POST /v0.1/docs/upload (Multipart Stream)
    H->>C: 2. Generate random 256-bit DEK & IV
    H->>C: 3. Wrap DEK using KEK from Session Context
    C-->>H: Return Encrypted DEK
    
    rect rgb(240, 253, 244)
        note over H,S: Chunked Encryption Loop (Constant Memory)
        loop For each 64 KB chunk in multipart stream
            H->>H: Read 64 KB Plaintext
            H->>C: Encrypt 64 KB chunk using DEK + unique nonce
            C-->>H: Return Encrypted chunk
            H->>S: Stream-write Encrypted chunk to storage
        end
    end
    
    H->>DB: 4. Store Document Metadata (Encrypted DEK, size, tags, etc.)
    DB-->>H: Metadata stored successfully
    H-->>Client: 5. Return 201 Created (JSON metadata, sensitive fields omitted)
```

---

## Quickstart

### Prerequisites

- **Go 1.25+**
- **CGO enabled** (required by `go-sqlite3`)
- **SQLite with FTS5** support (included in most distributions)

### Install & Run (Bare Metal)

The fastest way to set up the project locally is to run the automated setup command. It will check your Go toolchain and C compiler (GCC/Clang), configure dependencies, and automatically generate a secure `.env` file with a cryptographically random `JWT_SECRET`:

```bash
# Clone
git clone https://github.com/Kyei-Ernest/DocOps.git
cd DocOps

# Run automated setup
make setup

# Build
make build

# Run
make run
```

The server starts on `http://localhost:8080` by default. **All storage and database parent directories (e.g. `docops-data/`) are automatically created on startup.** No manual directory initialization or config file is required — sensible defaults are applied automatically.

### Run with Docker & Docker Compose

If you prefer to run DocOps without installing a Go toolchain or C compilers, you can build and start it using Docker in a single command:

1. **Run setup to generate a secure `.env` file:**
   ```bash
   make setup
   ```
   *(Alternatively, manually create a `.env` file containing `JWT_SECRET=your-random-32-byte-secret`)*

2. **Start the service:**
   ```bash
   docker compose up --build -d
   ```

The application will start on `http://localhost:8080`. All SQLite databases and uploaded files are securely persisted within a dedicated Docker volume named `docops-data`.


### Run Tests

```bash
# All tests
go test -tags "fts5" -v ./...

# By package
make services_crypto_test       # 25 tests — encryption, hashing, KEK/DEK, streaming
make services_metadata_test     # 15 tests — document CRUD, FTS5 search, isolation
make handler_test               # 68 tests — auth, upload, download, search, delete, recovery
make services_auth_user_test    #  3 tests — user persistence
make services_auth_session_test #  9 tests — session lifecycle, expiry, active GC
make auth_middleware_test        # 13 tests — JWT validation, rate limiting, context injection
make local_connector_test        #  7 tests — filesystem upload, download, delete
```

---

## API Reference

### Authentication

| Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/v0.1/auth/register` | Create account — returns access + refresh cookies |
| `POST` | `/v0.1/auth/login` | Authenticate — returns access + refresh cookies |
| `POST` | `/v0.1/auth/refresh` | Exchange refresh cookie for new access cookie |
| `POST` | `/v0.1/auth/logout` | Revoke sessions and clear cookies |
| `POST` | `/v0.1/auth/recover` | Recover password using offline Recovery Key |
| `POST` | `/v0.1/auth/change-password` | Change password for authenticated users (protected) |
| `POST` | `/v0.1/auth/rotate-master-key` | Rotates the user's Master Key and re-encrypts all document keys (protected) |

### Documents

| Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/v0.1/docs/upload` | Upload encrypted document (multipart/form-data) |
| `GET`  | `/v0.1/docs/{docID}/download` | Download and decrypt a document (streaming) |
| `GET`  | `/v0.1/docs/search?q={query}` | Full-text search across document metadata |
| `DELETE`| `/v0.1/docs/{docID}` | Securely delete document metadata and storage file |

#### Upload Request

```bash
curl -X POST http://localhost:8080/v0.1/docs/upload \
  -b cookies.txt \
  -F "file=@document.pdf" \
  -F "tags=legal,2026"
```

#### Upload Response

```json
{
  "id": "doc_a1b2c3d4-...",
  "name": "document.pdf",
  "file_type": "application/pdf",
  "size_bytes": 104857,
  "encrypted": true,
  "tags": "legal,2026",
  "created_at": "2026-05-12T14:00:00Z"
}
```

#### Download Request

```bash
curl -X GET http://localhost:8080/v0.1/docs/doc_a1b2c3d4-.../download \
  -b cookies.txt \
  -o document.pdf
```

The response streams the decrypted file with appropriate `Content-Type` and `Content-Disposition` headers. Decryption happens in 64 KB chunks — memory usage is constant regardless of file size.

#### Search Request

```bash
curl -X GET "http://localhost:8080/v0.1/docs/search?q=quarterly" \
  -b cookies.txt
```

#### Search Response

```json
[
  {
    "id": "doc_a1b2c3d4-...",
    "name": "quarterly-report.pdf",
    "file_type": "application/pdf",
    "encrypted": true,
    "size_bytes": 104857,
    "tags": "finance,2026",
    "created_at": "2026-05-12T14:00:00Z",
    "expires_at": null
  }
]
```

Search matches against document names, tags, and extracted text via the FTS5 index. Results are scoped to the authenticated user — cross-tenant results are never returned. Sensitive internal fields (`storage_key`, `encrypted_dek`, `extracted_text`) are omitted from the response.

#### Delete Request

```bash
curl -X DELETE http://localhost:8080/v0.1/docs/doc_a1b2c3d4-... \
  -b cookies.txt
```

#### Delete Response

Returns a `204 No Content` status with an empty body upon successful deletion from both the database and physical storage connector.

> [!IMPORTANT]
> All document endpoints require authentication. The auth middleware injects the KEK and user ID from the server-side session — no key material is ever sent by the client.

---

## Configuration

DocOps loads configuration in order of precedence:

1. **`config.yaml`** — optional; defaults applied if absent
2. **Environment variables** — secrets only (never committed to YAML)
3. **`.env` file** — convenience for local development

### `config.yaml`

```yaml
server:
  port: 8080
  read_timeout:  "30s"
  write_timeout: "30s"

storage:
  local:
    path: "./docops-data/files"

auth:
  access_token_ttl:  "15m"    # short-lived access tokens
  refresh_token_ttl: "168h"   # 7-day refresh tokens

database:
  path: "./docops-data/docops.db"

argon2:
  memory:      65536   # 64 MiB
  iterations:  3
  parallelism: 2
  key_length:  32      # 256-bit keys
  salt_length: 16      # 128-bit salts
```

### Environment Variables

| Variable | Required | Description |
|:---|:---:|:---|
| `JWT_SECRET` | **Yes** | HMAC-SHA256 signing key for JWTs. Use ≥ 32 random bytes. |

---

## Project Structure

```
DocOps/
├── main.go                     # Entry point
├── config.yaml                 # Runtime configuration
├── Makefile                    # Build & test targets
│
├── config/
│   └── config.go               # YAML + env loader, defaults, path resolution
│
├── models/
│   ├── config.go               # Config, ServerConfig, AuthConfig, Argon2Config
│   ├── document.go             # Document model (with encryption metadata)
│   ├── crypto.go               # EncryptParams, DecryptParams
│   └── storage.go              # UploadRequest, FileRef
│
├── services/
│   ├── crypto/
│   │   ├── crypto.go           # Argon2id, AES-256-GCM, KEK/DEK, streaming encrypt/decrypt
│   │   └── crypto_test.go      # 25 tests
│   ├── auth/
│   │   ├── users.go            # SQLite-backed UserStore
│   │   ├── users_test.go       #  3 tests
│   │   ├── session.go          # In-memory SessionStore with lazy expiry
│   │   └── session_test.go     #  9 tests
│   └── metadata/
│       ├── store.go            # Document CRUD + FTS5 search (user-scoped)
│       └── store_test.go       # 15 tests
│
├── middleware/
│   ├── auth.go                 # JWT → session → context middleware
│   ├── auth_test.go            #  8 tests
│   ├── ratelimit.go            # IP-based sliding-window rate limiter middleware
│   └── ratelimit_test.go       #  5 tests
│
├── handlers/
│   ├── auth.go                 # Register, login, refresh, logout
│   ├── auth_test.go            # 14 tests
│   ├── recovery.go             # Password recovery, password changes, and Master Key rotation
│   ├── recovery_test.go        #  4 tests
│   ├── upload.go               # Encrypted file upload handler
│   ├── upload_test.go          # 12 tests — upload encryption, auth, edge cases
│   ├── download.go             # Streaming decrypt + download handler
│   ├── download_test.go        # 15 tests — decryption, auth, streaming, errors
│   ├── search.go               # Full-text search handler
│   ├── search_test.go          # 14 tests — FTS5 queries, isolation, field filtering
│   ├── delete.go               # Secure document delete handler
│   └── delete_test.go          #  9 tests — file deletion, auth, ownership verification
│
└── connectors/
    ├── connector.go            # StorageConnector interface
    └── local/
        ├── local.go            # Filesystem-backed connector
        └── local_test.go       #  7 tests
```

---

## Roadmap

- [x] File download handler with DEK decryption
- [x] Chunked streaming encryption/decryption (64 KB, constant memory)
- [x] Full-text search handler with FTS5 + sensitive field filtering
- [x] HTTP mux wiring and route registration
- [x] Secure file deletion (both connector and database layers)
- [x] Rate limiting middleware (IP-based sliding-window)
- [x] Docker image and Compose file
- [ ] Cloud storage connectors (S3, GCS, Google Drive)
- [ ] Text extraction (PDF, DOCX) for search indexing
- [ ] Document expiry and TTL enforcement
- [x] Structured logging (slog)
- [ ] OpenAPI specification

---

## Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create a branch** for your feature (`git checkout -b feat/my-feature`)
3. **Write tests** — the project maintains high test coverage by design
4. **Run the full suite** before submitting: `go test -tags "fts5" -v ./...`
5. **Open a Pull Request** with a clear description of your changes

### Development Notes

- CGO is required for SQLite — set `CGO_ENABLED=1`
- Use the `-tags "fts5"` build tag for all commands that touch the metadata store
- Secrets must come from the environment, never from config files
- All new database operations must include `user_id` scoping

---

## License

This project is licensed under the [MIT License](LICENSE).

---


