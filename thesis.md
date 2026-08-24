# DocOps: A Self-Hostable, Searchable, Zero-Knowledge Document Storage API

**An Engineering Thesis on Applied Cryptographic Architecture in Go**

*Ernest Kyei · DocOps v0.1-alpha · August 2026*

---

## Abstract

Cloud document storage offers search and durability at the cost of privacy: the provider
can read everything. Local encrypted vaults (VeraCrypt, Cryptomator) offer privacy but
treat documents as opaque blobs — no search, no API, no multi-user access. This thesis
presents DocOps, a self-hostable document storage API that resolves this dichotomy by
combining envelope encryption with server-side full-text search, exposed as a plain HTTP
interface. Every document is encrypted under a unique 256-bit data key; data keys are
wrapped by a master key that exists only in process memory, re-derived from the user's
password via Argon2id at each login. Files are encrypted and decrypted as chunked
AES-256-GCM streams with constant 64 KiB memory overhead regardless of file size.

The central architectural claims are examined in depth: that domain-separated key
derivation prevents cross-protocol key linkage; that keys which never persist cannot be
stolen at rest; that AEAD authentication provides implicit verification of derived keys;
and that structural guarantees (keys confined to server memory, ownership scoped in SQL)
outperform convention-based security. We present an honest threat model that qualifies
the zero-knowledge claim — content is never readable at rest, metadata is — and enumerate
known gaps without embellishment. The implementation comprises approximately 170 tests
across seven packages, clean under Go's race detector, and ships that extension: a
stateless machine-credential tier (`docops_sk_…` bearer keys whose 256-bit secrets are
wrapped via HKDF — the entropy-appropriate counterpart to Argon2id for human passwords)
alongside atomic key rotation and AAD-bound wraps.

---

## Contents

1. [Introduction](#1-introduction)
2. [Background and Related Work](#2-background-and-related-work)
3. [System Architecture](#3-system-architecture)
4. [Cryptographic Design](#4-cryptographic-design)
5. [Authentication and Authorization](#5-authentication-and-authorization)
6. [Implementation Concerns in Go](#6-implementation-concerns-in-go)
7. [Data Flow Walkthrough](#7-data-flow-walkthrough)
8. [Testing Methodology](#8-testing-methodology)
9. [Threat Model and Limitations](#9-threat-model-and-limitations)
10. [Future Work](#10-future-work)
11. [Conclusion](#11-conclusion)
12. [References](#12-references)

---

## 1. Introduction

### 1.1 The Searchable Privacy Paradox

A developer building an application that handles sensitive user documents — identity
verification files, medical records, contracts, HR paperwork — faces an unappealing menu.
Managed object stores (S3 and peers) provide durability, APIs, and server-side search,
but read plaintext by default; server-side encryption keys belong to the provider.
Encrypted vaults protect content, but expose no API and cannot answer "find the contract
signed in March." Self-hosting does not change the calculus: a self-hosted Nextcloud or
MinIO still reads what it stores.

DocOps occupies the missing middle. It is a single deployable service — one container,
one SQLite file, one storage directory — such that:

1. **Content is never readable at rest.** Ciphertext is all that reaches disk; every
   byte is under AES-256-GCM with per-document keys.
2. **Search still works.** Names, tags, and extracted text are indexed in SQLite FTS5
   and scoped per user.
3. **Keys are structurally unreachable.** The root key material exists only in process
   RAM during active sessions, re-derived from passwords each login; it appears in no
   table, no file, no token.
4. **It is boring to integrate.** Plain HTTP, cookie sessions for humans, bearer keys
   for machines (roadmap), generated SDKs planned.

Point 3 deserves emphasis because it is the design's load-bearing wall: most "encrypted"
systems encrypt *with keys stored somewhere nearby*, which converts a database compromise
into a total content compromise. DocOps accepts real costs to avoid this (Section 4.2).

### 1.2 Scope and Contributions

This thesis describes v0.1-alpha: a single-node Go service backed by SQLite (with FTS5)
and a filesystem storage connector, ~170 tests passing under `-race`. Its contributions
are not novel primitives — Argon2id, GCM, and envelope encryption are established — but
their correct assembly under constraints that hobby projects routinely get wrong:

- Domain-separated key derivation across three independent salt domains (Section 4.1).
- Streaming AEAD with counter-derived per-chunk nonces at constant memory (Section 4.4).
- Implicit key-correctness verification via GCM authentication, replacing a sentinel-blob
  protocol that the original design intended explicitly (Section 4.3).
- An honest threat model, including the ways the system is *not* zero-knowledge and the
  defects knowingly shipped in v0.1 (Section 9).
- A deliberate evolution path from human-password roots to high-entropy machine roots
  (Section 10).

### 1.3 Method Note

Design rationale throughout was recorded as first-person engineering notes at project
inception (`docs/thesis-notes.md`) and is reconciled here against the code as actually
built, with drift marked where implementation and intent diverged. All claims carry
`file:line` anchors into the v0.1 source.

---

## 2. Background and Related Work

### 2.1 Envelope Encryption

Envelope encryption is the now-standard pattern for encrypting many objects under
manageable key material [9]: each object is encrypted under its own randomly generated
data encryption key (DEK), and DEKs are in turn encrypted ("wrapped") under a slower-to-
access key encryption key (KEK). Two properties motivate the indirection. First, blast
radius: a compromised wrapping key exposes wrapped DEKs rather than plaintext, and
compromise of any single DEK exposes exactly one object. Second, rotation economics:
rotating the KEK requires re-wrapping kilobytes of DEKs, not re-encrypting gigabytes of
documents. AWS KMS operationalized the pattern at scale; NIST SP 800-57 formalizes the
key-hierarchy discipline it embodies [10]. DocOps applies it with three tiers
(Section 3.2) so that password changes touch only wraps, and master-key rotation touches
only DEK wraps — documents themselves are immutable ciphertext until deleted.

### 2.2 Password Hashing and Memory Hardness

Passwords are low-entropy secrets and must be verified through deliberately expensive
functions. Argon2id [1], winner of the Password Hashing Competition, couples
side-channel-resistant data-independent passes with attack-amplifying data-dependent
passes; its memory-hardness makes GPU/ASIC parallelization costly in proportion to memory
budget. DocOps uses Argon2id exclusively (`golang.org/x/crypto/argon2`), defaults of
m=65536 KiB, t=3, p=2 with 32-byte outputs (`config/config.go` defaults), and emits the
PHC string format [8] — `$argon2id$v=19$m=…,t=…,p=…$salt$hash` — whose self-describing
property means verification reconstructs parameters from the string itself
(`services/crypto/crypto.go:75-131`). This choice has a subtle payoff exploited in
Section 4: hashes remain verifiable across parameter upgrades, enabling lazy rehashing.

### 2.3 AEAD and Nonce Discipline

AES-GCM [2] provides confidentiality and integrity in one primitive, but its guarantees
hold only under a hard rule: a (key, nonce) pair must never repeat. Reuse leaks the XOR
of paired plaintexts and, worse, enables universal tag forgery — both confidentiality and
authenticity collapse catastrophically (Section 4.4). Random 96-bit nonces from a CSPRNG
keep collision probability negligible within per-key operation budgets [2]. For large
artifacts, record-framed AEAD — encrypting fixed-size chunks each under a nonce derived
deterministically from a base nonce plus counter — is the established shape: TLS 1.3
records work this way [6], as does the `age` file format [12]. DocOps adopts this shape
for files (64 KiB chunks, Section 4.4) and simple single-shot sealing for keys.

### 2.4 Authentication: JWTs versus Server Sessions

JWTs [4] trade statelessness against revocation and payload exposure: a signed token is
honored anywhere until expiry, and whatever it carries travels through every proxy, log
pipeline, and client-side script store along its path. Opaque server-side sessions invert
the trade: lookup cost per request, instant revocation, and nothing sensitive on the wire.
DocOps hybridizes — a short-lived HS256 JWT carries *only* an opaque random session token
(`handlers/auth.go:35-38`), which indexes into a RAM session store holding identity and
key material (`middleware/auth.go:42-70`). The token is revocable mid-lifetime by store
deletion; the JWT alone authenticates nothing.

### 2.5 Related Systems

VeraCrypt and Cryptomator encrypt volumes or directory trees locally; neither offers an
API surface, concurrent multi-user access, or indexed search. S3 server-side encryption
keys reside with the provider; client-side S3 encryption libraries restore privacy but
reintroduce the key-management problem DocOps centralizes. Tink [11] and `age` [12] are
excellent cryptographic libraries — DocOps' streaming design borrows from `age`'s
chunked AEAD — but are libraries, not services; applications must still build auth,
storage, scoping, and search around them. DocOps' claim to a niche is the composition:
self-hosted, API-first, searchable, with a key hierarchy whose root never persists.

---

## 3. System Architecture

### 3.1 Components

```
                        ┌──────────────────────────────────────────────┐
 HTTP :8080 ── chi ──►  │ middleware.Auth / RateLimiter                │
                        └──────┬───────────────────────────────────────┘
                               │ userID + MasterKey (context)
             ┌─────────────────┼──────────────────────┬──────────────┐
             ▼                 ▼                      ▼              ▼
        handlers/auth    handlers/upload      handlers/download   search/delete/recovery
             │                 │                      │              │
     ┌───────▼──────┐   ┌──────▼───────┐      ┌───────▼──────┐       │
     │ UserStore    │   │ StorageConn  │      │ StorageConn  │       │
     │ (SQLite)     │   │ (local fs)   │      │ (local fs)   │       │
     └──────────────┘   └──────────────┘      └──────────────┘       │
     ┌──────────────┐                                        ┌───────▼──────┐
     │ SessionStore │                                        │ MetadataStore│
     │ (RAM+RWMutex)│                                        │ SQLite + FTS5│
     └──────────────┘                                        └──────────────┘
```

Routes are wired in `main.go:112-137`: five public auth endpoints behind an IP rate
limiter, two authenticated key-management endpoints, and four document endpoints behind
`middleware.Auth`. A single shared `*sql.DB` serves the user store; the metadata store
opens its own connection and runs idempotent migrations including FTS5 external-content
indexing with insert/delete triggers (`services/metadata/store.go:43-107`). Storage sits
behind the `StorageConnector` interface (`connectors/connector.go:9-14`) — Upload,
Download, Delete, Ping — with a streaming local-filesystem implementation whose objects
are named by UUID, never by filename, so disk layout leaks nothing about content.

### 3.2 The Key Hierarchy

```
Password ───Argon2id(salt₁)───► Password-KEK ──wrap──► ┌────────────┐
Recovery  ───Argon2id(salt₃)──► Recovery-KEK ─wrap───► │ Master Key │
API key   ───HKDF(salt₄)*────► API wrap key ──wrap───► └─────┬──────┘   (*shipped)
                                                             │ unwrap
                                              ┌──────────────▼──────────────┐
                                              │ DEK (32 B CSPRNG/document)  │
                                              └──────────────┬──────────────┘
                                              AES-256-GCM chunked stream
                                                             ▼
                                                 file ciphertext on disk
```

Password hash verification runs a *fourth*, fully independent derivation against salt₂
embedded in the PHC string. One naming clarification is required for honesty: the value
carried in sessions and request context under the field name `KEK`
(`services/auth/session.go:14-18`, `middleware/auth.go:65`) is in fact the **Master Key**
— the middle tier. The true password-KEK exists only transiently inside login, recovery,
and password-change flows. This naming debt is acknowledged rather than hidden; the
thesis consistently says *password-KEK*, *Master Key*, and *DEK* for the three tiers.

### 3.3 Data Model

Two tables carry state. `users` (`services/auth/users.go:46-59`): email, PHC password
hash, salt₁, wrapped Master Key + nonce, recovery salt₃ + recovery-wrapped Master Key +
nonce. `documents` (`services/metadata/store.go:43-61`): identity, owner, name/type/tags,
storage key, size, timestamps, and the crypto triple — `encrypted_dek`, `dek_nonce`,
`file_nonce` — plus `extracted_text`, mirrored into `documents_fts` (FTS5,
external-content, kept coherent by `documents_ai`/`documents_ad` triggers). Key columns
are excluded from JSON serialization at the model layer (`models/document.go`,
`json:"-"`) and again at handler response construction — defense in two layers against
accidental leakage.

## 4. Cryptographic Design

### 4.1 Domain Separation: Why Every Derivation Gets Its Own Salt

The system derives multiple keys from the same password. Two separate salts — one inside
the PHC string for password verification, one stored separately for KEK derivation —
enforce domain separation between the two derived values: even though both use the same
password and KDF, different salts guarantee independent outputs, so cracking the password
hash gives an attacker no information about the KEK. Reusing one salt would
cryptographically link the two derivations, undermining the point of having separate keys.

v0.1 generalizes the principle to three live salt domains: `users.salt` (salt₁,
wrapping the password-KEK), salt₂ embedded in the PHC string (password verification),
and salt₃ for the recovery-KEK
for the recovery-KEK that independently wraps the *same* Master Key
(`handlers/auth.go:132-160`). Registration runs these as explicit, independent Argon2id
invocations; nothing shares input state across domains. The planned API-key tier adds a
fourth domain under HKDF with its own per-key salt (Section 10).

### 4.2 The KEK That Is Never Stored

The password-KEK is never persisted because it does not need to be: it is re-derived at
login by running the same KDF over the user's password and the stored KEK salt. KDFs are
deterministic — identical inputs always produce the identical 256-bit key — so the key
can always be recovered without ever writing it to a database.

The security consequence is the design's core payoff. An attacker who fully compromises
the database walks away with salts, wrapped keys, and ciphertext — but no KEK exists in
storage to steal. Without the plaintext password there is nothing cryptographically
useful to take. The lifecycle is correspondingly strict: derive at login → unwrap Master
Key → hold in RAM for session duration → discard at logout or process exit. Outside an
active session, the key material does not exist anywhere in the system.

The cost is equally deliberate: Argon2id runs on every login precisely because it is
slow and memory-hard. ~64 MiB and tens of milliseconds per authentication is the price
of making offline brute-force against a stolen database economically irrational; v0.1
pays it knowingly. (Section 9 records the honest caveat that Go's garbage-collected byte
slices make *guaranteed* post-session zeroization aspirational rather than proven.)

### 4.3 Proving Key Correctness: Intended Blob versus As-Built Unwrap

The original design specified an explicit sentinel protocol. A fixed known plaintext —
`"docops-verify-v1"` — would be encrypted under the KEK at registration and stored as a
verification blob (`services/crypto/crypto.go:193-199`). At login, `VerifyPassword`
confirms the user knows the password by validating against the PHC string; then
`VerifyKEK` decrypts the blob and compares sentinels, proving that the KEK *derived from*
that password is the same key that existed at creation. The two checks prove different
things: a correct password paired with a mismatched or corrupted KEK salt would still
derive a wrong key, silently breaking decryption downstream — hence two independent
layers, ordered so the cheap constant-time password gate runs before any expensive KDF
work (`crypto.go:126`, then derivation).

As built, v0.1 wires something stronger and simpler: **the unwrap is the proof**.
Decrypting the wrapped Master Key under the freshly derived KEK (`handlers/auth.go:239`)
is itself a sentinel check whose "known plaintext" is GCM's authentication tag — a wrong
key fails tag verification with probability 1 − 2⁻¹²⁸, and no decryption result is
released on failure (`crypto.go:241-245`). The sentinel blob remains implemented and
unit-tested but deliberately unwired into production flows; the Login doc comment still
describing it is recorded as drift, not bug. The thesis takes the position that implicit
verification via AEAD authentication is preferable: fewer stored artifacts, fewer code
paths, identical assurance.

### 4.4 Nonce Discipline, Including Streams

AES-GCM's keystream is a function of key and nonce. Reuse of a nonce under the same key
generates the same keystream twice; an attacker XORs the two ciphertexts, the keystream
cancels, and the result is the XOR of two plaintexts — sufficient to recover both given
any structural knowledge. Because GCM's authentication subkey also derives from the
nonce, reuse additionally enables forgery of valid tags on arbitrary messages. Both
confidentiality and integrity fail simultaneously; this is why the failure mode is
labeled catastrophic rather than merely degrading.

DocOps therefore generates a fresh 96-bit nonce from `crypto/rand` at every sealing
operation (`services/crypto/crypto.go:270-273`) and stores nonces alongside ciphertexts,
where they are not secret but must be unique. Files use the record-framed scheme:
`EncryptStream` draws one random base nonce per file, splits input into 64 KiB chunks,
and derives each chunk nonce deterministically by XOR-ing a big-endian chunk counter
into the base nonce's low eight bytes (`chunkNonce`, `crypto.go:284-293`) — N unique
nonces for the storage cost of one, collision-free up to 2⁶⁴ chunks per file. Wire
format is `[u32 BE length][ciphertext‖tag]` repeated; the companion `decryptReader`
authenticates each chunk via `gcm.Open` *before* releasing any of its plaintext, so
truncation and tampering are caught at chunk boundaries rather than at end-of-stream
(`crypto.go:348-398`). Per-document DEKs bound every base nonce to a single file's
chunks, keeping per-(key,nonce) usage well inside GCM's budgets [2].

### 4.5 Envelope Split: Blast Radius, Rotation, Cost

Each document receives its own 256-bit DEK (`GenerateDEK`, `crypto.go:177-183`),
generated fresh at upload (`handlers/upload.go:95`) and wrapped under the Master Key
(`WrapDEK/UnwrapDEK`, `crypto.go:215-223`). The wrapping tier never touches document
bytes, for two concrete reasons. *Blast radius*: one key encrypting everything means one
compromise exposes everything at once; envelope encryption reduces a compromised wrap
key to a set of wrapped DEKs, each still requiring individual unwrapping to yield
plaintext. *Rotation*: rotating a directly-used root key would demand re-encrypting
every document; rotating the Master Key re-wraps only DEKs — kilobytes of work against
potentially gigabytes — which is what makes `rotate-master-key` operationally realistic
at all (Section 7.3). Performance inherits a precise corollary: the wrapping tier only
ever encrypts small, fixed-size inputs, so key-management cost is independent of corpus
size.

### 4.6 Constant-Time Verification

Standard equality checks short-circuit on first mismatching byte, leaking through
response timing how many leading bytes a guessed secret matched — the side channel
behind classic remote timing attacks [7]. Anywhere secret-derived values are compared,
DocOps uses `subtle.ConstantTimeCompare`, which always processes every byte
(`crypto.go:126`). The complementary discipline is silence: `VerifyKEK` returns a bare
boolean with no diagnostic detail (`crypto.go:206-212`), and login collapses
unknown-email and wrong-password into one identical 401 (`handlers/auth.go:208-233`) so
error text cannot enumerate users either.

---

## 5. Authentication and Authorization

### 5.1 Login Sequence

Login executes four ordered steps (`handlers/auth.go:210-251`): fetch user by email;
verify password against the PHC hash (cheap constant-time gate); derive the password-KEK
and unwrap the Master Key (expensive step, skipped entirely if the gate failed); issue
session. Failure at any step returns one generic 401 regardless of cause.

### 5.2 Why Keys Never Enter Tokens

The Master Key must never enter the JWT because JWTs live on clients — cookies or local
storage, both reachable by JavaScript. A single XSS vulnerability would let injected
script read the token, extract the key, and exfiltrate it; at that point the attacker
unwraps every DEK offline, permanently, surviving session expiry. Beyond injection, JWTs
ride request headers through load balancers, proxies, CDN edges, and log pipelines on
every call — any header-capturing hop writes the key to disk in plaintext.

DocOps' answer is structural rather than procedural: the JWT carries only an opaque
random session token (`Claims{SessionToken}`, `handlers/auth.go:35-38`); the server-side
store maps token → {userID, Master Key, expiry}; middleware injects key material into
request context where handlers consume it (`middleware/auth.go:57-67`). The token is an
identity handle; keys never cross the server boundary in any direction. Parsing rejects
non-HMAC algorithms explicitly on both ends (`handlers/auth.go:388-402`,
`middleware/auth.go:88-100`), closing the algorithm-confusion family of JWT attacks.

### 5.3 Server Sessions and Restart Semantics

Sessions live in an in-memory map behind a `sync.RWMutex` with periodic background GC
(`services/auth/session.go:26-77`). Process restart wipes all sessions — every logged-in
user is ejected and must re-authenticate, re-deriving keys as usual. This was accepted
for v0.1 on explicit reasoning: the consequence is UX inconvenience, not security or
integrity damage; no data is lost, no key compromised; proper persistence adds real
infrastructure complexity better deferred (Section 10 scopes it honestly). A valid-JWT-
with-dead-session request fails exactly like a bad JWT — indistinguishable 401 — because
middleware consults the store, not just the signature (`middleware/auth.go:57-63`).

### 5.4 Cookies

Session cookies are issued `HttpOnly; Secure; SameSite=Strict; Path=/`
(`handlers/auth.go:421-431`). HttpOnly hides the cookie from all JavaScript, blunting
token theft even when XSS lands — the attacker can ride the victim's requests but cannot
read or replay the credential elsewhere. SameSite=Strict keeps the cookie off cross-site
requests entirely, defeating CSRF by construction: forged forms from other origins
arrive unauthenticated. Strict's cost — cookies not sent on inbound cross-site
navigation — is immaterial for an API-first service. Clearing mirrors attributes exactly
with `MaxAge=-1` (`:437-447`).

### 5.5 Authentication versus Authorization, and the 401/403/404 Refinement

Authentication answers *who are you* — PHC verification, KEK derivation, signed token.
Authorization answers *what may you do* — enforced here by scoping ownership into SQL:
every document read filters on `user_id` (`GetByID(id, userID)`,
`services/metadata/store.go:147-181`; FTS search joins with the same predicate), so a
legitimate user probing another user's document is blocked at the data layer, uniformly,
in every handler, by construction.

Status-code policy follows an anti-leakage refinement of the standard 401/403 dichotomy.
401 covers the entire authentication gate, detail-free. Authorization failures surface
as **404, not 403**: a foreign document must be indistinguishable from a nonexistent
one, because "403: this docID belongs to someone else" is itself an information leak.
REST purism yields to enumeration resistance deliberately. Error vagueness is likewise
policy: generic messages protect against user enumeration, crypto-oracle guidance, and
existence probes, with debugging served by structured server-side logging instead of
client-facing detail (Section 6 notes the tradeoff).

## 6. Implementation Concerns in Go

### 6.1 `sync.RWMutex` versus `sync.Mutex`

A plain mutex serializes everything: reads block reads. The session store is read on
*every authenticated request* but written only at login/logout — a heavily read-dominant
workload — so it uses `sync.RWMutex`: concurrent holders of read locks, exclusive write
locks (`Get` under RLock at `session.go:96-107`; `Save`/`Delete` under Lock at
`:82-86`, `:112-115`). The rate limiter is the deliberate contrast case: every request
mutates its counters, so a plain `sync.Mutex` is correct there
(`middleware/ratelimit.go:17-23`). The pair makes the actual lesson visible — the right
lock follows from the read/write ratio of *this* structure, not from habit.

### 6.2 Context as the Key Carrier

`context.Context` carries request-scoped values and cancellation through middleware into
handlers. Key material travels there rather than through function arguments for three
reasons: middleware stamps identity and key once and every downstream handler reads them
uniformly (`KEKFromContext` in upload `handlers/upload.go:57`, download `:47`,
recovery flows); context values die with the request, mirroring the key lifecycle of
Section 4.2; and unexported typed keys (`contextKey struct{ name string }`,
`middleware/auth.go:15-23`) make the values unforgable by other packages. The standard
advice against placing large secrets in context is acknowledged; the exception is
accepted because lifetimes are single-request and logging never touches these values.

### 6.3 `defer` on Unlocks

`defer mu.Unlock()` schedules release on *every* exit path — returns and panics alike.
Manual unlocks between lock and early-return are deadlock incubators: one missed path
freezes the store for the entire process, and here that means every authenticated
request system-wide. Session-store methods keep critical sections small and single-exit,
with background GC coordinating via channel rather than long-held locks
(`session.go:55-66`).

### 6.4 Interfaces Where Tests Need Them

Handlers depend on the `StorageConnector` interface, not concrete storage
(`connectors/connector.go:9-14`) — which is why handler tests run with a hand-written
in-memory connector (`handlers/upload_test.go:24-61`) and no filesystem. The stores are
still passed as concrete structs (`main.go:98-102`); extracting interfaces there is the
recorded evolution path (ROADMAP P1-1), motivated identically: handlers testable without
real SQLite, backends swappable without touching handlers.

---

## 7. Data Flow Walkthrough

This section answers, against real code, the question that most reveals whether the
architecture is understood: *a user uploads a document — what happens cryptographically,
key by key, operation by operation?*

### 7.1 Upload (POST /v0.1/docs/upload)

1. **Authentication gate.** Middleware resolves cookie → JWT → session token → session;
   injects userID and Master Key into request context (`middleware/auth.go:42-67`).
   No key material arrived over the network.
2. **Handler intake.** Multipart parse with 10 MiB memory cap spilling to disk;
   file handle and optional tags extracted (`upload.go:73-90`).
3. **Fresh DEK.** `GenerateDEK()` produces 32 CSPRNG bytes unique to this document
   (`upload.go:95`). Reused DEKs would couple document fates; they are never reused.
4. **Opaque name.** `storageKey = uuid.NewString()` (`upload.go:105`) — disk names
   reveal nothing.
5. **Stream encryption.** A goroutine runs `EncryptStream(file, pipeWriter, dek)` while
   the connector concurrently drains the pipe's reader: 64 KiB chunks, each GCM-sealed
   under its counter-derived nonce, length-framed; one random base nonce returned for
   persistence (`upload.go:111-124`, `crypto.go:303-343`). Memory stays constant
   regardless of file size; plaintext never exists whole in memory.
6. **Envelope wrap.** `WrapDEK(dek, masterKey)` seals the DEK under the Master Key with
   a fresh nonce (`upload.go:130`). After this line the plaintext DEK is garbage; only
   the wrap persists.
7. **Ciphertext lands.** Connector streams framed ciphertext to
   `<base>/files/<uuid>` (`local.go:41-73`), deleting partials on failure; encryption
   failures trigger best-effort storage cleanup (`upload.go:153-157`).
8. **Metadata commit.** One row: owner, name/type/tags, storage key, size, and the
   crypto triple `encrypted_dek`, `dek_nonce`, `file_nonce` (`upload.go:162-186`);
   metadata failure also removes the orphaned file. FTS triggers index searchable text.
9. **Response.** 201 with whitelisted fields only — id, name, type, size, tags,
   timestamps (`upload.go:194-202`). Keys, nonces, storage paths never appear.

Keys touched, in order: **Master Key (from context) → new DEK → wrapped DEK stored**.
The file's bytes were encrypted exclusively under the ephemeral-per-document DEK.

### 7.2 Download (GET /v0.1/docs/{docID}/download)

Ownership-scoped metadata fetch (foreign IDs read as 404); connector opens the
ciphertext stream; `UnwrapDEK(doc.EncryptedDEK, doc.DEKNonce, masterKey)` recovers this
document's DEK (`download.go:76`); `DecryptStream` wraps the stream in the
chunk-authenticating reader (`:85`); headers set; `io.Copy` pumps plaintext to the
client, each chunk released only after tag verification (`crypto.go:348-398`). A wrong
key, tampered byte, or truncated tail fails closed mid-stream rather than leaking
unverified plaintext.

### 7.3 Recovery, Password Change, Rotation

Three flows reuse one primitive — re-wrapping the Master Key — and differ only in which
wrap they rebuild. Recovery derives a KEK from the shown-once recovery key
(`docops_rec_…`, 18 CSPRNG bytes, `handlers/auth.go:449-457`) to unwrap, then re-wraps
under a KEK derived from the new password (`recovery.go:29-88`). Password change does
the same starting from the live session key. Master-key rotation goes further:
generate new Master Key → unwrap-and-re-wrap *every* DEK under it → re-wrap under
password-KEK → mint a fresh recovery wrap → patch live sessions so active users never
notice (`recovery.go:174-305`). Documents' ciphertext bytes are untouched throughout —
Section 4.5's rotation economics made executable. Known defect: v0.1 performs the loop
non-transactionally (ROADMAP P0-2).

---

## 8. Testing Methodology

### 8.1 Inventory and Division of Labor

Approximately 170 tests across seven packages divide cleanly. *Unit tests*
(`services/crypto/crypto_test.go`, 25+ tests) prove primitives against their contracts:
salt/DEK length and uniqueness, KEK determinism and cross-salt differentiation,
round-trips, wrong-key rejection, tamper detection, nonce uniqueness, multi-chunk
streams exceeding one chunk, tampered-chunk rejection — plus an API-key wire-format
battery that pins key-ID parseability across hundreds of generated credentials.
*Integration tests* (90+ across `handlers/*`) compose real components — shared-pool
SQLite, httptest, real middleware — proving that upload actually persists retrievable
ciphertext, that stored bytes differ from plaintext (`download_test.go:364`), that
cross-user isolation holds through the full stack, that logout truly invalidates,
that a mid-rotation injected failure rolls back wholesale
(`rotation_atomicity_test.go`), that a wrapped DEK swapped between a user's own
documents fails GCM authentication (`aad_test.go`), that API keys authenticate
statelessly across simulated restarts with all failure modes producing byte-identical
401s (`apikeys_test.go`), and that expired documents are indistinguishable from
nonexistent ones. Store, middleware, service, and
connector suites fill their layers (15 + 13 + 12 + 7). Neither style subsumes the
other: units localize failures precisely; integration catches exactly the wiring and
lifecycle bugs units cannot see.

### 8.2 Weak KDF Parameters in Tests Are Correct

Tests override Argon2id to minimal parameters (`handlers/auth_test.go:22-28`).
Production defaults (m=65536, t=3, p=2) cost ~64 MiB and ~100 ms per derivation;
hundreds of derivations per suite would burn minutes and gigabytes for no logical gain.
Tests verify *logic* — correct unwrap flow, mismatch handling — and Argon2id with any
consistent parameters exercises identical code paths deterministically. Memory-hardness
is the anti-brute-force property itself (Section 4.2): weak constants in production
would cheapen offline attacks after any database leak. Same mechanism, opposite ends:
config tunes production upward, tests tune downward.

### 8.3 The Race Detector on the Concurrency Hotspot

`go test -race` instruments memory accesses and reports unsynchronized concurrent access
— bugs invisible to functional tests yet undefined under load. The SessionStore is the
hotspot: every authenticated request reads it, logins/logouts write it, and a GC
goroutine mutates it every five minutes; a missing lock could pass years of sequential
testing and then hand one user another user's session under load. Concurrent session
tests (`services/auth/session_test.go`) exist precisely for this; the suite runs clean
under `-race -tags fts5 ./...`.

Known gaps recorded honestly: no end-to-end test drives the fully assembled router; no
fuzzing targets the parsers or the chunk framer; timing-side-channel testing remains
manual reasoning plus `subtle.*` discipline rather than statistical measurement.

## 9. Threat Model and Limitations

### 9.1 What the System Claims — Precisely

| Adversary capability | Outcome |
|---|---|
| Full database compromise (dump `users`, `documents`) | Obtains PHC hashes, salts, wrapped keys, ciphertext, metadata. No usable key material; content protected by password entropy × Argon2id cost. |
| Disk/storage theft without database | UUID-named ciphertext + nonces are in DB, so files alone are inert. |
| Full compromise of a running server's memory | Game over for that session's users — true of every non-hardware system; stated rather than hidden. |
| XSS on an integrating frontend | HttpOnly cookies unreadable to script; attacker may ride the victim's active requests but extracts no token, no keys. |
| CSRF | SameSite=Strict defeats by construction. |
| User enumeration via login errors | Impossible: uniform 401s; register returns 409 deliberately (P1-4 records the tradeoff). |
| Document-existence probing across users | 404-uniformity makes foreign and nonexistent indistinguishable. |
| Ciphertext tampering or truncation | GCM authentication fails closed at chunk granularity. |

The zero-knowledge claim is therefore **content-at-rest only**. Names, tags, sizes,
timestamps, and extracted text are intentionally plaintext to power search; an adversary
with database read access learns *what* is stored though never *what it says*. Systems
claiming both searchable and end-to-end-encrypted simultaneously should be read with
suspicion; DocOps claims the former honestly and declines the latter (ROADMAP,
out-of-scope).

### 9.2 Known Defects and Drift in v0.1

Recorded without embellishment, each tracked in ROADMAP.md:

1. **Non-atomic rotation** — DEK re-wrap loop runs outside any transaction
   (`recovery.go:227-244`); crash mid-loop leaves mixed wraps (P0-2).
2. **No AAD binding** — wrapped DEKs are context-free blobs (`crypto.go:275`);
   cross-document swaps within one account authenticate successfully (P0-4).
3. **Proxy-header trust** — rate limiter honors spoofable `X-Forwarded-For`
   (`middleware/ratelimit.go:76-80`) (P0-6).
4. **Hard kill on shutdown** — `srv.Close()` truncates in-flight uploads (`main.go:154`)
   (P0-3).
5. **Static KDF costs per user** — config strengthening never upgrades existing hashes;
   PHC self-description enables the lazy-upgrade fix but v0.1 does not apply it (P0-5).
6. **Zeroization is aspirational** — Go's moving GC cannot guarantee byte-slice wipes;
   "key discarded at session end" means unreachable-and-collected, not provably erased.
7. **Dead code with stale narrative** — verification blob implemented/tested but
   unwired while Login's doc comment still describes it (Section 4.3); config TTLs
   parsed but shadowed by handler constants (`handlers/auth.go:22-25`).
8. **Single-node SQLite** — write concurrency and operational scale bounded by design
   for v0.1.

### 9.3 Residual Risks Accepted

Password reset without the recovery key destroys data irrecoverably — this is the
no-stored-KEK tradeoff working as designed, not a bug. The JWT secret is a single
symmetric root for token signing; asymmetric signing (RS/EdDSA) matters only when issuer
and verifier diverge, which they do not here. Register-time 409s leak account existence
to careful probes under the rate limiter's ceiling — accepted, documented, revisitable
(P1-4).

---

## 10. Future Work

The roadmap (`ROADMAP.md`) sequences correctness before operability before adoption.
Three items carry architectural weight worth stating here.

### 10.1 Machine Roots: The API-Key Path (shipped)

Developer adoption required machine-to-machine auth, and the password root cannot
serve it — server jobs do not type passwords into Argon2id per request. The shipped
design adds a fourth tier parallel to recovery: keys of form `docops_sk_<id>_<secret>` (32 CSPRNG
bytes, shown once), stored hash-only alongside a per-key salt and their own wrap of the
same Master Key; bearer requests verify `SHA-256(presented)` in constant time, derive a
wrap key via HKDF-SHA256, unwrap, and proceed through unchanged handlers.

The instructive part is the KDF choice. Argon2id exists because human passwords are
low-entropy; a 32-byte CSPRNG secret is already uniformly random, so memory-hardness
buys nothing against its HKDF output — the fast KDF is not a shortcut but the
*entropy-appropriate* choice, cutting per-request auth from ~100 ms to microseconds.
Envelope encryption earns its final dividend here: adding a tier wraps kilobytes, and
downstream handlers never learn a new key entered the building. Statelessness of the
bearer path additionally dissolves the restart problem (Section 5.3) for machine
traffic entirely.

### 10.2 Integrity Binding (AAD)

Versioned AAD binding each wrap to `(userID, docID)` converts the Section 9.2 second
defect into a hard failure, with legacy rows lazily re-wrapped on contact.

### 10.3 The Adoption Ladder

OpenAPI-first SDKs, the S3-compatible connector, PDF/DOCX extraction feeding the already-
wired FTS5 index, TTL enforcement over the existing column, and an org/sharing layer
generalizing SQL ownership scoping to grant checks. Session persistence stays honestly
scoped: refresh-token durability without ever persisting key material — machines get
survivability from P0-1 instead, humans re-login.

---

## 11. Conclusion

DocOps demonstrates that the Searchable Privacy Paradox is an architecture problem, not
a cryptographic one: established primitives — Argon2id, AES-GCM, envelope encryption,
FTS5 — compose into a service where documents are searchable yet unreadable at rest,
provided three disciplines hold. Derivation domains must be separated so that no two
purposes share key material. Root keys must be structurally excluded from storage,
tokens, logs, and client boundaries, accepted as an availability cost paid at every
login. And integrity must fail closed everywhere, from constant-time comparisons to
per-chunk AEAD authentication.

v0.1 ships with defects enumerated rather than hidden, tests sufficient to make its
invariants refactorable rather than fragile, and an evolution path — machine-rooted API
keys, integrity binding, adoption infrastructure — that extends the hierarchy without
revising it. The deepest lesson of the build matches the thesis's opening claim:
correctness here was structural, not procedural. Keys were safe because no code path
could move them, ownership held because no query could forget it, and nonce reuse was
impossible because generation lived in exactly one function. Systems stay secure when
their insecure behavior is unrepresentable; that standard, more than any primitive
choice, is what this project set out to engineer.

---

## 12. References

[1] Biryukov, A., Dinu, D., Khovratovich, D. *Argon2: the Memory-Hard Function for
Password Hashing and Other Applications.* RFC 9106, IETF, 2021.

[2] McGrew, D., Viega, J. *Recommendation for Block Cipher Modes of Operation: Galois/
Counter Mode (GCM) and GMAC.* NIST Special Publication 800-38D, 2007 (rev. draft
updates 2020–2026).

[3] Turan, M. S., et al. *Recommendation for Password-Based Key Derivation, Part 2:
Verification Schemes.* NIST SP 800-132 / SP 800-90B family context for entropy and
salting practice.

[4] Jones, M., Bradley, J., Sakimura, N. *JSON Web Token (JWT).* RFC 7519, IETF, 2015.

[5] Barth, A. *HTTP State Management Mechanism.* RFC 6265, IETF, 2011.

[6] Rescorla, E. *The Transport Layer Security (TLS) Protocol Version 1.3.* RFC 8446,
IETF, 2018 (record-framed AEAD precedent).

[7] Brumley, D., Boneh, D. *Remote Timing Attacks Are Practical.* Proceedings of USENIX
Security Symposium, 2003.

[8] P-H-C Steering Group. *PHC String Format Specification.*
https://github.com/P-H-C/phc-string-format.

[9] Amazon Web Services. *AWS Key Management Service Developer Guide — Envelope
Encryption.* https://docs.aws.amazon.com/kms/.

[10] Barker, E. *Recommendation for Key Management: Part 1 — General.* NIST SP 800-57
Part 1, Rev. 5, 2020.

[11] Google. *Tink Cryptographic Library — Design Documentation.* https://developers.google.com/tink.

[12] Valsorda, F. *The `age` File Encryption Format.* https://age-encryption.org/v1.

[13] Porter, D., Kennedy, J. *SQLite FTS5 Extension Documentation.*
https://www.sqlite.org/fts5.html.

[14] OWASP Foundation. *Password Storage Cheat Sheet* and *Authentication Cheat Sheet.*
https://cheatsheetseries.owasp.org/.

[15] The Go Authors. *crypto/subtle*, *crypto/cipher*, *sync*, *context* package
documentation. https://go.dev/doc/.



