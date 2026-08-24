# DocOps Roadmap

> Status: v0.1-alpha · ~190 tests passing · single-node SQLite + local filesystem
> **P0 and P1 are COMPLETE** (shipped 2026-08-24); remaining work lives in P2.
>
> Companion documents: `README.md` (security model), `docs/thesis-notes.md` (design
> rationale source material), `thesis.md` (full engineering thesis).

---

## North Star

**DocOps is the encrypted document backend for applications.**

The defensible asset is not encrypted storage — S3, Tink, and Cryptomator all encrypt.
It is **encrypted storage that remains searchable**, delivered as a boring HTTP API in a
single container. Application developers integrate once and never touch raw file bytes,
ciphertext, or key material; their users' documents are unreadable at rest even to the
hosting developer.

Adoption ladder (each rung unlocks the next):

1. **API-key auth path** — unblocks machine-to-machine use (P0-1)
2. **OpenAPI spec ✅ shipped · generated SDKs** — zero-friction evaluation and integration (spec at `api/openapi.yaml`, viewers at `/docs` + `/redoc`)
3. **S3-compatible connector** — one connector covers S3, R2, MinIO, Spaces (P2)
4. **PDF/DOCX text extraction** — turns "searchable" from demo into differentiator (P2)
5. **Orgs / sharing / scoped keys** — team adoption (P2)

Everything in P0 exists to make the current system *correct under failure*; P1 makes it
*operable*; P2 makes it *adoptable*.

---

## P0 — Correctness & Unblocking

Do these before any feature work. Each is small, bounded, and removes either a data-integrity
hazard or the primary adoption blocker.

### P0-1 · API-key authentication path (machine-to-machine)

**Problem.** The entire key hierarchy roots in human passwords (`password → Argon2id →
password-KEK`, `handlers/auth.go:236`). A server-side job cannot type a password into
Argon2id per request. Developers consume backends with API keys; without them DocOps is
vault-shaped only.

**Design.** An API key is a *machine-shaped recovery key* — the recovery tier
(`handlers/auth.go:144-160`) already proves a second independent wrap of the same Master
Key works.

```
Password ──Argon2id──► Password-KEK ──wrap──► ┌────────────┐
Recovery  ──Argon2id──► Recovery-KEK ─wrap──► │ Master Key │◄──wrap── per-doc DEKs
API key   ──HKDF-SHA256──► API wrap key ────► └────────────┘      (unchanged)
```

- Key format: `docops_sk_<key_id>_<secret>` where `secret` is 32 CSPRNG bytes,
  base64url-encoded, shown exactly once at creation (same UX contract as the recovery key).
- Storage: new `api_keys` table — `key_id TEXT PK, user_id TEXT NOT NULL, name TEXT,
  secret_hash BLOB NOT NULL, hkdf_salt BLOB NOT NULL, wrapped_master_key BLOB NOT NULL,
  master_key_nonce BLOB NOT NULL, created_at DATETIME NOT NULL, last_used_at DATETIME,
  revoked_at DATETIME`. Hash-only storage: `secret_hash = SHA-256(secret)`.
- KDF choice is deliberate and entropy-based: human passwords need Argon2id because they
  are low-entropy; a 32-byte CSPRNG secret is already high-entropy, so
  `HKDF-SHA256(secret, hkdf_salt, info="docops api-wrap v1")` suffices. Per-request auth
  costs microseconds instead of a ~100 ms Argon2id run.
- Auth flow: `Authorization: Bearer docops_sk_…` → indexed lookup by `key_id` →
  `subtle.ConstantTimeCompare(SHA-256(presented), stored)` → HKDF → unwrap Master Key →
  inject into request context exactly as the cookie path does
  (`middleware/auth.go:65-67`). **No session store involvement — stateless per request.**
  Machine traffic consequently survives restarts and scales horizontally while humans
  still re-login.
- Middleware fork: cookie→session store (humans, unchanged) ∥ bearer→derive-per-request
  (machines, new). Downstream handlers untouched — envelope encryption earns its keep here.
- Endpoints: `POST /v0.1/auth/api-keys` (create, returns secret once),
  `GET /v0.1/auth/api-keys` (list metadata, never secrets), `DELETE
  /v0.1/auth/api-keys/{keyID}` (revoke = set `revoked_at`; revoked keys fail closed).
- Rate limiting applies to key-authenticated document routes as well as public auth routes.
- v1 keys carry full user authority; scoped/read-only keys are P2.

**Acceptance criteria.**
- [x] DB leak yields `secret_hash`, `hkdf_salt`, wrapped keys — no usable key material.
- [x] Wrong/tampered/revoked/malformed keys all produce an identical detail-free 401.
- [x] Key auth performs zero Argon2id work; unwrap path identical to cookie path downstream.
- [x] Revoked key rejected on first use; `last_used_at` updates are throttled (no write per request).
- [x] Secret appears exactly once in exactly one response body; never logged anywhere.

**Tests.** Constant-time compare unit tests; tampered-secret rejection; revocation
integration test through full upload/download; cross-key isolation; race detector on
concurrent bearer requests; timing-sanity smoke test on hash comparison.

**Anchors.** New: `services/auth/apikeys.go`, `handlers/apikeys.go`,
`middleware/auth.go` fork. Reuses: `crypto.WrapDEK/UnwrapDEK`
(`services/crypto/crypto.go:215-223`).

### P0-2 · Atomic master-key rotation

**Problem.** `RotateMasterKey` re-wraps every DEK via per-document `UpdateDEK` calls with
no transaction (`handlers/recovery.go:227-244`). A crash mid-loop leaves mixed old/new
wraps and no record of which is which — unrecoverable without brute force.

**Design.** Single SQLite transaction spanning `ListAllForUser` reads, all DEK re-wraps,
and the user-key update. Either the whole rotation commits or none of it does; the old
Master Key remains valid until commit, so concurrent downloads stay correct throughout.

**Acceptance criteria.**
- [x] Injected failure at any loop position rolls back completely; user can still decrypt everything with the old key (`rotation_atomicity_test.go`).
- [x] Rotation runs in one `metaStore.InTx` spanning DEK re-wraps + user row (recovery re-issue included).
- [x] Old Master Key remains authoritative until commit; retry-after-repair covered by test.

**Tests.** Transaction-abort injection tests; concurrent reader test during rotation;
crash-recovery simulation.

### P0-3 · Graceful shutdown

**Problem.** `main.go:154` calls `srv.Close()`, which kills in-flight requests — an
upload mid-stream can leave an orphaned ciphertext file or a committed-metadata-without-file state.

**Design.** Replace with `srv.Shutdown(ctx)` using a timeout context (e.g. 30 s); stop
accepting connections, drain active ones, then close stores in dependency order.

**Acceptance criteria.**
- [x] SIGTERM drains connections (`srv.Shutdown`, 30 s budget, forced-close fallback); live-verified.
- [x] Listeners stop immediately on signal; process exits after drain or timeout.

**Tests.** Integration test issuing an in-flight request against a shutting-down server.

### P0-4 · AAD binding of wrapped DEKs

**Problem.** Wrapped DEKs are unbound blobs (`gcm.Seal(..., nil)` —
`services/crypto/crypto.go:275`). A wrapped DEK swapped between two of a user's own
documents decrypts successfully. Requires DB write access to exploit, but the fix is cheap
defense-in-depth.

**Design.** AAD = `"docops-dek-v1|" + userID + "|" + docID` for document DEKs; analogous
binding for master-key wraps (`"docops-master-v1|" + userID`). Version the wire format so
legacy rows remain readable and are lazily re-wrapped with AAD on next rotation/login.

**Acceptance criteria.**
- [x] Cross-document DEK swap fails GCM authentication (swap-attack test).
- [x] Legacy rows decrypt via `UnwrapDEKAny`; rotation migrates wraps to bound form idempotently.

**Tests.** Swap-attack unit test; legacy-format compatibility test; migration idempotence.

### P0-5 · Argon2 parameter upgrade-on-login

**Problem.** The PHC string carries its creation params (self-describing —
`services/crypto/crypto.go:75-131`), so strengthening `config.yaml` never upgrades
existing users: old hashes verify forever under old costs.

**Design.** On successful login, parse the PHC params; if config params are strictly
stronger, re-hash the password, generate a fresh KEK salt under new params, derive the new
KEK, re-wrap the Master Key (and only that — recovery wrap keeps its own salt), persist in
one transaction. Upgrade happens after authentication succeeds, at most once per param bump.

**Acceptance criteria.**
- [x] Login with old-cost hash transparently upgrades and still returns session.
- [x] Second login performs no redundant upgrade (byte-identical PHC assertion).
- [x] Weaker/equal config never downgrades; per-user `kek_params`/`recovery_kek_params` persisted (also fixed latent recovery-vs-config drift bug).

**Tests.** Param-bump integration test asserting exactly-one upgrade; recovery-path
compatibility post-upgrade.

### P0-6 · Explicit proxy-trust flag for rate limiter

**Problem.** The limiter trusts `X-Forwarded-For` / `X-Real-IP` verbatim
(`middleware/ratelimit.go:76-80`) — trivially spoofable to bypass limits or to frame
victim IPs into 429s when deployed bare.

**Design.** `trust_proxy_headers: false` by default in `models.RateLimitConfig`; headers
honored only when explicitly enabled (documented as "set only behind a sanitizing proxy").

**Acceptance criteria.**
- [x] Default build ignores spoofed headers entirely; RemoteAddr used.
- [x] Opt-in via `rate_limit.trust_proxy_headers: true`; split-mode tested.

**Tests.** Split limiter tests on both modes.

---

## P1 — Operational ✅ (all shipped 2026-08-24)

### P1-1 · Session-store interface extraction
Extract `SessionStore` behind an interface (`Save/Get/Delete/Close`) so handlers depend on
abstraction (`main.go:81-82` passes concrete structs). Proves out the pattern already
validated by `StorageConnector` + `mockConnector` (`connectors/connector.go:9-14`,
`handlers/upload_test.go:24-61`).

### P1-2 · Refresh-token persistence across restarts — honestly scoped
Human access-token sessions staying RAM-only is a *feature* (keys never at rest). Scope:
persist refresh sessions (opaque token hash + identity + expiry) so restarts don't kill
remember-me flows; master keys still require re-derivation on next access-token issue —
which the API-key path (P0-1) renders unnecessary for machines. Do not persist key
material; if that constraint ever must break, it breaks into a KMS/env-root workstream,
not a sessions table.

### P1-3 · Security audit logging
Structured `slog` events for `login_success/login_failed/register/recover/
change_password/rotate_master_key/upload/delete/api_key_created/revoked` with actor, IP,
doc IDs, request IDs. Invariant: no key material, no secrets, no ciphertext in logs — ever.

### P1-4 · Register enumeration policy
Register currently returns 409 for duplicate emails (correct anti-enumeration would defer
to email verification). Decide deliberately: keep 409 (rate-limited, documented tradeoff)
or move verification-gated signup. Document the choice in README's security model.

### P1-5 · Health & readiness endpoints
`GET /healthz` (process up), `GET /readyz` (DB ping + storage ping — both components
already expose health checks: `db.Ping()` `main.go:60`, `connector.Ping()` `main.go:92`).

---

## P2 — Product

| Item | Notes |
|---|---|
| **S3-compatible connector** | Interface already abstracts it (`connectors/connector.go:9-14`); one implementation covers S3/R2/MinIO/Spaces. Streaming multipart for large files. |
| **Scoped API keys** | Read-only, tag-scoped, per-bucket grants; extends P0-1's `api_keys` table with a `scopes` column checked at the authorization layer. |
| **Text extraction pipeline** | PDF/DOCX → `extracted_text` at upload (`metadata/store.go` FTS5 index is already wired via `documents_ai` trigger). Turns search from name/tag-only into the core differentiator. |
| **TTL enforcement** | ✅ SHIPPED: download-time 404 gate + startup/hourly storage-first sweeper. |
| **OpenAPI + generated SDKs** | ✅ SPEC SHIPPED: `api/openapi.yaml` (all 15 operations, both auth schemes) served at `/openapi.yaml` with Swagger UI `/docs` + Redoc `/redoc`. Remaining: generated TS/Python/Go clients + quickstart. |
| **Orgs / sharing model** | ACL table + authorization-layer extension; ownership scoping in SQL generalizes to grant checks (`GetByID(id, userID)` → `(id, principal, acl)`). |
| **Playground web UI** | Thin client over the API; comes last — UI is expensive, SDK-first DX is not. |

---

## Explicitly out of scope (by design)

- **Client-side/end-to-end encryption**: server-side indexing requires server-side plaintext
  moments; claiming E2E would be dishonest. Content-at-rest is zero-knowledge; *metadata is
  not* — stated plainly in the thesis threat model.
- **Distributed multi-node sessions** pre-P0-1: the stateless bearer path dissolves most of
  the problem; revisit only for human-session fan-out at real scale.
