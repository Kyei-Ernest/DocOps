# DocOps Thesis Notes — Design Rationale (Source Material for thesis.md)

> **Purpose:** These are the design-rationale answers written down at the beginning of
> the project. They are preserved as primary source material and must be woven into
> `thesis.md` when it is written. Each entry is annotated with exact code anchors that
> realize the rationale, discovered during the deep system analysis of 2026-08-24.
> Where the code has evolved past the original note, a "Drift" marker records the delta
> so the thesis describes the system as it *is*, not only as it was conceived.

---

## Part I — Cryptography (`services/crypto/crypto.go`)

### 1. Why two separate salts — one inside the PHC string for password verification, one stored separately for KEK derivation

Two separate salts enforce domain separation between the two derived values. Even though
both use the same password and KDF, different salts guarantee independent outputs — so
cracking the password hash gives an attacker no information about the KEK. Reusing the
same salt would cryptographically link the two, undermining the whole point of having
separate keys.

**Code anchors:**
- PHC salt (inside hash string), generated per-call: `HashPassword` — `services/crypto/crypto.go:27-54`
- Separate KEK salt: `GenerateSalt()` — `services/crypto/crypto.go:166-172`; persisted as `users.salt` (`services/auth/users.go:47-58`)
- Registration runs both derivations as independent Argon2id calls: `handlers/auth.go:118` (hash) and `handlers/auth.go:132-142` (kekSalt → DeriveKEK → WrapDEK)

**⚠ Drift:** The hierarchy grew to three tiers / three salts. Now: (a) PHC salt inside
the password hash, (b) KEK salt for the *password-KEK*, (c) a third `recovery_salt` for
a *recovery-KEK* independently wrapping the same master key (`handlers/auth.go:144-160`).
Also, the session value named "KEK" is actually the **Master Key** — the password-KEK
wraps the master key; the master key wraps document DEKs
(`services/auth/session.go:10-18`; see naming-collision note in Part VI).

### 2. Why the KEK never gets stored anywhere, and what re-derivation means

The KEK is never persisted to storage because it doesn't need to be — it's derived at
runtime on every login by running the same KDF (Argon2id) with the user's password and
the stored KEK salt. Since KDFs are deterministic, the same inputs always produce the
same 256-bit key, so we can always get it back without ever writing it to a database.

Direct security benefit: even if an attacker fully compromises the database, they walk
away with the KEK salt and encrypted data blobs — but the KEK itself never existed in
storage, so there is nothing cryptographically useful to steal without the user's
plaintext password.

Lifecycle: derived at login → used to unwrap the data key → zeroed out from memory when
the session ends. Outside an active session, the KEK does not exist anywhere in the
system.

Tradeoff: this makes the KDF run on every login, which is intentionally expensive —
Argon2id is designed to be slow and memory-hard. That cost is accepted deliberately
because it's what makes both brute-force attacks and stored-key theft impractical at the
same time.

**Code anchors:**
- Deterministic derivation: `DeriveKEK` — `services/crypto/crypto.go:152-161`
- Login-time re-derivation + unwrap: `handlers/auth.go:236-239`
- Session-only residence (RAM): `Session{KEK []byte}` — `services/auth/session.go:14-18`
- Default cost parameters m=65536 KiB, t=3, p=2, key=32 B, salt=16 B: `config/config.go` defaults

### 3. What the verification blob proves at login — and why `VerifyKEK` runs after `VerifyPassword` instead of replacing it

The verification blob proves that the KEK derived at login is identical to the KEK that
existed at account creation. It works by attempting to decrypt a ciphertext whose
plaintext is already known; if decryption produces the expected value, the KEK is
confirmed correct.

`VerifyKEK` is called after `VerifyPassword`, not instead of it, because they prove two
different things. `VerifyPassword` confirms the user knows the correct password by
validating against the PHC string. `VerifyKEK` confirms that the KEK derived from that
password is actually usable — a correct password with a mismatched or corrupted KEK salt
would still derive a wrong key, which would silently break decryption downstream. The two
checks are independent layers.

Ordering is deliberate: `VerifyPassword` runs first as a fast, cheap gate. If the
password is wrong, there is no point deriving a KEK and attempting decryption at all.

**Code anchors:**
- Sentinel `"docops-verify-v1"` encrypted under the KEK: `CreateVerificationBlob` — `crypto.go:193-199`
- Silent-failure verification (no diagnostic detail leaked): `VerifyKEK` — `crypto.go:206-212`
- Constant-time gate first: `subtle.ConstantTimeCompare` in `VerifyPassword` — `crypto.go:126`

**⚠ Drift (important for thesis honesty):** In v0.1 the sentinel-blob flow is implemented
and unit-tested but **not wired into any production handler** — no verification-blob
columns exist in the `users` schema, and the Login doc comment (`handlers/auth.go:204-206`)
still describes the old flow. KEK correctness is now proven *implicitly*: the GCM unwrap
of the wrapped Master Key fails if the derived KEK is wrong (`handlers/auth.go:239`),
because AES-GCM authentication rejects a wrong key with overwhelming probability. The
thesis should present the implicit GCM-authentication proof as the mechanism in place and
the sentinel blob as the explicit, auditable alternative.

### 4. Why nonce reuse with the same key breaks AES-GCM completely

AES-GCM derives a keystream from the combination of the key and nonce, then XORs that
keystream with the plaintext to produce the ciphertext. If the same nonce is reused with
the same key, the same keystream is generated twice. An attacker who captures both
ciphertexts can XOR them together — the keystream cancels out completely — leaving the
XOR of the two plaintexts, enough to recover both messages. Confidentiality is fully
broken.

It doesn't stop there. GCM's authentication tag is also derived using the same nonce, so
reuse gives an attacker enough material to forge valid authentication tags on arbitrary
messages. That kills integrity as well.

This is why it's called "catastrophic" — one nonce reuse doesn't just weaken the
encryption, it invalidates both security guarantees AES-GCM is built on. Nonces here are
generated with a cryptographically secure random generator and sized at 96 bits, making
accidental collision computationally negligible.

**Code anchors:**
- 96-bit CSPRNG nonce per operation: `Encrypt` — `crypto.go:270-273`
- Stream base nonce per file: `EncryptStream` — `crypto.go:313-316`
- Chunk-nonce uniqueness without storing N nonces: `chunkNonce` XORs a big-endian u64
  counter into the last 8 bytes of the base nonce — `crypto.go:284-293`
- Nonce length validated before open: `Decrypt` — `crypto.go:238-240`

### 5. DEK vs KEK — why envelope encryption; why not encrypt every document directly with the KEK

The DEK/KEK split follows the envelope encryption pattern — each document is encrypted
with its own unique DEK, and the DEK itself is wrapped (encrypted) by the KEK. The KEK
never touches document data directly.

Two concrete reasons:

1. **Blast radius.** One key encrypting every document means one compromised key exposes
   everything simultaneously. With envelope encryption, a compromised KEK exposes only
   the wrapped DEKs — the documents themselves remain protected until each DEK is
   individually unwrapped.
2. **Key rotation.** If the KEK encrypted documents directly, rotating it would mean
   re-encrypting every document — potentially millions of files. With the split,
   rotation only re-wraps DEKs under the new KEK. Documents are never touched, making
   rotation fast, cheap, and operationally realistic.

Performance point: the KEK only ever encrypts small, fixed-size DEKs, keeping key
management operations lightweight regardless of how large or numerous documents are.

**Code anchors:**
- Per-document 256-bit DEK: `GenerateDEK` — `crypto.go:177-183`
- Wrap/unwrap primitives: `WrapDEK` / `UnwrapDEK` — `crypto.go:215-223`
- Upload: fresh DEK per file, streamed encryption, envelope wrap — `handlers/upload.go` (DEK :95, wrap :130)
- Download: unwrap DEK, stream-decrypt — `handlers/download.go` (:76, :85)
- Rotation realized exactly as described: `RotateMasterKey` unwraps→re-wraps each DEK
  without touching ciphertext — `handlers/recovery.go:174-305`; `UpdateDEK` — `services/metadata/store.go:299-308`

---

## Part II — Auth Architecture

### 6. Why the KEK never goes in the JWT — the actual attack, not just "it's a rule"

JWTs live on the client — localStorage or cookies, both readable by JavaScript. A single
XSS vulnerability anywhere lets injected script read the JWT, extract the KEK, and
exfiltrate it silently. At that point the attacker can unwrap every DEK and decrypt every
document offline, with no further access to the system — permanent damage surviving
session expiry.

Beyond XSS, JWTs travel in every HTTP request header, meaning the KEK would pass through
load balancers, reverse proxies, CDN edges, and application logs on every request. Any
one capturing headers writes the KEK to a log file in plaintext.

The KEK belongs in server-side memory only — derived at login, used to unwrap the DEK
for the operation at hand, then discarded. It should never leave the server boundary.
The JWT is an identity and authorization token, not a key transport mechanism.

**Code anchors (defense-in-depth realized twice over):**
- JWT claims carry only an opaque random session token, zero key material: `Claims{SessionToken}` — `handlers/auth.go:35-38`
- Server-side indirection: middleware resolves token → session (holding the key) — `middleware/auth.go:57-67`
- Key material injected into request context server-side only: `ctx = context.WithValue(..., KEKKey, session.KEK)` — `middleware/auth.go:65-67`
- HS256-only parsing rejects algorithm-confusion (`alg:none`, RS↔HS swap): `handlers/auth.go:388-402` and mirrored in `middleware/auth.go:88-100`
- Cookies are HttpOnly+Secure+SameSite=Strict: `handlers/auth.go:421-431`

### 7. What happens to all user state if the server restarts — and why that's acceptable for v0.1

When the server restarts, all in-memory state is wiped — active sessions and every KEK
currently held in memory are gone. Persistent data in SQLite is unaffected, but every
logged-in user is effectively kicked out. Their next request fails, they re-authenticate,
and the KEK is re-derived from their password and KEK salt as normal.

This is an acceptable tradeoff for v0.1 because the consequence is a UX inconvenience,
not a security or data-integrity failure. No data is lost, no keys are compromised, and
the security model remains completely intact after restart. Solving this properly —
session persistence, encrypted session stores, or distributed key management — adds
significant infrastructure complexity that isn't justified at this stage. For a first
version, forced re-login on restart is a clean, honest limitation.

**Code anchors:**
- Explicitly documented as in-memory: `services/auth/session.go:20-22`
- Store design: `sessions map[string]*Session` behind `sync.RWMutex` with 5-min GC loop — `session.go:26-77`
- Restart consequence chain: valid JWT → dead session → identical `401 unauthorized` — `middleware/auth.go:57-63`
- Recovery path is exactly re-login → re-derive: `handlers/auth.go:236-239`

### 8. Authentication vs authorization — Stage 4 required both

Authentication answers **"who are you"** — verifying the password against the PHC string,
deriving the KEK, and issuing a signed JWT representing a confirmed identity.

Authorization answers **"what are you allowed to do"** — checked on every subsequent
request by inspecting JWT claims/session validity against the resource being accessed.
A valid JWT gets you past authentication, but doesn't grant access to every document in
the system.

Stage 4 needed both because they solve different problems. Authentication ensures you're
talking to a real, verified user. Authorization ensures that user can only reach documents
they own or have been explicitly granted access to — a legitimate user accessing another
user's document must be blocked at the authorization layer, not the authentication layer.

**Code anchors:**
- Authentication: password verify → derive → unwrap → issue session (`handlers/auth.go:210-251`)
- Per-request authentication gate: `middleware.Auth` — `middleware/auth.go:42-70`
- Authorization realized as ownership scoping *in SQL*: `GetByID(id, userID)` filters on
  `user_id` so foreign documents look like 404s — `services/metadata/store.go:147-181`,
  used by download `handlers/download.go:61-65`, delete `handlers/delete.go:43`, search
  `handlers/search.go:56` + `store.Search` FTS JOIN scoped by user_id
- Cross-user isolation is test-enforced: cross-user tests in `handlers/download_test.go`,
  `services/metadata/store_test.go`

### 9. Why `subtle.ConstantTimeCompare` exists and what timing attacks are

Standard string comparison functions short-circuit — they bail out the moment they find a
mismatching byte. A wrong guess failing on byte 1 returns faster than one failing on byte
10. An attacker who can send controlled inputs and precisely measure response times can
exploit those nanosecond differences to determine how many bytes they've guessed
correctly, then brute-force the correct value one byte at a time.

`subtle.ConstantTimeCompare` eliminates this by always comparing every byte regardless of
where a mismatch occurs. It always runs to completion, so every comparison takes the same
amount of time — there is no timing signal left to extract.

In this system it matters anywhere sensitive values are compared — verification blobs,
authentication tags, derived tokens. These are exactly the values an attacker would want
to probe; a standard equality check there would silently open a side channel even if
everything else were correctly implemented.

**Code anchors:**
- The one production comparison of secret-derived data: `subtle.ConstantTimeCompare(actualHash, expectedHash)` — `crypto.go:126`
- Complementary anti-leak pattern: `VerifyKEK` returns bare `bool` with silent failure — `crypto.go:206-212`; login collapses unknown-email and wrong-password into identical `401 invalid credentials` — `handlers/auth.go:208-233` (anti-enumeration)

---

## Part III — Go Specifically

### 10. Why `sync.RWMutex` and not `sync.Mutex`

`sync.Mutex` locks exclusively on every operation — reads block other reads, and reads
block writes. That's unnecessarily restrictive when most operations are reads.

`sync.RWMutex` makes a practical distinction: multiple goroutines can hold a read lock
simultaneously, but a write lock is exclusive and blocks everything else. This matters
because the session store is read on every authenticated request but only written on
login/logout — a heavily read-dominant workload. A plain Mutex there means every
concurrent request queues behind each other even when all they do is read.

RWMutex gives safe concurrent reads without contention while still guaranteeing writes
are fully isolated. The right choice always comes down to the read/write ratio.

**Code anchors:**
- `mu sync.RWMutex` on SessionStore; `Get` takes RLock only — `services/auth/session.go:96-107`; `Save`/`Delete` take Lock — `:82-86`, `:112-115`
- Contrast case: rate limiter uses plain `sync.Mutex` because its workload is write-only
  (every request mutates counters) — `middleware/ratelimit.go:17-23`. Good thesis contrast pair.

### 11. What a context is and why the KEK travels through it rather than as a function argument

Original note was a question to be answered; answered now for the thesis:

`context.Context` is Go's standard request-scoped value-and-cancellation carrier. In an
HTTP server each request gets its own context that flows through middleware into handlers
and is cancelled when the request completes or the client disconnects.

The key travels through context rather than arguments for three reasons:
1. **Uniform middleware injection** — auth middleware stamps identity + key material once;
   every handler downstream (`upload.go:57`, `download.go:47`, `recovery.go:110`) reads it
   the same way without signature changes threading the key through every call.
2. **Lifecycle correctness** — context values die with the request, mirroring the
   "key exists only inside the session/request" lifecycle from §2.
3. **Type-safe keys** — unexported `contextKey struct{ name string }` prevents any other
   package from forging or reading these values by accident — `middleware/auth.go:15-23`.

Caveat for thesis: Go docs discourage storing large secrets in context; here it's accepted
because values live only for the request duration and are never logged.

**Code anchors:** key definitions `middleware/auth.go:15-23`; accessors `KEKFromContext` /
`UserIDFromContext` `:76-86`; consumers listed above.

### 12. What `defer` does and why it matters on mutex unlocks specifically

`defer` schedules a function call to run when the surrounding function returns — however
it returns: normal return, early return, or panic. On mutex unlocks this is critical:
if you unlock manually and an early return or panic slips in between lock and unlock,
the mutex stays locked forever and every subsequent goroutine deadlocks.

With `defer mu.Unlock()`, the unlock is guaranteed exactly once at function exit no
matter the exit path. The tiny cost of deferring is worth eliminating an entire class of
deadlock bugs. Forgetting it means one panic path silently freezes the whole store —
in this project, every authenticated request in the system depends on the session-store
mutex being releasable.

**Code anchors:** SessionStore methods lock/unlock within single short functions
(`session.go:82-115`) keeping critical sections minimal; GC loop and `Close()` coordinate
via channel rather than holding locks across long operations (`session.go:55-66`).

### 13. Interface-driven design — stores should be interfaces so Stage 4+ handlers are testable without a real DB

Handlers already depend on the `StorageConnector` interface
(`connectors/connector.go:9-14`: Upload/Download/Delete/Ping), which enabled the
hand-written `mockConnector` in `handlers/upload_test.go:24-61` — no filesystem needed.

Remaining concrete dependencies (thesis: evolution path):
- `*authsvc.UserStore`, `*authsvc.SessionStore`, `*metadata.Store` are passed as concrete
  struct pointers into handler constructors (`main.go:98-102`). Extracting
  `UserStore`/`SessionStore`/`MetadataStore` interfaces is the natural next step so
  handler tests run without real SQLite and so alternative backends (Postgres, Redis
  sessions) slot in unchanged.

---

## Part IV — HTTP

### 14. Why `HttpOnly` cookies block JavaScript access and why that matters here

`HttpOnly` is a cookie attribute instructing the browser to expose the cookie to HTTP(S)
requests only — `document.cookie` and all other JS access return nothing for it. Even if
XSS injects script, the script cannot read the token out of the cookie jar.

Why it matters for DocOps specifically: the access token is the *only* client-visible
secret. All key material lives server-side (§6). HttpOnly enforces that boundary at the
browser level — the client literally cannot hold what it cannot hold. Combined with the
opaque session-token indirection (§6), stealing the cookie yields a hijackable-but-bounded
session, never keys.

**Code anchors:** `setHttpOnlyCookie` sets `HttpOnly=true; Secure=true; SameSite=Strict;
Path=/` — `handlers/auth.go:421-431`; clearing mirrors attributes with `MaxAge=-1` — `:437-447`.

### 15. What `SameSite: Strict` prevents

SameSite=Strict tells the browser not to attach the cookie to any cross-site request —
including top-level navigations from other origins. This defeats CSRF outright: a
malicious page at evil.com triggering POST /v0.1/docs/upload via auto-submitted form or
fetch cannot carry the victim's cookies, so the forged request arrives unauthenticated.

Tradeoff noted for thesis: Strict also drops cookies on legitimate inbound links from
other sites (e.g., clicking a doc link from email requires a fresh in-site navigation);
chosen anyway because DocOps is API-first, not link-driven, so CSRF immunity outweighs
the UX edge case.

**Code anchors:** `http.SameSite(http.SameSiteStrictMode)` — `handlers/auth.go:421-431`.

### 16. 401 vs 403 — both needed in Stage 4+

- **401 Unauthorized** = "I don't know who you are." No/invalid/expired credentials.
  Fixable by re-authenticating.
- **403 Forbidden** = "I know who you are; you may not do this." Identity established,
  permission denied. Re-authenticating won't help.

In DocOps today: 401 covers the entire auth gate (`middleware/auth.go:39-41` — missing
cookie, bad JWT, expired/dead session all collapse to detail-free 401). Authorization
failures are deliberately surfaced as **404, not 403**, on document routes
(`download.go:61-65`, delete) — revealing existence of another user's document leaks
information; a non-existent and a foreign document are indistinguishable. Thesis point:
the classic 401/403 dichotomy refined into 401 vs 404-by-design, trading REST purity for
enumeration resistance.

### 17. Why error responses are deliberately vague

Every ambiguous failure returns one generic message: `401 invalid credentials` whether
the email exists or the password is wrong (`handlers/auth.go:208-233`, recovery
`recovery.go:46-49`); `VerifyKEK` returns bare false with no reason (`crypto.go:206-212`);
document misses are uniform 404s. What's protected against:

1. **User enumeration** — attackers harvest valid emails by differing error messages.
2. **Oracle attacks** — detailed crypto errors ("bad nonce length", "GCM auth failed")
   tell an attacker exactly which layer failed and guide tampering.
3. **Existence leaks** — 404-uniformity hides which docIDs belong to other users.

Cost acknowledged: vaguer errors complicate legitimate debugging — compensated by
server-side structured logging (`slog` in main.go) where operators see detail clients
never do.

---

## Part V — Testing

### 18. Unit vs integration tests — what each actually proves

- **Unit tests** prove a component satisfies its contract in isolation. Here:
  `services/crypto/crypto_test.go` (25 tests — salt uniqueness, KEK determinism, nonce
  uniqueness, tamper rejection, stream round-trips) proves the cryptographic primitives
  behave correctly given correct inputs.
- **Integration tests** prove components work *together*: real in-memory SQLite +
  httptest + real handler wiring. `handlers/*_test.go` (68 tests) prove that upload
  really persists ciphertext retrievable by download, that auth middleware + session
  store + handler compose, and that cross-user isolation holds through the full stack.

Neither subsumes the other: unit tests localize failures precisely; integration tests
catch wiring/lifecycle bugs units cannot see (e.g., stored bytes ≠ plaintext verified at
`download_test.go:364`).

### 19. Why `testParams` uses weak Argon2id settings — correct for tests, wrong for production

Production params (m=65536 KiB, t=3, p=2) cost ~64 MiB and ~100 ms per derivation. With
hundreds of tests deriving KEKs repeatedly, suites would take minutes and hammer memory.
Tests use m=1024/t=1/p=1-style minimal params (`handlers/auth_test.go:22-28`) because
tests verify *logic* (correct unwrap flow, mismatch detection), not KDF strength — Argon2id
with any consistent parameters produces deterministic keys, so weak params exercise
identical code paths in milliseconds.

Why never in production: memory-hardness is the entire anti-brute-force argument (§2).
Weak params make offline cracking cheap; the security property lives in the constants,
not the code shape. Config makes production values tunable (`models/config.go:28-34`),
tests override downward — same mechanism, opposite ends.

### 20. The race detector (`go test -race`) — why SessionStore tests especially

The race detector instruments memory accesses at compile time and flags unsynchronized
concurrent access to the same address from multiple goroutines — races invisible to
functional tests yet undefined-behavior-in-waiting under real load.

SessionStore is the concurrency hotspot: every authenticated request calls `Get`
(RLock), logins/logouts call `Save`/`Delete` (Lock), plus the background GC goroutine
mutating the same map every 5 minutes. A missed lock might survive years of sequential
testing then corrupt the map under load — worst case, returning another user's session.
Race coverage lives in `services/auth/session_test.go` (9 concurrent tests); full suite:
`go test -race -tags fts5 ./...`.

---

## Part VI — Deep System Analysis (2026-08-24)

Findings from full-codebase analysis that must inform `thesis.md`.

### A. Actual key hierarchy (three tiers, not two)

```
Password ──Argon2id──► Password-KEK ──AES-GCM-wrap──► Master Key (32 B CSPRNG)
                                                          │
Recovery Key ("docops_rec_…") ──Argon2id(salt#3)──► Recovery-KEK
                                          (second wrap of SAME Master Key)
                                                          ▼
                                        AES-GCM-wrap ──► per-document DEK (32 B CSPRNG)
                                                          │
                                    AES-256-GCM chunked stream ──► file ciphertext on disk
```

The original two-salt rationale (§1) is still true but now generalizes to *N* independent
derivations with *N* salts; recovery added a third domain.

### B. Naming collision (must be resolved in thesis prose)

`Session.KEK`, `KEKFromContext`, etc., hold the **Master Key**, not the password-derived
KEK. The password-KEK exists only transiently inside Login/Recover/ChangePassword.
Thesis should either rename code or define terms precisely once, early, then be
consistent: *password-KEK* (wraps master key), *master key* (wraps document DEKs),
*DEK* (encrypts one document).

### C. The canonical upload walkthrough (the "readiness question", answered from code)

POST /v0.1/docs/upload → middleware.Auth resolves JWT→session→injects master key + userID
into context → handler pulls key via `KEKFromContext` (`upload.go:57`) → parse multipart
(10 MB memory cap) → `GenerateDEK()` fresh 32-B DEK (`:95`) → `storageKey = uuid` (`:105`)
→ `EncryptStream(file, pw, dek)` in a goroutine through an `io.Pipe`: 64 KB chunks, each
GCM-sealed under a counter-derived nonce; single random base nonce returned (`:111-124`)
→ `WrapDEK(dek, masterKey)` envelope-wraps the DEK (`:130`) → connector streams ciphertext
to disk under opaque UUID name (`:139-146`) → metadata row saved: storage_key,
encrypted_dek, dek_nonce, file_nonce, user_id (`:162-186`) → 201 with whitelisted fields
only (`:194-202`). Keys touched, in order: **master key (context) → new DEK → wrapped
DEK stored; file bytes never touch a long-lived key**. Failure paths clean up orphaned
ciphertext (`:153-157`, `:183`).

### D. Download mirror

Ownership-scoped metadata fetch → `UnwrapDEK(doc.EncryptedDEK, doc.DEKNonce, kek)`
(`download.go:76`) → `DecryptStream(dataStream, doc.FileNonce, dek)` (`:85`) → `io.Copy`
to response; each 64 KB chunk authenticated before plaintext release
(`decryptReader`, `crypto.go:348-398`).

### E. Known gaps to acknowledge (honesty section of thesis)

1. Verification blob dead code / stale Login doc comment (§3 drift).
2. Config TTLs parsed but unused; hardcoded constants win (`handlers/auth.go:22-25`).
3. Rate limiter trusts `X-Forwarded-For`/`X-Real-IP` verbatim — spoofable unless behind
   sanitizing proxy (`middleware/ratelimit.go:76-80`).
4. `RotateMasterKey` re-wraps DEKs non-atomically (no transaction) — crash mid-loop leaves
   mixed old/new wraps (`recovery.go:227-244`).
5. KEK zeroization on session end is aspirational in Go (GC moves byte slices; not yet
   implemented as explicit wipe) — phrase carefully in thesis.
6. No AAD binding ciphertext to document IDs anywhere (`crypto.go:257-259` notes this).

### F. Stack facts for thesis intro

Go 1.25 · chi v5 · golang-jwt/v5 (HS256-only) · Argon2id (golang.org/x/crypto) ·
SQLite + FTS5 external-content index with ai/ad triggers · mattn/go-sqlite3 CGO ·
~140 tests across 7 packages · Alpha/v0.1 · MIT.

---

## Part VII — Readiness Question (keep verbatim; use as thesis §"Cryptographic Walkthrough")

> *A user uploads a document. Walk me through exactly what happens cryptographically from
> the moment the handler receives the request to the moment something gets written to the
> database — every key, every encryption operation, in order.*

Answered against real code in Part VI-C above. Stage 4+ work is that answer written in Go.

---

## Instructions for future thesis.md writing session

1. Weave Parts I–V verbatim rationales into their respective design chapters, replacing
   generic claims with the anchored file:line citations.
2. Resolve the Drift markers: describe v0.1 as-built (implicit GCM unwrap proof, three-tier
   hierarchy), cite original rationale as the design intent evolution.
3. Use Part VI-E as the "Limitations & Future Work" skeleton.
4. Use Part VI-C/D as the core "System Design → Data Flow" chapter.
5. Keep tone: first-person engineering rationale (these notes' voice), evidence-backed.
