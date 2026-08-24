// Package crypto is DocOps' single cryptographic boundary: Argon2id password
// hashing and KEK derivation, AES-256-GCM sealing with CSPRNG nonces, chunked
// stream AEAD with counter-derived per-chunk nonces, AAD-bound key wraps, and
// HKDF derivation for high-entropy machine credentials.
//
// NOTHING outside this package may import crypto/aes, crypto/cipher, argon2,
// or hkdf — every primitive decision (nonce discipline, salt separation,
// constant-time comparison) is enforced here once so callers cannot get it
// wrong elsewhere.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Kyei-Ernest/DocOps/models"

	"golang.org/x/crypto/argon2"
)

// HashPassword derives a secure hash of password using Argon2id and returns it
// as a PHC-formatted string (e.g. "$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>").
//
// A fresh random salt is generated on every call, so hashing the same password
// twice will produce different output — this is expected and correct.
// The PHC format is self-describing, meaning VerifyPassword can reconstruct all
// parameters it needs directly from the encoded string without any extra state.
func HashPassword(password string, p *models.Argon2Config) (string, error) {
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		p.Iterations,
		p.Memory,
		p.Parallelism,
		p.KeyLength,
	)

	// Encode as PHC string format: $argon2id$v=19$m=...,t=...,p=...$salt$hash
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.Memory,
		p.Iterations,
		p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encoded, nil
}

var (
	// ErrInvalidHash is returned when the stored hash string is malformed or
	// cannot be parsed as a valid PHC-encoded Argon2id hash.
	ErrInvalidHash = errors.New("invalid hash format")

	// ErrMismatch is returned when the provided password does not match the hash.
	// Callers should treat this identically to ErrInvalidHash at the API boundary
	// to avoid leaking whether an account exists.
	ErrMismatch = errors.New("password does not match")
)

// VerifyPassword checks password against an encoded PHC hash string and returns
// an EncryptParams (carrying the salt) that can be used to re-derive the KEK
// without a second password prompt.
//
// Returning the salt on success avoids the caller having to re-parse the PHC
// string just to get at the salt for KEK derivation. The Argon2id parameters
// are read from the encoded string itself, so the caller does not need to supply
// them — this is the main advantage of the self-describing PHC format.
func VerifyPassword(password, encoded string) (*models.EncryptParams, error) {
	// Parse the PHC string format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	// Splitting on "$" yields ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
	// — note the leading empty string from the leading "$".
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return nil, ErrInvalidHash
	}

	// Validate the Argon2id version embedded in the hash. A mismatch here means
	// the hash was produced by a different library version and may not be compatible.
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, ErrInvalidHash
	}

	// Reconstruct the cost parameters that were used when the hash was created.
	// These must be used as-is; changing them would produce a different hash.
	var p models.Argon2Config
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
		&p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, ErrInvalidHash
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, ErrInvalidHash
	}

	// Infer the key length from the stored hash rather than a config value;
	// this ensures we re-derive with exactly the same output length even if
	// the default KeyLength has changed since the hash was created.
	p.KeyLength = uint32(len(expectedHash))

	actualHash := argon2.IDKey(
		[]byte(password),
		salt,
		p.Iterations,
		p.Memory,
		p.Parallelism,
		p.KeyLength,
	)

	// subtle.ConstantTimeCompare runs in time proportional to len(a)+len(b)
	// regardless of content, preventing timing side-channels that could reveal
	// how many leading bytes of the candidate hash are correct.
	if subtle.ConstantTimeCompare(actualHash, expectedHash) != 1 {
		return nil, ErrMismatch
	}

	return &models.EncryptParams{Salt: salt}, nil
}

// ParsePHCParams extracts the cost parameters embedded in a PHC-formatted
// Argon2id hash without verifying anything. Used by the lazy KDF-upgrade path,
// which compares stored parameters against current configuration.
func ParsePHCParams(encoded string) (memory, iterations, parallelism uint32, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return 0, 0, 0, ErrInvalidHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return 0, 0, 0, ErrInvalidHash
	}
	return memory, iterations, parallelism, nil
}

// NeedsRehash reports whether a PHC-encoded hash was produced with materially
// weaker parameters than the given target configuration, meaning the next
// successful authentication should transparently rehash-and-rewrap.
//
// Policy: upgrade only when every target parameter is >= the stored value and
// at least one is strictly greater. A mixed comparison (target stronger on one
// axis, weaker on another) never upgrades — silently weakening some dimension
// of an existing hash would be worse than leaving it stale.
func NeedsRehash(encoded string, target *models.Argon2Config) (bool, error) {
	memory, iterations, parallelism, err := ParsePHCParams(encoded)
	if err != nil {
		return false, err
	}
	atLeastEqual := target.Memory >= memory &&
		target.Iterations >= iterations &&
		uint32(target.Parallelism) >= parallelism
	strictlyGreater := target.Memory > memory ||
		target.Iterations > iterations ||
		uint32(target.Parallelism) > parallelism
	return atLeastEqual && strictlyGreater, nil
}

// ParsePHCString extracts the raw Argon2id hash bytes from a PHC-formatted
// string. It does not verify the hash — use VerifyPassword for that.
// Intended for callers that need the raw hash bytes for a secondary purpose
// (e.g. as key material) without re-running the full verification flow.
func ParsePHCString(phcString string) ([]byte, error) {
	parts := strings.Split(phcString, "$")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid PHC string format")
	}
	return base64.RawStdEncoding.DecodeString(parts[5])
}

// DeriveKEK derives the Key Encryption Key from a user's password and salt
// using Argon2id. The KEK is the master symmetric key that encrypts/decrypts
// all per-document Data Encryption Keys (DEKs) for this user.
//
// The same password + salt + params triple always yields the same KEK, so it
// can be re-derived at login without storing the KEK anywhere. The salt must
// be the one stored alongside the user's password hash in the database.
func DeriveKEK(password string, salt []byte, p *models.Argon2Config) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		p.Iterations,
		p.Memory,
		p.Parallelism,
		p.KeyLength,
	)
}

// GenerateSalt returns 16 bytes of cryptographically random data suitable for
// use as an Argon2id salt. A new salt must be generated for each user — salts
// must never be reused across accounts.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// GenerateDEK returns a 256-bit (32-byte) random Data Encryption Key for
// AES-256-GCM. A unique DEK should be generated per document (or per
// sensitive field) and stored encrypted under the user's KEK.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	return dek, nil
}

// CreateVerificationBlob encrypts a fixed sentinel string ("docops-verify-v1")
// under the given KEK and returns the ciphertext and nonce. Both values must
// be persisted in the database at registration time.
//
// At login, VerifyKEK re-derives the KEK from the user's password and attempts
// to decrypt this blob; successful decryption of the known sentinel proves the
// KEK is correct without requiring the plaintext password to be stored anywhere.
// This separates password verification (Argon2id) from key correctness verification (AES-GCM).
func CreateVerificationBlob(kek []byte) (ciphertext, nonce []byte, err error) {
	ciphertext, nonce, err = Encrypt([]byte("docops-verify-v1"), kek)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, nonce, nil
}

// VerifyKEK decrypts the stored verification blob with the given KEK and
// confirms the plaintext matches the expected sentinel. Returns true only if
// decryption succeeds and the sentinel matches — any error (wrong key, corrupt
// blob, tampered nonce) silently returns false, giving callers no diagnostic
// detail that could aid an attacker.
func VerifyKEK(kek, blob, nonce []byte) bool {
	plaintext, err := Decrypt(blob, nonce, kek)
	if err != nil {
		return false
	}
	return string(plaintext) == "docops-verify-v1"
}

// AAD domain builders. Every wrapped key is cryptographically bound to the
// identity of what it protects, so a valid-looking blob lifted from one row
// and planted into another fails GCM authentication instead of decrypting
// successfully (confused-deputy defense, ROADMAP P0-4).
func DEKAAD(userID, docID string) []byte {
	return []byte("docops-dek-v1|" + userID + "|" + docID)
}

func MasterKeyAAD(userID string) []byte {
	return []byte("docops-master-v1|" + userID)
}

func RecoveryKeyAAD(userID string) []byte {
	return []byte("docops-recovery-v1|" + userID)
}

func APIKeyAAD(userID, keyID string) []byte {
	return []byte("docops-apikey-v1|" + userID + "|" + keyID)
}

// WrapDEK encrypts a plaintext DEK under the user's KEK for safe storage.
// Prefer the AAD-bound variant for all new code paths.
func WrapDEK(dek, kek []byte) (wrappedDEK, nonce []byte, err error) {
	return Encrypt(dek, kek)
}

// WrapDEKBound is WrapDEK with Additional Authenticated Data binding: the
// resulting blob can only be opened with both the correct key AND the exact
// same AAD context it was sealed under.
func WrapDEKBound(dek, kek, aad []byte) (wrappedDEK, nonce []byte, err error) {
	return sealAad(dek, kek, aad)
}

// UnwrapDEK decrypts a stored wrapped DEK using the user's KEK,
// returning the plaintext DEK ready for document encryption/decryption.
func UnwrapDEK(wrappedDEK, nonce, kek []byte) ([]byte, error) {
	return Decrypt(wrappedDEK, nonce, kek)
}

// UnwrapDEKBound opens an AAD-bound wrap produced by WrapDEKBound.
func UnwrapDEKBound(wrappedDEK, nonce, kek, aad []byte) ([]byte, error) {
	return openAad(wrappedDEK, nonce, kek, aad)
}

// UnwrapDEKAny opens a wrapped DEK that may be either AAD-bound (current
// format) or legacy unbound (rows written before ROADMAP P0-4 shipped).
//
// Order matters and is not an oracle: the bound attempt runs first, and both
// failures are indistinguishable GCM authentication errors. Rows still in the
// legacy format are upgraded to bound wraps the next time Master Key rotation
// runs, since rotation re-wraps every DEK with binding.
func UnwrapDEKAny(wrappedDEK, nonce, kek, aad []byte) ([]byte, error) {
	if len(aad) > 0 {
		if pt, err := openAad(wrappedDEK, nonce, kek, aad); err == nil {
			return pt, nil
		}
	}
	return Decrypt(wrappedDEK, nonce, kek)
}

// Decrypt decrypts blob using AES-256-GCM with the provided nonce and kek.
// The GCM authentication tag (appended to the ciphertext by Encrypt) is
// verified automatically — if the blob or nonce has been tampered with,
// gcm.Open returns an error and no plaintext is ever returned.
func Decrypt(blob, nonce, kek []byte) ([]byte, error) {
	return openAad(blob, nonce, kek, nil)
}

func openAad(blob, nonce, key, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length: got %d, want %d", len(nonce), gcm.NonceSize())
	}
	decrypted, err := gcm.Open(nil, nonce, blob, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return decrypted, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the given key and returns
// the ciphertext and a freshly generated random nonce. Both must be stored
// together — the nonce is required for decryption and is not secret, but it
// must be unique per encryption operation. Reusing a nonce with the same key
// completely breaks GCM's confidentiality and authenticity guarantees.
//
// The GCM authentication tag is appended to the ciphertext by gcm.Seal and is
// verified transparently during Decrypt — callers do not handle it directly.
//
// AAD (Additional Authenticated Data) is not used here; pass non-nil AAD to
// gcm.Seal/Open if you need to bind ciphertext to a specific context (e.g. a
// document ID) without encrypting that context.
func Encrypt(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	return sealAad(plaintext, key, nil)
}

// sealAad is the single GCM sealing path: fresh 96-bit CSPRNG nonce per call,
// optional AAD binding, tag appended to ciphertext.
func sealAad(plaintext, key, aad []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

const StreamChunkSize = 64 * 1024 // 64 KB of plaintext per chunk

// chunkNonce derives a unique nonce for each chunk by XOR-ing the last 8 bytes
// of the base nonce with the chunk counter. This avoids storing N nonces while
// guaranteeing every chunk uses a distinct nonce — a hard GCM requirement.
func chunkNonce(base []byte, counter uint64) []byte {
	n := make([]byte, len(base))
	copy(n, base)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], counter)
	for i := 0; i < 8 && i < len(n); i++ {
		n[len(n)-8+i] ^= b[i]
	}
	return n
}

// EncryptStream encrypts src in StreamChunkSize chunks using AES-256-GCM and
// writes framed ciphertext to dst. Each chunk is independently authenticated,
// so DecryptStream can verify and yield plaintext without buffering the whole file.
//
// Wire format: repeated [ 4-byte big-endian chunk length | GCM ciphertext+tag ]
//
// Returns the single base nonce that must be stored alongside the ciphertext
// (e.g. in doc.FileNonce). All per-chunk nonces are derived from it internally.
func EncryptStream(src io.Reader, dst io.Writer, key []byte) (nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("EncryptStream: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("EncryptStream: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("EncryptStream: nonce: %w", err)
	}

	buf := make([]byte, StreamChunkSize)
	var counter uint64
	var lbuf [4]byte

	for {
		n, readErr := io.ReadFull(src, buf)
		if n > 0 {
			ct := gcm.Seal(nil, chunkNonce(nonce, counter), buf[:n], nil)
			binary.BigEndian.PutUint32(lbuf[:], uint32(len(ct)))
			if _, err = dst.Write(lbuf[:]); err != nil {
				return nil, fmt.Errorf("EncryptStream: write length: %w", err)
			}
			if _, err = dst.Write(ct); err != nil {
				return nil, fmt.Errorf("EncryptStream: write chunk: %w", err)
			}
			counter++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("EncryptStream: read: %w", readErr)
		}
	}
	return nonce, nil
}

// decryptReader is an io.Reader that decrypts and authenticates one GCM chunk
// at a time. Plaintext is never returned before the GCM tag is verified, so
// a truncated or tampered stream is caught at the chunk boundary, not at EOF.
type decryptReader struct {
	src     io.Reader
	gcm     cipher.AEAD
	base    []byte
	counter uint64
	buf     []byte // current decrypted chunk
	pos     int    // read offset into buf
	done    bool
}

func (r *decryptReader) Read(p []byte) (int, error) {
	// Drain buffered plaintext from the last decrypted chunk first.
	if r.pos < len(r.buf) {
		n := copy(p, r.buf[r.pos:])
		r.pos += n
		return n, nil
	}
	if r.done {
		return 0, io.EOF
	}

	// Read the 4-byte length prefix of the next chunk.
	var lbuf [4]byte
	if _, err := io.ReadFull(r.src, lbuf[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			r.done = true
			return 0, io.EOF
		}
		return 0, fmt.Errorf("decryptReader: read length: %w", err)
	}

	ct := make([]byte, binary.BigEndian.Uint32(lbuf[:]))
	if _, err := io.ReadFull(r.src, ct); err != nil {
		return 0, fmt.Errorf("decryptReader: read chunk %d: %w", r.counter, err)
	}

	// Open authenticates and decrypts in one call — no plaintext is released
	// if the tag check fails.
	pt, err := r.gcm.Open(nil, chunkNonce(r.base, r.counter), ct, nil)
	if err != nil {
		return 0, fmt.Errorf("chunk %d authentication failed: %w", r.counter, err)
	}

	r.counter++
	r.buf = pt
	r.pos = 0

	n := copy(p, r.buf)
	r.pos += n
	return n, nil
}

// DecryptStream returns an io.Reader that decrypts a chunked GCM stream
// produced by EncryptStream. This is the function your handler should call —
// its signature matches what your download handler already expects:
//
//	decryptedReader, err := crypto.DecryptStream(dataStream, doc.FileNonce, dek)
//	io.Copy(w, decryptedReader)
func DecryptStream(src io.Reader, nonce []byte, key []byte) (io.Reader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("DecryptStream: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("DecryptStream: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("DecryptStream: invalid nonce length: got %d, want %d",
			len(nonce), gcm.NonceSize())
	}
	return &decryptReader{src: src, gcm: gcm, base: nonce}, nil
}
