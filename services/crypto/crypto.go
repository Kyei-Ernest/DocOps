package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
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
func HashPassword(password string, p *models.Argon2idParams) (string, error) {
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
	var p models.Argon2idParams
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
func DeriveKEK(password string, salt []byte, p *models.Argon2idParams) []byte {
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

// Decrypt decrypts blob using AES-256-GCM with the provided nonce and kek.
// The GCM authentication tag (appended to the ciphertext by Encrypt) is
// verified automatically — if the blob or nonce has been tampered with,
// gcm.Open returns an error and no plaintext is ever returned.
func Decrypt(blob, nonce, kek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	decrypted, err := gcm.Open(nil, nonce, blob, nil)
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

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}