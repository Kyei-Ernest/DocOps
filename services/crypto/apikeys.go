package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// APIKeyPrefix starts every DocOps API key. Recognizable prefixes let scanners
// and secret-scanning tools detect leaked keys, and let the middleware branch
// between bearer-key and cookie authentication by inspection alone.
const APIKeyPrefix = "docops_sk_"

// GeneratedAPIKey is the full result of GenerateAPIKey.
type GeneratedAPIKey struct {
	Plaintext string // "docops_sk_<key_id>_<secret>" — shown exactly once, never stored
	KeyID     string // indexed lookup component
	Secret    []byte // high-entropy secret component (32 CSPRNG bytes)
}

// GenerateAPIKey mints a fresh API key. The secret is 32 bytes of CSPRNG
// output — uniformly random, so unlike passwords it needs NO memory-hard KDF:
// brute-forcing HKDF output over a 256-bit space is computationally hopeless.
// This entropy-appropriate choice makes per-request authentication cost
// microseconds instead of an Argon2id run (~100 ms), which is what makes
// stateless bearer authentication viable on hot paths.
//
// The key ID is HEX-encoded deliberately: base64url includes `_` in its
// alphabet, and the wire format `docops_sk_<key_id>_<secret>` splits on the
// FIRST underscore — an underscore-bearing key ID would make parsing
// ambiguous for roughly a third of generated keys.
func GenerateAPIKey() (*GeneratedAPIKey, error) {
	keyID := make([]byte, 8) // 16 hex chars
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, keyID); err != nil {
		return nil, fmt.Errorf("generate key id: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}
	keyIDStr := hex.EncodeToString(keyID)
	return &GeneratedAPIKey{
		Plaintext: APIKeyPrefix + keyIDStr + "_" + base64.RawURLEncoding.EncodeToString(secret),
		KeyID:     keyIDStr,
		Secret:    secret,
	}, nil
}

// HashAPISecret produces the stored-at-rest form of an API key secret.
// SHA-256 suffices precisely because the input is 256 bits of uniform
// randomness — there is nothing to brute-force, so a slow KDF adds cost for
// defenders without slowing attackers meaningfully. Lookup is by key_id; the
// hash is compared in constant time by the caller.
func HashAPISecret(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}

const apiWrapInfo = "docops api-wrap v1"

// DeriveAPIWrapKey derives the key that wraps (and unwraps) the Master Key
// for one API key, from the presented secret and that key's stored salt.
// HKDF-SHA256 per RFC 5869; the salt is unique per API key row so identical
// secrets across rows would still derive independent wrap keys (domain
// separation, same argument as the Argon2id salt policy).
func DeriveAPIWrapKey(secret, salt []byte) ([]byte, error) {
	out := make([]byte, 32)
	k := hkdf.New(sha256.New, secret, salt, []byte(apiWrapInfo))
	if _, err := io.ReadFull(k, out); err != nil {
		return nil, fmt.Errorf("derive api wrap key: %w", err)
	}
	return out, nil
}

// ParseAPIKey splits a presented bearer credential into its lookup and secret
// components. Returns ok=false for anything malformed — callers respond with
// one generic 401 regardless of which part was wrong.
func ParseAPIKey(presented string) (keyID string, secret []byte, ok bool) {
	if len(presented) <= len(APIKeyPrefix)+1 || !startsWith(presented, APIKeyPrefix) {
		return "", nil, false
	}
	rest := presented[len(APIKeyPrefix):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '_' {
			keyID := rest[:i]
			secretB64 := rest[i+1:]
			secret, err := base64.RawURLEncoding.DecodeString(secretB64)
			if err != nil || len(keyID) == 0 || len(secret) != 32 {
				return "", nil, false
			}
			return keyID, secret, true
		}
	}
	return "", nil, false
}

func startsWith(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if s[i] != prefix[i] {
			return false
		}
	}
	return true
}
