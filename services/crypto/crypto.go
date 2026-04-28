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


var ErrInvalidHash     = errors.New("invalid hash format")
var ErrMismatch        = errors.New("password does not match")

func VerifyPassword(password, encoded string) (*models.EncryptParams, error) {
    // Parse the PHC string format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
    parts := strings.Split(encoded, "$")
    if len(parts) != 6 {
        return nil, ErrInvalidHash
    }

    // Extract and validate the Argon2 version (e.g. v=19)
    var version int
    if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
        return nil, ErrInvalidHash
    }

    // Extract memory (m), iterations/time (t), and parallelism/threads (p)
    var p models.Argon2idParams
    if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
        &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
        return nil, ErrInvalidHash
    }

    // Decode the base64-encoded salt
    salt, err := base64.RawStdEncoding.DecodeString(parts[4])
    if err != nil {
        return nil, ErrInvalidHash
    }

    // Decode the base64-encoded expected hash
    expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
    if err != nil {
        return nil, ErrInvalidHash
    }

    // Derive key length from the expected hash length
    p.KeyLength = uint32(len(expectedHash))

    // Recompute the hash using the same params + salt against the provided password
    actualHash := argon2.IDKey(
        []byte(password),
        salt,
        p.Iterations,  // time cost
        p.Memory,      // memory cost
        p.Parallelism, // threads
        p.KeyLength,
    )

    // Constant-time comparison to prevent timing attacks
    // (regular == comparison leaks info about where bytes differ)
    if subtle.ConstantTimeCompare(actualHash, expectedHash) != 1 {
        return nil, ErrMismatch
    }

    return &models.EncryptParams{Salt: salt}, nil
}

// ParsePHCString extracts the raw hash from a PHC-formatted string
func ParsePHCString(phcString string) ([]byte, error) {
    parts := strings.Split(phcString, "$")
    if len(parts) != 6 {
        return nil, fmt.Errorf("invalid PHC string format")
    }
    
    // Last part is the hash (base64 encoded)
    hashBase64 := parts[5]
    return base64.RawStdEncoding.DecodeString(hashBase64)
}

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

func GenerateSalt() ([]byte, error) {
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return nil, fmt.Errorf("failed to generate salt: %w", err)
    }
    return salt, nil
}

func GenerateDEK() ([]byte, error) {
    dek := make([]byte, 32)
    if _, err := rand.Read(dek); err != nil {
        return nil, fmt.Errorf("failed to generate DEK: %w", err)
    }
    return dek, nil
}

// called once at registration — store the result in DB
func CreateVerificationBlob(kek []byte) ([]byte, []byte, error) {
    ciphertext, nonce, err := Encrypt([]byte("docops-verify-v1"), kek)
    if err != nil {
        return nil, nil, err
    }
    return ciphertext, nonce, nil
}

// called at login — proves the derived KEK is correct
// DB stores for each user:
// verification_blob  []byte  (ciphertext)
// verification_nonce []byte  (nonce used when encrypting blob)
func VerifyKEK(kek, blob, nonce []byte) bool {
    plaintext, err := Decrypt(blob, nonce, kek)
    if err != nil {
        return false
    }
    return string(plaintext) == "docops-verify-v1"
}


func Decrypt(blob, nonce, kek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err // return it, don't swallow it
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


func Encrypt(plaintext, key []byte) (ciphertext, nonce []byte, err error) {

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
    }
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
 
	// 2. Generate nonce
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil,fmt.Errorf("failed to generate nonce: %w", err)
	}


	// 3. AAD (optional)
	var aad []byte = nil

	// Encrypt
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	//fmt.Println("Ciphertext:", base64.StdEncoding.EncodeToString(ciphertext))

	return ciphertext, nonce, nil
}


