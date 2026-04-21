package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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


func Encrypt(input string, hashed_password string) (*models.DecryptParams, error) {

	// 1. Extract raw hash bytes from PHC string
    rawHash, err := ParsePHCString(hashed_password)
    if err != nil {
        return nil, fmt.Errorf("failed to parse PHC string: %w", err)
    }
    if len(rawHash) < 32 {
        return nil, fmt.Errorf("hash too short for AES-256: got %d bytes", len(rawHash))
    }

    key := rawHash[:32] // AES-256 requires exactly 32 bytes

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %w", err)
    }
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 2. Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	plaintext := []byte(input)

	// 3. AAD (optional)
	var aad []byte = nil

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	//fmt.Println("Ciphertext:", base64.StdEncoding.EncodeToString(ciphertext))

	return &models.DecryptParams{Nonce: nonce, Ciphertext: ciphertext, AAD: aad}, nil
}


func EncryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed. Use POST", http.StatusMethodNotAllowed)
		return
	}

	
	//read and parse jason request json body
	var params models.EncryptParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Call existing Encrypt function
	encryption_result, err := Encrypt(params.Plaintext) 
	if err != nil {
		http.Error(w, "Encryption failed: "+err.Error(), http.StatusInternalServerError)
		return  // ✅ just ends this request, server stays alive
	}

	// Return successful response
	w.Header().Set("Content-Type", "application/json")  // add this before Encode
	// Correct - writes proper JSON
		if err := json.NewEncoder(w).Encode(encryption_result); err != nil {
		log.Printf("failed to encode response: %v", err)
	}

}


func Decrypt(params *models.DecryptParams) (string, error) {
	block, err := aes.NewCipher(params.Key)
	if err != nil {
		return "", err // return it, don't swallow it
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	
	decrypted, err := gcm.Open(nil, params.Nonce, params.Ciphertext, params.AAD)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	return string(decrypted), nil
}


func DecryptHandler(w http.ResponseWriter, r *http.Request) {
	// Can only accept post methods
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed. Use POST", http.StatusMethodNotAllowed)
		return
	}

	// Read and parse JSON request body
	var params models.DecryptParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Call existing Decrypt function
	decrypted, err := Decrypt(&params)
	if err != nil {
		http.Error(w, "Decryption failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	//Return successful response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"decrypted": decrypted,
	})
}
