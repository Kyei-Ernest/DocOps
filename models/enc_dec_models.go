package models


type DecryptParams struct {
	Nonce           []byte      `json:"nonce"`
	Ciphertext      []byte      `json:"ciphertext"`
	AAD             []byte      `json:"aad"`
    HashedPassword  []byte      `json:"hashed_password"`

	
}


type EncryptParams struct {
	Plaintext       string   `json:"plaintext"`
    Password        string   `json:"password"`
    StoredPHCHash   []byte   `json:"stored_phc_hash"`
    Salt            []byte   `json:"salt"`
}

type Argon2idParams struct {
    Memory      uint32
    Iterations  uint32
    Parallelism uint8
    SaltLength  uint32
    KeyLength   uint32
}

// Recommended params (adjust based on your server's capacity)
var DefaultArgonParams = &Argon2idParams{
    Memory:      64 * 1024, // 64 MB
    Iterations:  3,
    Parallelism: 2,
    SaltLength:  16,
    KeyLength:   32,
}

