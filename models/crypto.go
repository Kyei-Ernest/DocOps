package models

type DecryptParams struct {
	Nonce          []byte `json:"nonce"`
	Ciphertext     []byte `json:"ciphertext"`
	AAD            []byte `json:"aad"`
	HashedPassword []byte `json:"hashed_password"`
}

type EncryptParams struct {
	Plaintext     string `json:"plaintext"`
	Password      string `json:"password"`
	StoredPHCHash []byte `json:"stored_phc_hash"`
	Salt          []byte `json:"salt"`
}
