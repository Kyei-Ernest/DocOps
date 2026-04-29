package main

import (
	"fmt"

	"github.com/Kyei-Ernest/DocOps/models"
	"github.com/Kyei-Ernest/DocOps/services/crypto"
)

func main() {
	padded := make([]byte, 16)
	copy(padded, "lama")
	ciphertext, nonce, err := crypto.CreateVerificationBlob(padded)

	if err != nil {
		fmt.Println(err)
	}
	

	decrypt, err := crypto.Decrypt(ciphertext, nonce, padded)

	fmt.Println("plaintext: ", string(decrypt))

	fmt.Println("Derived KEK: ", crypto.DeriveKEK("lamine", padded, models.DefaultArgonParams))
}
