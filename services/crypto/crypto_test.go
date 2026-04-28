package crypto

import (
	"testing"
	"github.com/Kyei-Ernest/DocOps/models"
)


// ─── SALT ────────────────────────────────────────────────────
func TestGenerateSalt(t *testing.T) {
    salt1, err := GenerateSalt()
    if err != nil {
        t.Fatalf("GenerateSalt failed: %v", err)
    }
    if len(salt1) != 16 {
        t.Fatalf("expected 16 bytes, got %d", len(salt1))
    }

    // two salts should never be the same
    salt2, _ := GenerateSalt()
    if string(salt1) == string(salt2) {
        t.Fatal("two salts are identical — randomness broken")
    }
}

// ─── DEK ─────────────────────────────────────────────────────
func TestGenerateDEK(t *testing.T) {
    dek1, err := GenerateDEK()
    if err != nil {
        t.Fatalf("GenerateDEK failed: %v", err)
    }
    if len(dek1) != 32 {
        t.Fatalf("expected 32 bytes, got %d", len(dek1))
    }

    dek2, _ := GenerateDEK()
    if string(dek1) == string(dek2) {
        t.Fatal("two DEKs are identical — randomness broken")
    }
}

// ─── KEK DERIVATION ──────────────────────────────────────────
func TestDeriveKEK_IsDeterministic(t *testing.T) {
    password := "mypassword"
    salt, _ := GenerateSalt()

    kek1 := DeriveKEK(password, salt, models.DefaultArgonParams)
    kek2 := DeriveKEK(password, salt, models.DefaultArgonParams)

    // same inputs must always produce same KEK
    if string(kek1) != string(kek2) {
        t.Fatal("DeriveKEK is not deterministic — same inputs gave different outputs")
    }
}

func TestDeriveKEK_DifferentPasswords(t *testing.T) {
    salt, _ := GenerateSalt()

    kek1 := DeriveKEK("password1", salt, models.DefaultArgonParams)
    kek2 := DeriveKEK("password2", salt, models.DefaultArgonParams)

    if string(kek1) == string(kek2) {
        t.Fatal("different passwords produced the same KEK")
    }
}

func TestDeriveKEK_DifferentSalts(t *testing.T) {
    salt1, _ := GenerateSalt()
    salt2, _ := GenerateSalt()

    kek1 := DeriveKEK("samepassword", salt1, models.DefaultArgonParams)
    kek2 := DeriveKEK("samepassword", salt2, models.DefaultArgonParams)

    if string(kek1) == string(kek2) {
        t.Fatal("different salts produced the same KEK")
    }
}

// ─── ENCRYPT / DECRYPT ───────────────────────────────────────
func TestEncryptDecrypt_RoundTrip(t *testing.T) {
    key, _ := GenerateDEK()
    plaintext := []byte("this is my secret document")

    ciphertext, nonce, err := Encrypt(plaintext, key)
    if err != nil {
        t.Fatalf("Encrypt failed: %v", err)
    }

    result, err := Decrypt(ciphertext, nonce, key)
    if err != nil {
        t.Fatalf("Decrypt failed: %v", err)
    }

    if string(result) != string(plaintext) {
        t.Fatalf("expected %q got %q", plaintext, result)
    }
}

func TestEncrypt_ProducesDifferentCiphertextEachTime(t *testing.T) {
    key, _ := GenerateDEK()
    plaintext := []byte("same plaintext")

    cipher1, _, _ := Encrypt(plaintext, key)
    cipher2, _, _ := Encrypt(plaintext, key)

    // nonces differ so ciphertext must differ
    if string(cipher1) == string(cipher2) {
        t.Fatal("same plaintext produced identical ciphertext — nonce reuse detected")
    }
}

func TestDecrypt_WrongKeyFails(t *testing.T) {
    key, _ := GenerateDEK()
    wrongKey, _ := GenerateDEK()

    ciphertext, nonce, _ := Encrypt([]byte("secret"), key)

    _, err := Decrypt(ciphertext, nonce, wrongKey)
    if err == nil {
        t.Fatal("decryption with wrong key should have failed but didn't")
    }
}

func TestDecrypt_TamperedCiphertextFails(t *testing.T) {
    key, _ := GenerateDEK()
    ciphertext, nonce, _ := Encrypt([]byte("secret"), key)

    // flip a byte
    ciphertext[0] ^= 0xFF

    _, err := Decrypt(ciphertext, nonce, key)
    if err == nil {
        t.Fatal("decryption of tampered ciphertext should have failed")
    }
}

// ─── VERIFICATION BLOB ───────────────────────────────────────
func TestVerifyKEK_CorrectKey(t *testing.T) {
    salt, _ := GenerateSalt()
    kek := DeriveKEK("mypassword", salt, models.DefaultArgonParams)

    blob, nonce, err := CreateVerificationBlob(kek)
    if err != nil {
        t.Fatalf("CreateVerificationBlob failed: %v", err)
    }

    if !VerifyKEK(kek, blob, nonce) {
        t.Fatal("VerifyKEK returned false for correct key")
    }
}

func TestVerifyKEK_WrongKey(t *testing.T) {
    salt, _ := GenerateSalt()
    kek := DeriveKEK("correctpassword", salt, models.DefaultArgonParams)
    wrongKEK := DeriveKEK("wrongpassword", salt, models.DefaultArgonParams)

    blob, nonce, _ := CreateVerificationBlob(kek)

    if VerifyKEK(wrongKEK, blob, nonce) {
        t.Fatal("VerifyKEK returned true for wrong key")
    }
}

// ─── FULL FLOW ───────────────────────────────────────────────
func TestFullEncryptionFlow(t *testing.T) {
    password := "mypassword"

    // ── REGISTRATION ──
    salt, _ := GenerateSalt()
    kek := DeriveKEK(password, salt, models.DefaultArgonParams)
    blob, blobNonce, _ := CreateVerificationBlob(kek)
    // store in DB: salt, blob, blobNonce

    // ── FILE UPLOAD ──
    dek, _ := GenerateDEK()
    fileContent := []byte("this is my contract pdf content")

    encryptedFile, fileNonce, _ := Encrypt(fileContent, dek)
    encryptedDEK, dekNonce, _ := Encrypt(dek, kek)
    // store in DB: encryptedFile (at provider), encryptedDEK, fileNonce, dekNonce

    // ── NEW SESSION / LOGIN ──
    recoveredKEK := DeriveKEK(password, salt, models.DefaultArgonParams)
    if !VerifyKEK(recoveredKEK, blob, blobNonce) {
        t.Fatal("login verification failed")
    }

    // ── FILE DOWNLOAD ──
    recoveredDEK, err := Decrypt(encryptedDEK, dekNonce, recoveredKEK)
    if err != nil {
        t.Fatalf("failed to decrypt DEK: %v", err)
    }

    recoveredFile, err := Decrypt(encryptedFile, fileNonce, recoveredDEK)
    if err != nil {
        t.Fatalf("failed to decrypt file: %v", err)
    }

    if string(recoveredFile) != string(fileContent) {
        t.Fatalf("file content mismatch: expected %q got %q", fileContent, recoveredFile)
    }

    t.Log("full encryption flow passed ✅")
}