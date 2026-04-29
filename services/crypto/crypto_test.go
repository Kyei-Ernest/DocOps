package crypto

import (
    "bytes"
    "testing"

    "github.com/Kyei-Ernest/DocOps/models"
)

// ─── HELPERS ─────────────────────────────────────────────────

// mustGenerateSalt calls GenerateSalt and fails the test immediately on error.
func mustGenerateSalt(t *testing.T) []byte {
    t.Helper()
    salt, err := GenerateSalt()
    if err != nil {
        t.Fatalf("GenerateSalt failed: %v", err)
    }
    return salt
}

// mustGenerateDEK calls GenerateDEK and fails the test immediately on error.
func mustGenerateDEK(t *testing.T) []byte {
    t.Helper()
    dek, err := GenerateDEK()
    if err != nil {
        t.Fatalf("GenerateDEK failed: %v", err)
    }
    return dek
}

// mustEncrypt calls Encrypt and fails the test immediately on error.
func mustEncrypt(t *testing.T, plaintext, key []byte) (ciphertext, nonce []byte) {
    t.Helper()
    ct, n, err := Encrypt(plaintext, key)
    if err != nil {
        t.Fatalf("Encrypt failed: %v", err)
    }
    return ct, n
}

// ─── SALT ────────────────────────────────────────────────────

func TestGenerateSalt_Length(t *testing.T) {
    salt := mustGenerateSalt(t)
    if len(salt) != 16 {
        t.Fatalf("expected 16 bytes, got %d", len(salt))
    }
}

func TestGenerateSalt_Uniqueness(t *testing.T) {
    salt1 := mustGenerateSalt(t)
    salt2 := mustGenerateSalt(t)
    if bytes.Equal(salt1, salt2) {
        t.Fatal("two salts are identical — randomness broken")
    }
}

// ─── DEK ─────────────────────────────────────────────────────

func TestGenerateDEK_Length(t *testing.T) {
    dek := mustGenerateDEK(t)
    if len(dek) != 32 {
        t.Fatalf("expected 32 bytes, got %d", len(dek))
    }
}

func TestGenerateDEK_Uniqueness(t *testing.T) {
    dek1 := mustGenerateDEK(t)
    dek2 := mustGenerateDEK(t)
    if bytes.Equal(dek1, dek2) {
        t.Fatal("two DEKs are identical — randomness broken")
    }
}

// ─── KEK DERIVATION ──────────────────────────────────────────

func TestDeriveKEK_Length(t *testing.T) {
    salt := mustGenerateSalt(t)
    kek := DeriveKEK("password", salt, models.DefaultArgonParams)
    if len(kek) != 32 {
        t.Fatalf("expected 32-byte KEK, got %d", len(kek))
    }
}

func TestDeriveKEK_IsDeterministic(t *testing.T) {
    salt := mustGenerateSalt(t)
    kek1 := DeriveKEK("mypassword", salt, models.DefaultArgonParams)
    kek2 := DeriveKEK("mypassword", salt, models.DefaultArgonParams)
    if !bytes.Equal(kek1, kek2) {
        t.Fatal("DeriveKEK is not deterministic — same inputs gave different outputs")
    }
}

func TestDeriveKEK_DifferentPasswords(t *testing.T) {
    salt := mustGenerateSalt(t)
    kek1 := DeriveKEK("password1", salt, models.DefaultArgonParams)
    kek2 := DeriveKEK("password2", salt, models.DefaultArgonParams)
    if bytes.Equal(kek1, kek2) {
        t.Fatal("different passwords produced the same KEK")
    }
}

func TestDeriveKEK_DifferentSalts(t *testing.T) {
    salt1 := mustGenerateSalt(t)
    salt2 := mustGenerateSalt(t)
    kek1 := DeriveKEK("samepassword", salt1, models.DefaultArgonParams)
    kek2 := DeriveKEK("samepassword", salt2, models.DefaultArgonParams)
    if bytes.Equal(kek1, kek2) {
        t.Fatal("different salts produced the same KEK")
    }
}

// ─── ENCRYPT / DECRYPT ───────────────────────────────────────

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
    key := mustGenerateDEK(t)
    plaintext := []byte("this is my secret document")

    ciphertext, nonce := mustEncrypt(t, plaintext, key)

    result, err := Decrypt(ciphertext, nonce, key)
    if err != nil {
        t.Fatalf("Decrypt failed: %v", err)
    }
    if !bytes.Equal(result, plaintext) {
        t.Fatalf("expected %q got %q", plaintext, result)
    }
}

// TestEncryptDecrypt_EmptyPlaintext ensures empty input is handled correctly
// rather than panicking or producing a zero-length ciphertext.
func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
    key := mustGenerateDEK(t)
    plaintext := []byte{}

    ciphertext, nonce := mustEncrypt(t, plaintext, key)

    result, err := Decrypt(ciphertext, nonce, key)
    if err != nil {
        t.Fatalf("Decrypt of empty plaintext failed: %v", err)
    }
    if !bytes.Equal(result, plaintext) {
        t.Fatalf("round-trip of empty plaintext failed: got %q", result)
    }
}

func TestEncrypt_ProducesDifferentCiphertextEachTime(t *testing.T) {
    key := mustGenerateDEK(t)
    plaintext := []byte("same plaintext")

    cipher1, nonce1 := mustEncrypt(t, plaintext, key)
    cipher2, nonce2 := mustEncrypt(t, plaintext, key)

    // nonces must differ (randomness check)
    if bytes.Equal(nonce1, nonce2) {
        t.Fatal("two encryptions produced the same nonce — nonce reuse detected")
    }
    // ciphertexts must therefore also differ
    if bytes.Equal(cipher1, cipher2) {
        t.Fatal("same plaintext produced identical ciphertext — nonce reuse detected")
    }
}

func TestDecrypt_WrongKeyFails(t *testing.T) {
    key := mustGenerateDEK(t)
    wrongKey := mustGenerateDEK(t)

    ciphertext, nonce := mustEncrypt(t, []byte("secret"), key)

    _, err := Decrypt(ciphertext, nonce, wrongKey)
    if err == nil {
        t.Fatal("decryption with wrong key should have failed but didn't")
    }
}

func TestDecrypt_TamperedCiphertextFails(t *testing.T) {
    key := mustGenerateDEK(t)
    ciphertext, nonce := mustEncrypt(t, []byte("secret"), key)

    ciphertext[0] ^= 0xFF // flip one bit

    _, err := Decrypt(ciphertext, nonce, key)
    if err == nil {
        t.Fatal("decryption of tampered ciphertext should have failed")
    }
}

// TestDecrypt_TruncatedNonceFails confirms that a malformed (too-short) nonce
// is rejected rather than silently reading out of bounds.
func TestDecrypt_TruncatedNonceFails(t *testing.T) {
    key := mustGenerateDEK(t)
    ciphertext, nonce := mustEncrypt(t, []byte("secret"), key)

    truncated := nonce[:len(nonce)/2]

    _, err := Decrypt(ciphertext, truncated, key)
    if err == nil {
        t.Fatal("decryption with truncated nonce should have failed")
    }
}

// ─── VERIFICATION BLOB ───────────────────────────────────────

func TestVerifyKEK_CorrectKey(t *testing.T) {
    salt := mustGenerateSalt(t)
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
    salt := mustGenerateSalt(t)
    kek := DeriveKEK("correctpassword", salt, models.DefaultArgonParams)
    wrongKEK := DeriveKEK("wrongpassword", salt, models.DefaultArgonParams)

    blob, nonce, err := CreateVerificationBlob(kek)
    if err != nil {
        t.Fatalf("CreateVerificationBlob failed: %v", err)
    }
    if VerifyKEK(wrongKEK, blob, nonce) {
        t.Fatal("VerifyKEK returned true for wrong key")
    }
}

// TestVerifyKEK_TamperedBlob confirms that a single flipped bit in the
// verification blob is caught by the AEAD authentication tag.
func TestVerifyKEK_TamperedBlob(t *testing.T) {
    salt := mustGenerateSalt(t)
    kek := DeriveKEK("mypassword", salt, models.DefaultArgonParams)

    blob, nonce, err := CreateVerificationBlob(kek)
    if err != nil {
        t.Fatalf("CreateVerificationBlob failed: %v", err)
    }

    blob[0] ^= 0xFF // corrupt one byte

    if VerifyKEK(kek, blob, nonce) {
        t.Fatal("VerifyKEK returned true for tampered blob — authentication not enforced")
    }
}

// TestCreateVerificationBlob_NonceUniqueness ensures each call generates a
// fresh nonce. Reusing nonces with the same key breaks AES-GCM security.
func TestCreateVerificationBlob_NonceUniqueness(t *testing.T) {
    salt := mustGenerateSalt(t)
    kek := DeriveKEK("mypassword", salt, models.DefaultArgonParams)

    _, nonce1, err := CreateVerificationBlob(kek)
    if err != nil {
        t.Fatalf("first CreateVerificationBlob failed: %v", err)
    }
    _, nonce2, err := CreateVerificationBlob(kek)
    if err != nil {
        t.Fatalf("second CreateVerificationBlob failed: %v", err)
    }
    if bytes.Equal(nonce1, nonce2) {
        t.Fatal("CreateVerificationBlob reused a nonce — AES-GCM security broken")
    }
}

// ─── FULL FLOW ───────────────────────────────────────────────

func TestFullEncryptionFlow(t *testing.T) {
    password := "mypassword"

    // ── REGISTRATION ──
    salt := mustGenerateSalt(t)
    kek := DeriveKEK(password, salt, models.DefaultArgonParams)
    blob, blobNonce, err := CreateVerificationBlob(kek)
    if err != nil {
        t.Fatalf("CreateVerificationBlob failed: %v", err)
    }

    // ── FILE UPLOAD ──
    dek := mustGenerateDEK(t)
    fileContent := []byte("this is my contract pdf content")

    encryptedFile, fileNonce := mustEncrypt(t, fileContent, dek)
    encryptedDEK, dekNonce := mustEncrypt(t, dek, kek)

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

    if !bytes.Equal(recoveredFile, fileContent) {
        t.Fatalf("file content mismatch: expected %q got %q", fileContent, recoveredFile)
    }
}