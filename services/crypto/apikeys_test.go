package crypto

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

// TestGenerateAPIKey_ParseRoundTripBatch pins the wire-format contract across
// hundreds of generations: if key IDs could ever contain the `_` separator
// (the base64url bug this catches), a fraction of these would fail to parse.
func TestGenerateAPIKey_ParseRoundTripBatch(t *testing.T) {
	for i := 0; i < 500; i++ {
		generated, err := GenerateAPIKey()
		if err != nil {
			t.Fatalf("generate #%d: %v", i, err)
		}
		keyID, secret, ok := ParseAPIKey(generated.Plaintext)
		if !ok {
			t.Fatalf("generated key #%d failed to parse: %s", i, generated.Plaintext)
		}
		if keyID != generated.KeyID || !bytes.Equal(secret, generated.Secret) {
			t.Fatalf("round-trip mismatch on #%d", i)
		}
		if strings.Contains(keyID, "_") {
			t.Fatalf("key id %q contains separator character", keyID)
		}
	}
}

func TestParseAPIKey_RejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"docops_sk_",
		"docops_sk_onlykeyid",
		"not-a-docops-key",
		"docops_sk_abc_" + "!!!invalid-base64!!!",
	}
	for i, tc := range cases {
		if _, _, ok := ParseAPIKey(tc); ok {
			t.Fatalf("case %d (%q): expected rejection", i, tc)
		}
	}
}

func TestDeriveAPIWrapKey_DeterministicAndSaltSeparated(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	salt1 := make([]byte, 16)
	salt2 := make([]byte, 16)
	rand.Read(salt1)
	rand.Read(salt2)

	k1a, err := DeriveAPIWrapKey(secret, salt1)
	if err != nil {
		t.Fatal(err)
	}
	k1b, _ := DeriveAPIWrapKey(secret, salt1)
	if !bytes.Equal(k1a, k1b) {
		t.Fatal("HKDF derivation not deterministic")
	}
	k2, _ := DeriveAPIWrapKey(secret, salt2)
	if bytes.Equal(k1a, k2) {
		t.Fatal("different salts produced identical wrap keys")
	}
	if len(k1a) != 32 {
		t.Fatalf("wrap key length = %d, want 32", len(k1a))
	}
}

func TestHashAPISecret_Consistent(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	h1 := HashAPISecret(secret)
	h2 := HashAPISecret(secret)
	if !bytes.Equal(h1, h2) {
		t.Fatal("hash inconsistent")
	}
	if len(h1) != 32 {
		t.Fatalf("hash length = %d, want 32", len(h1))
	}
}
