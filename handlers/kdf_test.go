package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Kyei-Ernest/DocOps/models"
	authsvc "github.com/Kyei-Ernest/DocOps/services/auth"
	"github.com/Kyei-Ernest/DocOps/services/crypto"
)

// strongerParams is strictly >= testParams (m=65536,t=1,p=1) on every axis,
// which is exactly what crypto.NeedsRehash requires to trigger an upgrade.
func strongerParams() *models.Argon2Config {
	return &models.Argon2Config{Memory: 128 * 1024, Iterations: 2, Parallelism: 2, KeyLength: 32, SaltLength: 16}
}

// weakerParams mirrors testParams so it can never trigger an upgrade.
func weakerParams() *models.Argon2Config {
	return &models.Argon2Config{Memory: 64 * 1024, Iterations: 1, Parallelism: 1, KeyLength: 32, SaltLength: 16}
}

// handlerOver rebuilds an AuthHandler around h's existing stores with custom
// Argon2id config — simulating "same database, different server config".
func handlerOver(h *AuthHandler, params *models.Argon2Config) *AuthHandler {
	return NewAuthHandler(h.users, h.sessions, h.metaStore, params, testJWTSecret)
}

func phcParamsString(t *testing.T, phc string) string {
	t.Helper()
	m, i, p, err := crypto.ParsePHCParams(phc)
	if err != nil {
		t.Fatalf("parse PHC %q: %v", phc, err)
	}
	return fmt.Sprintf("m=%d,t=%d,p=%d", m, i, p)
}

func TestLogin_UpgradesWeakKDFParametersExactlyOnce(t *testing.T) {
	h := newTestHandler(t)
	strong := handlerOver(h, strongerParams())
	const email, password = "upgrade@example.com", "password123"

	if rr := postJSON(t, h.Register, map[string]string{"email": email, "password": password}); rr.Code != http.StatusCreated {
		t.Fatalf("register failed: %d", rr.Code)
	}

	before, _ := h.users.GetByEmail(context.Background(), email)

	// First login through the STRONG handler must succeed AND upgrade.
	if rr := postJSON(t, strong.Login, map[string]string{"email": email, "password": password}); rr.Code != http.StatusOK {
		t.Fatalf("login via strong handler failed: %d: %s", rr.Code, rr.Body.String())
	}

	after, _ := h.users.GetByEmail(context.Background(), email)
	want := authsvc.FormatArgon2Params(strongerParams())
	if after.KEKParams != want {
		t.Fatalf("kek_params = %q, want %q", after.KEKParams, want)
	}
	if got := phcParamsString(t, after.PasswordHash); got != want {
		t.Fatalf("password hash params = %q, want %q", got, want)
	}

	// The master key must still unwrap under the NEW KEK derivation.
	newKEK := crypto.DeriveKEK(password, after.Salt, strongerParams())
	if _, err := crypto.UnwrapDEKBound(after.WrappedMasterKey, after.MasterKeyNonce, newKEK, crypto.MasterKeyAAD(after.ID)); err != nil {
		t.Fatalf("master key lost after upgrade: %v", err)
	}

	upgradedPHC := after.PasswordHash

	// Second login: upgrade already applied — PHC must be byte-identical.
	if rr := postJSON(t, strong.Login, map[string]string{"email": email, "password": password}); rr.Code != http.StatusOK {
		t.Fatalf("second login failed: %d", rr.Code)
	}
	final, _ := h.users.GetByEmail(context.Background(), email)
	if final.PasswordHash != upgradedPHC {
		t.Fatal("second login re-upgraded an already-current hash")
	}
	if before.Salt == nil {
		t.Fatal("sanity: pre-upgrade user missing salt")
	}
}

func TestLogin_NeverDowngradesStrongAccounts(t *testing.T) {
	h := newTestHandler(t)
	strong := handlerOver(h, strongerParams())
	const email, password = "strong@example.com", "password123"

	if rr := postJSON(t, strong.Register, map[string]string{"email": email, "password": password}); rr.Code != http.StatusCreated {
		t.Fatalf("register failed: %d", rr.Code)
	}
	before, _ := h.users.GetByEmail(context.Background(), email)

	weak := handlerOver(h, weakerParams())
	if rr := postJSON(t, weak.Login, map[string]string{"email": email, "password": password}); rr.Code != http.StatusOK {
		t.Fatalf("login via weak handler failed: %d", rr.Code)
	}

	after, _ := h.users.GetByEmail(context.Background(), email)
	if after.PasswordHash != before.PasswordHash {
		t.Fatal("hash was rewritten when logging in under weaker config")
	}
	if !bytes.Equal(before.Salt, after.Salt) || !bytes.Equal(before.WrappedMasterKey, after.WrappedMasterKey) {
		t.Fatal("key material churned on a no-op login")
	}
}

func TestRecover_AfterKDFUpgradeStillWorks(t *testing.T) {
	h := newTestHandler(t)
	strong := handlerOver(h, strongerParams())
	const email = "recovers@example.com"
	const firstPassword, secondPassword = "password123", "brandnewpass456"

	regRR := postJSON(t, h.Register, map[string]string{"email": email, "password": firstPassword})
	if regRR.Code != http.StatusCreated {
		t.Fatalf("register failed: %d", regRR.Code)
	}
	var regResp map[string]string
	json.NewDecoder(regRR.Body).Decode(&regResp)
	recoveryKey := regResp["recovery_key"]

	// Upgrade the password path by logging in under the strong config.
	if rr := postJSON(t, strong.Login, map[string]string{"email": email, "password": firstPassword}); rr.Code != http.StatusOK {
		t.Fatalf("upgrade login failed: %d", rr.Code)
	}

	// Recovery MUST still work: the recovery wrap kept its own salt AND its
	// own persisted parameters. Deriving with live config here would have
	// destroyed access permanently — this pins down that latent bug.
	recRR := postJSON(t, strong.Recover, map[string]string{
		"email":        email,
		"recovery_key": recoveryKey,
		"new_password": secondPassword,
	})
	if recRR.Code != http.StatusOK {
		t.Fatalf("recovery after upgrade failed: %d: %s", recRR.Code, recRR.Body.String())
	}

	if rr := postJSON(t, strong.Login, map[string]string{"email": email, "password": secondPassword}); rr.Code != http.StatusOK {
		t.Fatalf("login with recovered password failed: %d", rr.Code)
	}
	if rr := postJSON(t, strong.Login, map[string]string{"email": email, "password": firstPassword}); rr.Code != http.StatusUnauthorized {
		t.Fatalf("old password still accepted after recovery: %d", rr.Code)
	}
}
