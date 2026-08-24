package handlers

import (
	"context"

	"github.com/Kyei-Ernest/DocOps/models"
	authsvc "github.com/Kyei-Ernest/DocOps/services/auth"
	"github.com/Kyei-Ernest/DocOps/services/crypto"
)

// kekParamsFor returns the Argon2id parameters under which this user's Master
// Key wrap was created. Key derivation must reproduce the ORIGINAL cost
// parameters forever: deriving with newer live config would yield a different
// KEK and permanently lose access to the wrapped key.
//
// Rows created before parameter persistence have an empty KEKParams string;
// those fall back to current config, matching pre-upgrade behaviour exactly.
// The fallback is also what makes the recover flow work for users whose
// recovery wrap predates the column.
func kekParamsFor(user *authsvc.User, current *models.Argon2Config, field string) *models.Argon2Config {
	stored := user.KEKParams
	if field == "recovery" {
		stored = user.RecoveryKEKParams
	}
	if stored == "" {
		return current
	}
	parsed, err := authsvc.ParseArgon2Params(stored)
	if err != nil {
		return current
	}
	// The persisted triple covers memory/time/parallelism; output length is a
	// fixed system-wide constant (256-bit keys), taken from live config.
	out := *parsed
	out.KeyLength = current.KeyLength
	return &out
}

// upgradeKDFParameters re-hashes the password and re-wraps the Master Key
// under the CURRENT configured Argon2id parameters. Called after a successful
// login when crypto.NeedsRehash says the stored hash is materially weaker
// than config (ROADMAP P0-5).
//
// The recovery wrap is deliberately untouched: it has its own salt and its
// own persisted parameters and does not depend on the password path at all.
//
// Single-row UPDATE — atomic per statement in SQLite; no explicit transaction
// is required for consistency here.
func (h *AuthHandler) upgradeKDFParameters(ctx context.Context, password string, user *authsvc.User, masterKey []byte) error {
	newPasswordHash, err := crypto.HashPassword(password, h.params)
	if err != nil {
		return err
	}
	newSalt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}
	newKEK := crypto.DeriveKEK(password, newSalt, h.params)
	newWrappedMasterKey, newMasterKeyNonce, err := crypto.WrapDEKBound(masterKey, newKEK, crypto.MasterKeyAAD(user.ID))
	if err != nil {
		return err
	}

	user.PasswordHash = newPasswordHash
	user.Salt = newSalt
	user.WrappedMasterKey = newWrappedMasterKey
	user.MasterKeyNonce = newMasterKeyNonce
	user.KEKParams = authsvc.FormatArgon2Params(h.params)

	return h.users.UpdateUserKeys(ctx, user)
}
