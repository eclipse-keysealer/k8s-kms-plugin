// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/eclipse-keypont/crypto11/v2"
	"github.com/eclipse-keypont/gose/jose"
	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/providers"
)

const rotationPlaintext = "the quick brown fox jumps over the lazy dog — k8s-kms-plugin rotation e2e"

// ── Rotation helpers ──────────────────────────────────────────────────────────

// captureEncryptResponse starts a standalone plugin with the given extra serve
// args, encrypts rotationPlaintext, stops the plugin, and returns the ciphertext,
// keyID, and annotations from the EncryptResponse.
func captureEncryptResponse(t *testing.T, extraArgs ...string) (ciphertext, keyID string, annotations map[string]string) {
	t.Helper()
	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	proc := startPlugin(t, sock, extraArgs...)
	defer proc.stop()
	waitForSocket(t, sock)

	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(rotationPlaintext))
	body := fmt.Sprintf(`{"plaintext":%q,"uid":"rot-pre-enc"}`, plaintextB64)

	var resp encryptResponse
	require.NoError(t, json.Unmarshal(callGrpcurl(t, sock, "Encrypt", body), &resp))
	require.NotEmpty(t, resp.Ciphertext, "pre-rotation Encrypt.ciphertext must not be empty")
	require.NotEmpty(t, resp.KeyID, "pre-rotation Encrypt.keyID must not be empty")
	return resp.Ciphertext, resp.KeyID, resp.Annotations
}

// kmsRotationRoundtrip exercises a running rotation plugin on socket.
// It runs four sequential sub-tests:
//  1. Status — must return a keyID different from oldKeyID (the rotated key).
//  2. EncryptWithNewKeyDuringRotation — Encrypt must succeed and return the new keyID.
//  3. DecryptWithNewKeyDuringRotation — round-trip decryption of the just-encrypted ciphertext.
//  4. DecryptWithOldKeyDuringRotation — oldCiphertext (encrypted with oldKeyID before rotation)
//     must still decrypt to rotationPlaintext.
func kmsRotationRoundtrip(t *testing.T, socket, oldCiphertext, oldKeyID string, oldAnnotations map[string]string) {
	t.Helper()

	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(rotationPlaintext))

	var newKeyID, activeCiphertext string
	var activeAnnotations map[string]string

	t.Run("Status", func(t *testing.T) {
		var resp statusResponse
		require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Status", `{}`), &resp))
		require.NotEmpty(t, resp.KeyID, "Status.keyID must not be empty")
		assert.NotEqual(t, oldKeyID, resp.KeyID, "rotation plugin must advertise a different active key than the rotated one")
		newKeyID = resp.KeyID
	})
	if t.Failed() {
		return
	}

	t.Run("EncryptWithNewKeyDuringRotation", func(t *testing.T) {
		body := fmt.Sprintf(`{"plaintext":%q,"uid":"rot-enc-new"}`, plaintextB64)
		var resp encryptResponse
		require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Encrypt", body), &resp))
		require.NotEmpty(t, resp.Ciphertext, "Encrypt.ciphertext must not be empty")
		assert.Equal(t, newKeyID, resp.KeyID, "Encrypt.keyID must match the active key from Status")
		activeCiphertext = resp.Ciphertext
		activeAnnotations = resp.Annotations
	})
	if t.Failed() {
		return
	}

	t.Run("DecryptWithNewKeyDuringRotation", func(t *testing.T) {
		body := fmt.Sprintf(`{"ciphertext":%q,"uid":"rot-dec-new","key_id":%q,"annotations":%s}`,
			activeCiphertext, newKeyID, marshalAnnotations(t, activeAnnotations))
		var resp decryptResponse
		require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Decrypt", body), &resp))
		recovered, err := base64.StdEncoding.DecodeString(resp.Plaintext)
		require.NoError(t, err, "base64-decode Decrypt.plaintext (new key)")
		assert.Equal(t, rotationPlaintext, string(recovered))
	})

	t.Run("DecryptWithOldKeyDuringRotation", func(t *testing.T) {
		body := fmt.Sprintf(`{"ciphertext":%q,"uid":"rot-dec-old","key_id":%q,"annotations":%s}`,
			oldCiphertext, oldKeyID, marshalAnnotations(t, oldAnnotations))
		var resp decryptResponse
		require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Decrypt", body), &resp))
		recovered, err := base64.StdEncoding.DecodeString(resp.Plaintext)
		require.NoError(t, err, "base64-decode Decrypt.plaintext (old key)")
		assert.Equal(t, rotationPlaintext, string(recovered))
	})
}

// oldTokenArgs returns the common --old-p11-* connection flags pointing to the
// shared e2e SoftHSM token. In these tests both old and new keys live on the
// same token, so these values mirror testConfig.
func oldTokenArgs() []string {
	return []string{
		"--old-p11-lib", testConfig.Path,
		"--old-p11-label", testConfig.TokenLabel,
		"--old-p11-pin", testConfig.Pin,
	}
}

// runRotationTest is the shared two-phase rotation harness.
//
//   - oldServeArgs: extra args for startPlugin when pre-encrypting with the old key.
//   - newServeArgs: extra args for startPlugin for the new (active) key side.
//   - oldRotationArgs: args placed after the "rotation" sub-command (old key identity
//     and algorithm flags consumed by rotationCmd).
func runRotationTest(t *testing.T, oldServeArgs, newServeArgs, oldRotationArgs []string) {
	t.Helper()

	// Phase 1: standalone "serve" with the old key — named sub-test so the step
	// is visible in the test report alongside the rotation sub-tests.
	var oldCiphertext, oldKeyID string
	var oldAnnotations map[string]string
	t.Run("EncryptWithOldKeyBeforeRotation", func(t *testing.T) {
		oldCiphertext, oldKeyID, oldAnnotations = captureEncryptResponse(t, oldServeArgs...)
	})
	if t.Failed() {
		return
	}

	// Phase 2: "serve rotation" plugin.
	// startPlugin already prepends: serve --socket .. --p11-lib .. --p11-label .. --p11-pin .. --log-level debug
	// We append: <newServeArgs> rotation <oldRotationArgs>
	rotationExtraArgs := make([]string, 0, len(newServeArgs)+1+len(oldRotationArgs))
	rotationExtraArgs = append(rotationExtraArgs, newServeArgs...)
	rotationExtraArgs = append(rotationExtraArgs, "rotation")
	rotationExtraArgs = append(rotationExtraArgs, oldRotationArgs...)

	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	proc := startPlugin(t, sock, rotationExtraArgs...)
	defer proc.stop()
	waitForSocket(t, sock)

	kmsRotationRoundtrip(t, sock, oldCiphertext, oldKeyID, oldAnnotations)
}

// ── Per-algorithm key generation and CLI arg helpers ─────────────────────────

// generateKeyForAlgo generates the HSM key(s) required by algo, registers
// t.Cleanup for deletion, and returns the KEK label and (for aes-cbc only)
// the HMAC key label.  Any sub-test that calls this with AlgMLKEM is skipped
// automatically when the token does not support CKM_ML_KEM_KEY_PAIR_GEN.
func generateKeyForAlgo(t *testing.T, algo jose.Alg) (kekLabel, hmacLabel string) {
	t.Helper()
	kekLabel = newLabel(t)

	switch algo {
	case providers.AlgAESGCM:
		key, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(kekLabel), 256, crypto11.CipherAES)
		require.NoError(t, err, "generate AES-256-GCM key")
		t.Cleanup(func() { _ = key.Delete() })

	case providers.AlgAESCBC:
		hmacLabel = newLabel(t)
		kek, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(kekLabel), 256, crypto11.CipherAES)
		require.NoError(t, err, "generate AES-256-CBC KEK")
		t.Cleanup(func() { _ = kek.Delete() })
		// HMAC key: CKK_GENERIC_SECRET with CKA_SIGN=true so CKM_SHA256_HMAC is permitted.
		hmacAttrs, err := crypto11.NewAttributeSetWithIDAndLabel(newKeyID(t), []byte(hmacLabel))
		require.NoError(t, err)
		require.NoError(t, hmacAttrs.Set(pkcs11.CKA_SIGN, true))
		require.NoError(t, hmacAttrs.Set(pkcs11.CKA_VERIFY, true))
		hmac, err := testCtx.GenerateSecretKeyWithAttributes(hmacAttrs, 256, crypto11.CipherGeneric)
		require.NoError(t, err, "generate HMAC-SHA256 key")
		t.Cleanup(func() { _ = hmac.Delete() })

	case providers.AlgRSAOAEP:
		kp, err := testCtx.GenerateRSAKeyPairWithLabel(newKeyID(t), []byte(kekLabel), 2048)
		require.NoError(t, err, "generate RSA-2048-OAEP key pair")
		t.Cleanup(func() { _ = kp.Delete() })

	case providers.AlgMLKEM:
		kp, err := testCtx.GenerateMLKEMKeyPairWithLabel(newKeyID(t), []byte(kekLabel), crypto11.MLKEM768)
		if err != nil {
			t.Skipf("ML-KEM key generation not supported by this token: %v"+
				" — requires SoftHSMv3 from https://github.com/pqctoday-org/pqctoday-hsm", err)
		}
		t.Cleanup(func() { _ = kp.Delete() })

	default:
		t.Fatalf("generateKeyForAlgo: unsupported algorithm %q", algo)
	}
	return
}

// serveArgsForAlgo returns the --algorithm-family / --p11-key-label (and optionally
// --p11-hmac-label for aes-cbc) serve flags for the given algorithm.
func serveArgsForAlgo(algo jose.Alg, kekLabel, hmacLabel string) []string {
	args := []string{"--algorithm-family", string(algo), "--p11-key-label", kekLabel}
	if algo == providers.AlgAESCBC {
		args = append(args, "--p11-hmac-label", hmacLabel)
	}
	return args
}

// oldRotationArgsForAlgo returns the --old-algorithm-family / --old-p11-key-label
// (and optionally --old-p11-hmac-label for aes-cbc) rotation flags, prepended
// with the common --old-p11-* token connection flags.
func oldRotationArgsForAlgo(algo jose.Alg, kekLabel, hmacLabel string) []string {
	args := append(oldTokenArgs(), "--old-algorithm-family", string(algo), "--old-p11-key-label", kekLabel)
	if algo == providers.AlgAESCBC {
		args = append(args, "--old-p11-hmac-label", hmacLabel)
	}
	return args
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestRotation covers all 16 combinations of old → new algorithm family (4 × 4).
// Each combination is a sub-test named "From<old>_To<new>".
// Sub-tests that involve ML-KEM are skipped automatically on tokens that do not
// support CKM_ML_KEM_KEY_PAIR_GEN (SoftHSMv2 and earlier); requires SoftHSMv3.
func TestRotation(t *testing.T) {
	type algoEntry struct {
		family jose.Alg
		name   string
	}
	algos := []algoEntry{
		{providers.AlgAESGCM, "AESGCM"},
		{providers.AlgAESCBC, "AESCBC"},
		{providers.AlgRSAOAEP, "RSAOAEP"},
		{providers.AlgMLKEM, "MLKEM"},
	}

	for _, oldEntry := range algos {
		for _, newEntry := range algos {
			t.Run(fmt.Sprintf("From%s_To%s", oldEntry.name, newEntry.name), func(t *testing.T) {
				oldKekLabel, oldHmacLabel := generateKeyForAlgo(t, oldEntry.family)
				newKekLabel, newHmacLabel := generateKeyForAlgo(t, newEntry.family)

				runRotationTest(t,
					serveArgsForAlgo(oldEntry.family, oldKekLabel, oldHmacLabel),
					serveArgsForAlgo(newEntry.family, newKekLabel, newHmacLabel),
					oldRotationArgsForAlgo(oldEntry.family, oldKekLabel, oldHmacLabel),
				)
			})
		}
	}
}
