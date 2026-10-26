// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"testing"

	"github.com/eclipse-keypont/crypto11/v2"
	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/providers"

	k8skmsv2 "k8s.io/kms/apis/v2"
)

// The provider resolves a KEK on the first request and reuses it. These tests replace the KEK
// on the token under the same CKA_ID and CKA_LABEL, as an operator restoring a key would, and
// check that the provider follows without a restart:
//
//   - replaced between two requests, the next round trip works: the cached handle is stale and
//     the provider resolves the key again;
//   - deleted, a request fails with an error rather than a panic;
//   - re-created after that, the next round trip works again.

// requireEncryptFails asserts that Encrypt returns an error, not a panic.
func requireEncryptFails(t *testing.T, p *providers.P11) {
	t.Helper()
	require.NotPanics(t, func() {
		_, err := p.Encrypt(context.Background(), &k8skmsv2.EncryptRequest{Plaintext: []byte(testPlaintext)})
		require.Error(t, err, "Encrypt with the KEK deleted from the token")
	})
}

// requireDecryptFails asserts that Decrypt of encResp returns an error, not a panic.
func requireDecryptFails(t *testing.T, p *providers.P11, encResp *k8skmsv2.EncryptResponse) {
	t.Helper()
	require.NotPanics(t, func() {
		_, err := p.Decrypt(context.Background(), &k8skmsv2.DecryptRequest{
			Ciphertext:  encResp.GetCiphertext(),
			KeyId:       encResp.GetKeyId(),
			Annotations: encResp.GetAnnotations(),
		})
		require.Error(t, err, "Decrypt with the KEK deleted from the token")
	})
}

func TestKeyCache_AESGCM_KEKReplaced(t *testing.T) {
	skipIfNoLibrary(t)
	id, label := newTestID(t), newTestLabel(t)

	kek, err := testCtx.GenerateSecretKeyWithLabel(id, []byte(label), 256, crypto11.CipherAES)
	require.NoError(t, err)
	p := newP11WithLabel(t, label, providers.AlgAESGCM)
	encryptDecryptRoundtrip(t, p, []byte(testPlaintext))

	require.NoError(t, kek.Delete())
	kek, err = testCtx.GenerateSecretKeyWithLabel(id, []byte(label), 256, crypto11.CipherAES)
	require.NoError(t, err)
	first := encryptDecryptRoundtrip(t, p, []byte(testPlaintext))

	require.NoError(t, kek.Delete())
	requireEncryptFails(t, p)
	requireDecryptFails(t, p, first)

	kek, err = testCtx.GenerateSecretKeyWithLabel(id, []byte(label), 256, crypto11.CipherAES)
	require.NoError(t, err)
	t.Cleanup(func() { _ = kek.Delete() })
	encryptDecryptRoundtrip(t, p, []byte(testPlaintext))
}

func TestKeyCache_AESCBC_KEKReplaced(t *testing.T) {
	skipIfNoLibrary(t)
	kekID, kekLabel := newTestID(t), newTestLabel(t)
	hmacID, hmacLabel := newTestID(t), newTestLabel(t)

	kek, err := testCtx.GenerateSecretKeyWithLabel(kekID, []byte(kekLabel), 256, crypto11.CipherAES)
	require.NoError(t, err)
	hmacAttrs, err := crypto11.NewAttributeSetWithIDAndLabel(hmacID, []byte(hmacLabel))
	require.NoError(t, err)
	require.NoError(t, hmacAttrs.Set(pkcs11.CKA_SIGN, true))
	require.NoError(t, hmacAttrs.Set(pkcs11.CKA_VERIFY, true))
	hmacKey, err := testCtx.GenerateSecretKeyWithAttributes(hmacAttrs, 256, crypto11.CipherGeneric)
	require.NoError(t, err)
	t.Cleanup(func() { _ = hmacKey.Delete() })

	p := newP11CBCWithLabel(t, kekLabel, hmacLabel)
	encryptDecryptRoundtrip(t, p, []byte(testPlaintext))

	require.NoError(t, kek.Delete())
	kek, err = testCtx.GenerateSecretKeyWithLabel(kekID, []byte(kekLabel), 256, crypto11.CipherAES)
	require.NoError(t, err)
	first := encryptDecryptRoundtrip(t, p, []byte(testPlaintext))

	require.NoError(t, kek.Delete())
	requireEncryptFails(t, p)
	requireDecryptFails(t, p, first)

	kek, err = testCtx.GenerateSecretKeyWithLabel(kekID, []byte(kekLabel), 256, crypto11.CipherAES)
	require.NoError(t, err)
	t.Cleanup(func() { _ = kek.Delete() })
	encryptDecryptRoundtrip(t, p, []byte(testPlaintext))
}

func TestKeyCache_RSAOAEP_KeyPairReplaced(t *testing.T) {
	skipIfNoLibrary(t)
	id, label := newTestID(t), newTestLabel(t)

	kp, err := testCtx.GenerateRSAKeyPairWithLabel(id, []byte(label), 2048)
	require.NoError(t, err)
	p := newP11WithLabel(t, label, providers.AlgRSAOAEP)
	encryptDecryptRoundtrip(t, p, []byte(testPlaintext))

	// Encrypt must pick up the new public key, or Decrypt with the new private key fails.
	require.NoError(t, kp.Delete())
	kp, err = testCtx.GenerateRSAKeyPairWithLabel(id, []byte(label), 2048)
	require.NoError(t, err)
	first := encryptDecryptRoundtrip(t, p, []byte(testPlaintext))

	require.NoError(t, kp.Delete())
	requireEncryptFails(t, p)
	requireDecryptFails(t, p, first)

	kp, err = testCtx.GenerateRSAKeyPairWithLabel(id, []byte(label), 2048)
	require.NoError(t, err)
	t.Cleanup(func() { _ = kp.Delete() })
	encryptDecryptRoundtrip(t, p, []byte(testPlaintext))
}

func TestKeyCache_MLKEM_KeyPairReplaced(t *testing.T) {
	skipIfNoLibrary(t)
	id, label := newTestID(t), newTestLabel(t)

	kp, err := testCtx.GenerateMLKEMKeyPairWithLabel(id, []byte(label), crypto11.MLKEM768)
	if err != nil {
		t.Skipf("HSM does not support ML-KEM: %v", err)
	}
	p := newP11WithLabel(t, label, providers.AlgMLKEM)
	encryptDecryptRoundtrip(t, p, []byte(testPlaintext))

	require.NoError(t, kp.Delete())
	kp, err = testCtx.GenerateMLKEMKeyPairWithLabel(id, []byte(label), crypto11.MLKEM768)
	require.NoError(t, err)
	first := encryptDecryptRoundtrip(t, p, []byte(testPlaintext))

	require.NoError(t, kp.Delete())
	requireEncryptFails(t, p)
	requireDecryptFails(t, p, first)

	kp, err = testCtx.GenerateMLKEMKeyPairWithLabel(id, []byte(label), crypto11.MLKEM768)
	require.NoError(t, err)
	t.Cleanup(func() { _ = kp.Delete() })
	encryptDecryptRoundtrip(t, p, []byte(testPlaintext))
}
