// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

// Package integration contains HSM-backed integration tests.
//
// Required environment variables (inherited from p11_integration_test.go init()):
//
//	PKCS11_MODULE  — path to the PKCS#11 shared library
//	PKCS11_TOKEN    — token label
//	PKCS11_PIN      — token PIN
//
// AES-GCM, AES-CBC and RSA-OAEP tests run against SoftHSMv2 or any PKCS#11 token.
// ML-KEM tests require SoftHSMv3 from https://github.com/pqctoday-org/pqctoday-hsm
// which implements PKCS#11 v3.2 (CKM_ML_KEM_KEY_PAIR_GEN / CKM_ML_KEM).
package integration

import (
	"context"
	"os"
	"testing"

	"github.com/eclipse-keypont/crypto11/v2"
	"github.com/eclipse-keypont/gose/jose"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/providers"

	k8skmsv2 "k8s.io/kms/apis/v2"
)

const testPlaintext = "the quick brown fox jumps over the lazy dog"

// skipIfNoLibrary skips the test when PKCS11_MODULE is not set, which means the
// init() in p11_integration_test.go already panicked. Guard every test with this
// so the suite can run as a no-op in environments without an HSM.
func skipIfNoLibrary(t *testing.T) {
	t.Helper()
	if os.Getenv("PKCS11_MODULE") == "" {
		t.Skip("PKCS11_MODULE not set — skipping integration test")
	}
}

// newTestID returns a unique, text-encoded UUID suitable for use as a PKCS#11 CKA_ID.
func newTestID(t *testing.T) []byte {
	t.Helper()
	id, err := uuid.NewRandom()
	require.NoError(t, err)
	b, err := id.MarshalText()
	require.NoError(t, err)
	return b
}

// newTestLabel returns a unique label string derived from the test name.
func newTestLabel(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewRandom()
	require.NoError(t, err)
	return t.Name() + "-" + id.String()[:8]
}

// jweEncHeader unmarshals a compact JWE and returns its enc header value.
func jweEncHeader(t *testing.T, ciphertext []byte) jose.Enc {
	t.Helper()
	var jwe jose.JweRfc7516Compact
	require.NoError(t, jwe.Unmarshal(string(ciphertext)))
	return jwe.ProtectedHeader.Enc
}

// newP11WithLabel creates a P11 provider identified by CKA_LABEL (no CKA_ID supplied).
func newP11WithLabel(t *testing.T, label string, alg jose.Alg) *providers.P11 {
	t.Helper()
	p, err := providers.NewP11(
		testConfig,
		"",    // kekkeyid (CKA_ID) — discover from label
		label, // k8sKekLabel (CKA_LABEL)
		"",    // hmacKeyLabel
		"",    // hmacCkaId
		alg,
		false, // isKeyRotation
		nil, "", "", "", "", "",
	)
	require.NoError(t, err)
	return p
}

// newP11CBCWithLabel creates a P11 provider for AES-CBC + HMAC.
func newP11CBCWithLabel(t *testing.T, kekLabel, hmacLabel string) *providers.P11 {
	t.Helper()
	p, err := providers.NewP11(
		testConfig,
		"",        // kekkeyid
		kekLabel,  // k8sKekLabel
		hmacLabel, // hmacKeyLabel
		"",        // hmacCkaId
		providers.AlgAESCBC,
		false,
		nil, "", "", "", "", "",
	)
	require.NoError(t, err)
	return p
}

// encryptDecryptRoundtrip is a shared helper that encrypts and then decrypts,
// asserting the recovered plaintext equals the original. Annotations are forwarded from
// the EncryptResponse to the DecryptRequest, mirroring the apiserver's round-trip guarantee
// (required for ML-KEM, whose KEM ciphertext travels in annotations).
func encryptDecryptRoundtrip(t *testing.T, p *providers.P11, plaintext []byte) *k8skmsv2.EncryptResponse {
	t.Helper()
	encResp, err := p.Encrypt(context.Background(), &k8skmsv2.EncryptRequest{
		Plaintext: plaintext,
	})
	require.NoError(t, err)
	require.NotNil(t, encResp)

	decResp, err := p.Decrypt(context.Background(), &k8skmsv2.DecryptRequest{
		Ciphertext:  encResp.GetCiphertext(),
		KeyId:       encResp.GetKeyId(),
		Annotations: encResp.GetAnnotations(),
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResp.GetPlaintext())
	return encResp
}

// ---------------------------------------------------------------------------
// AES-GCM — auto-detected key size
// ---------------------------------------------------------------------------

func testAESGCM(t *testing.T, bitSize int, wantEnc jose.Enc) {
	t.Helper()
	skipIfNoLibrary(t)

	id := newTestID(t)
	label := newTestLabel(t)

	key, err := testCtx.GenerateSecretKeyWithLabel(id, []byte(label), bitSize, crypto11.CipherAES)
	require.NoErrorf(t, err, "GenerateSecretKeyWithLabel(%d-bit)", bitSize)
	t.Cleanup(func() { _ = key.Delete() })

	p := newP11WithLabel(t, label, providers.AlgAESGCM)

	encResp := encryptDecryptRoundtrip(t, p, []byte(testPlaintext))

	// Verify the JWE enc header matches the actual key size, not a hardcoded constant.
	assert.Equal(t, wantEnc, jweEncHeader(t, encResp.GetCiphertext()),
		"JWE enc header should reflect the %d-bit HSM key", bitSize)
}

func TestAESGCM_AutoDetect_128bit(t *testing.T) {
	testAESGCM(t, 128, jose.EncA128GCM)
}

func TestAESGCM_AutoDetect_192bit(t *testing.T) {
	testAESGCM(t, 192, jose.EncA192GCM)
}

func TestAESGCM_AutoDetect_256bit(t *testing.T) {
	testAESGCM(t, 256, jose.EncA256GCM)
}

// ---------------------------------------------------------------------------
// AES-CBC + HMAC-SHA256
// ---------------------------------------------------------------------------

func TestAESCBC_EncryptDecrypt(t *testing.T) {
	skipIfNoLibrary(t)

	kekID := newTestID(t)
	kekLabel := newTestLabel(t)
	hmacID := newTestID(t)
	hmacLabel := newTestLabel(t)

	kek, err := testCtx.GenerateSecretKeyWithLabel(kekID, []byte(kekLabel), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate AES-256 KEK")
	t.Cleanup(func() { _ = kek.Delete() })

	// HMAC key: CKK_GENERIC_SECRET with CKA_SIGN=true so CKM_SHA256_HMAC is permitted.
	hmacAttrs, err := crypto11.NewAttributeSetWithIDAndLabel(hmacID, []byte(hmacLabel))
	require.NoError(t, err)
	require.NoError(t, hmacAttrs.Set(crypto11.CkaSign, true))
	require.NoError(t, hmacAttrs.Set(crypto11.CkaVerify, true))
	hmacKey, err := testCtx.GenerateSecretKeyWithAttributes(hmacAttrs, 256, crypto11.CipherGeneric)
	require.NoError(t, err, "generate HMAC key")
	t.Cleanup(func() { _ = hmacKey.Delete() })

	p := newP11CBCWithLabel(t, kekLabel, hmacLabel)
	encryptDecryptRoundtrip(t, p, []byte(testPlaintext))
}

// ---------------------------------------------------------------------------
// RSA-OAEP
// ---------------------------------------------------------------------------

func TestRSAOAEP_EncryptDecrypt(t *testing.T) {
	skipIfNoLibrary(t)

	id := newTestID(t)
	label := newTestLabel(t)

	kp, err := testCtx.GenerateRSAKeyPairWithLabel(id, []byte(label), 2048)
	require.NoError(t, err, "GenerateRSAKeyPairWithLabel 2048-bit")
	t.Cleanup(func() { _ = kp.Delete() })

	p := newP11WithLabel(t, label, providers.AlgRSAOAEP)
	encryptDecryptRoundtrip(t, p, []byte(testPlaintext))
}

// ---------------------------------------------------------------------------
// ML-KEM — requires SoftHSMv3 (pqctoday-org/pqctoday-hsm)
// ---------------------------------------------------------------------------

// mlkemCiphertextLen maps each ML-KEM parameter set to its raw KEM encapsulation
// ciphertext (CT) size in bytes, per FIPS 203.
var mlkemCiphertextLen = map[crypto11.MLKEMParameterSet]int{
	crypto11.MLKEM512:  768,
	crypto11.MLKEM768:  1088,
	crypto11.MLKEM1024: 1568,
}

// testMLKEM exercises the full NewP11 → Encrypt → Decrypt cycle for one ML-KEM parameter
// set and verifies the KMS v2 binary envelope contract: the KEM ciphertext (key
// establishment material) travels in the kem-ciphertext Annotations entry sized to the parameter
// set's CT length, the algorithm-family Annotations entry echoes "ml-kem", and
// EncryptResponse.Ciphertext (the AEAD-wrapped DEK seed) stays well under the KMS v2 1 kB
// limit — this is the case a JWE-shaped envelope could not satisfy for ML-KEM-768/1024.
func testMLKEM(t *testing.T, paramSet crypto11.MLKEMParameterSet) {
	t.Helper()
	skipIfNoLibrary(t)

	id := newTestID(t)
	label := newTestLabel(t)

	kp, err := testCtx.GenerateMLKEMKeyPairWithLabel(id, []byte(label), paramSet)
	if err != nil {
		// SoftHSMv2 does not support ML-KEM; require SoftHSMv3.
		t.Skipf("HSM does not support ML-KEM (param set %d): %v — requires SoftHSMv3 from pqctoday-org/pqctoday-hsm", paramSet, err)
	}
	t.Cleanup(func() { _ = kp.Delete() })

	p := newP11WithLabel(t, label, providers.AlgMLKEM)
	encResp := encryptDecryptRoundtrip(t, p, []byte(testPlaintext))

	assert.Lessf(t, len(encResp.GetCiphertext()), 1024,
		"EncryptResponse.ciphertext must stay under the KMS v2 1 kB limit, got %d bytes", len(encResp.GetCiphertext()))

	annotations := encResp.GetAnnotations()
	require.Len(t, annotations, 2, "expected a kem-ciphertext annotation and an algorithm-family annotation")

	ct, ok := annotations[providers.KemCiphertextAnnotationKey]
	require.True(t, ok, "missing %s annotation", providers.KemCiphertextAnnotationKey)
	assert.Equal(t, mlkemCiphertextLen[paramSet], len(ct),
		"KEM ciphertext annotation length should match parameter set %d", paramSet)

	assert.Equal(t, []byte("ml-kem"), annotations[providers.AlgorithmFamilyAnnotationKey])
}

func TestMLKEM_512_EncryptDecrypt(t *testing.T) {
	testMLKEM(t, crypto11.MLKEM512)
}

func TestMLKEM_768_EncryptDecrypt(t *testing.T) {
	testMLKEM(t, crypto11.MLKEM768)
}

func TestMLKEM_1024_EncryptDecrypt(t *testing.T) {
	testMLKEM(t, crypto11.MLKEM1024)
}

// TestMLKEM_Uniqueness verifies the KMS v2 uniqueness requirement: encrypting the same
// plaintext twice yields distinct ciphertext and distinct kem-ciphertext annotation values, since
// ML-KEM encapsulation and the AES-GCM nonce are both freshly randomized per call.
func TestMLKEM_Uniqueness(t *testing.T) {
	skipIfNoLibrary(t)

	id := newTestID(t)
	label := newTestLabel(t)

	kp, err := testCtx.GenerateMLKEMKeyPairWithLabel(id, []byte(label), crypto11.MLKEM768)
	if err != nil {
		t.Skipf("HSM does not support ML-KEM: %v — requires SoftHSMv3 from pqctoday-org/pqctoday-hsm", err)
	}
	t.Cleanup(func() { _ = kp.Delete() })

	p := newP11WithLabel(t, label, providers.AlgMLKEM)

	resp1, err := p.Encrypt(context.Background(), &k8skmsv2.EncryptRequest{Plaintext: []byte(testPlaintext)})
	require.NoError(t, err)
	resp2, err := p.Encrypt(context.Background(), &k8skmsv2.EncryptRequest{Plaintext: []byte(testPlaintext)})
	require.NoError(t, err)

	assert.NotEqual(t, resp1.GetCiphertext(), resp2.GetCiphertext())
	assert.NotEqual(t,
		resp1.GetAnnotations()[providers.KemCiphertextAnnotationKey],
		resp2.GetAnnotations()[providers.KemCiphertextAnnotationKey])
}

// TestMLKEM_TamperedKemCiphertextAnnotation verifies end to end that an EncryptResponse cannot
// be decrypted once its kem-ciphertext annotation has been altered — the annotation is stored
// in plaintext in etcd, which the KMS v2 contract explicitly does not protect from tampering.
//
// Two independent mechanisms reject this, and the test asserts only the observable outcome:
// Decapsulate on a modified KEM ciphertext returns a different shared secret (FIPS 203 uses
// implicit rejection rather than signalling an error), and the annotation is bound into the
// AES-GCM tag as AAD. Isolating the AAD alone requires holding the derived key constant, which
// no real KEM allows; TestMlkemAAD_BindsEnvelopeToKemCiphertext covers that as a unit test.
func TestMLKEM_TamperedKemCiphertextAnnotation(t *testing.T) {
	skipIfNoLibrary(t)

	id := newTestID(t)
	label := newTestLabel(t)

	kp, err := testCtx.GenerateMLKEMKeyPairWithLabel(id, []byte(label), crypto11.MLKEM768)
	if err != nil {
		t.Skipf("HSM does not support ML-KEM: %v — requires SoftHSMv3 from pqctoday-org/pqctoday-hsm", err)
	}
	t.Cleanup(func() { _ = kp.Delete() })

	p := newP11WithLabel(t, label, providers.AlgMLKEM)

	encResp, err := p.Encrypt(context.Background(), &k8skmsv2.EncryptRequest{Plaintext: []byte(testPlaintext)})
	require.NoError(t, err)

	// Flip one bit of the KEM ciphertext, leaving every other field of the response intact.
	tampered := make(map[string][]byte, len(encResp.GetAnnotations()))
	for k, v := range encResp.GetAnnotations() {
		tampered[k] = append([]byte(nil), v...)
	}
	require.NotEmpty(t, tampered[providers.KemCiphertextAnnotationKey])
	tampered[providers.KemCiphertextAnnotationKey][0] ^= 0x01

	_, err = p.Decrypt(context.Background(), &k8skmsv2.DecryptRequest{
		Ciphertext:  encResp.GetCiphertext(),
		KeyId:       encResp.GetKeyId(),
		Annotations: tampered,
	})
	require.Error(t, err, "a tampered kem-ciphertext annotation must not decrypt")

	// The untouched response still decrypts, proving the failure came from the tampering
	// rather than from the key pair or the envelope itself.
	decResp, err := p.Decrypt(context.Background(), &k8skmsv2.DecryptRequest{
		Ciphertext:  encResp.GetCiphertext(),
		KeyId:       encResp.GetKeyId(),
		Annotations: encResp.GetAnnotations(),
	})
	require.NoError(t, err)
	assert.Equal(t, []byte(testPlaintext), decResp.GetPlaintext())
}

// ---------------------------------------------------------------------------
// Key rotation — AES-GCM active key decrypts ciphertext from an old AES-GCM key
// ---------------------------------------------------------------------------

func TestAESGCM_KeyRotation(t *testing.T) {
	skipIfNoLibrary(t)

	// Provision old KEK (128-bit) and new KEK (256-bit) on the HSM.
	oldID := newTestID(t)
	oldLabel := newTestLabel(t)
	newID := newTestID(t)
	newLabel := newTestLabel(t)

	oldKey, err := testCtx.GenerateSecretKeyWithLabel(oldID, []byte(oldLabel), 128, crypto11.CipherAES)
	require.NoError(t, err)
	t.Cleanup(func() { _ = oldKey.Delete() })

	newKey, err := testCtx.GenerateSecretKeyWithLabel(newID, []byte(newLabel), 256, crypto11.CipherAES)
	require.NoError(t, err)
	t.Cleanup(func() { _ = newKey.Delete() })

	// Encrypt with the old key using a standalone provider.
	oldP, err := providers.NewP11(
		testConfig,
		"", oldLabel, "", "",
		providers.AlgAESGCM,
		false, nil, "", "", "", "", "",
	)
	require.NoError(t, err)

	encResp, err := oldP.Encrypt(context.Background(), &k8skmsv2.EncryptRequest{
		Plaintext: []byte(testPlaintext),
	})
	require.NoError(t, err)

	// Decrypt using a rotation provider: new key is active, old key is for decryption only.
	rotP, err := providers.NewP11(
		testConfig,
		"", newLabel, "", "",
		providers.AlgAESGCM,
		true,         // isKeyRotation
		testConfig,   // oldConfig (same token)
		"", oldLabel, // old KEK by label
		"", "", // no old HMAC
		providers.AlgAESGCM,
	)
	require.NoError(t, err)

	decResp, err := rotP.Decrypt(context.Background(), &k8skmsv2.DecryptRequest{
		Ciphertext: encResp.GetCiphertext(),
		KeyId:      encResp.GetKeyId(),
	})
	require.NoError(t, err)
	assert.Equal(t, []byte(testPlaintext), decResp.GetPlaintext())
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

func TestStatus_ReturnsKeyId(t *testing.T) {
	skipIfNoLibrary(t)

	id := newTestID(t)
	label := newTestLabel(t)

	key, err := testCtx.GenerateSecretKeyWithLabel(id, []byte(label), 256, crypto11.CipherAES)
	require.NoError(t, err)
	t.Cleanup(func() { _ = key.Delete() })

	p := newP11WithLabel(t, label, providers.AlgAESGCM)

	resp, err := p.Status(context.Background(), &k8skmsv2.StatusRequest{})
	require.NoError(t, err)
	assert.Equal(t, "v2", resp.Version)
	assert.Equal(t, "ok", resp.Healthz)
	assert.NotEmpty(t, resp.KeyId, "KeyId should be the hex CKA_ID of the KEK")
}
