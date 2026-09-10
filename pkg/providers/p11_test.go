// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package providers

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/eclipse-keypont/crypto11/v2"
	"github.com/eclipse-keypont/gose"
	"github.com/eclipse-keypont/gose/jose"
	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	k8skmsv2 "k8s.io/kms/apis/v2"
)

// TestValidateHexKeyID covers all branches of the standalone validator.
func TestValidateHexKeyID(t *testing.T) {
	tooLong := strings.Repeat("a", maxCkaIDHexLen+2) // even length, over limit
	atLimit := strings.Repeat("a", maxCkaIDHexLen)

	cases := []struct {
		name    string
		input   string
		wantErr string // substring; empty means no error expected
	}{
		{"empty", "", "hex key ID is empty"},
		{"odd length", "abc", "even number of characters"},
		{"too long", tooLong, "exceeds PKCS#11 maximum"},
		{"valid short", "abcd", ""},
		{"valid single byte", "00", ""},
		{"at limit", atLimit, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHexKeyID(tc.input)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// TestUserKeyIDTooLongForKMSv2IsRejected covers the question the two limits raise: can an
// operator supply a --p11-key-id that this plugin accepts but the Kubernetes API server later
// rejects as an over-long KMS v2 KeyId?
//
// The answer must be no, and specifically because the PKCS#11 bound is the stricter of the
// two — maxCkaIDHexLen (510) sits well under maxKMSv2KeyIDSize (1024), so a CKA_ID big enough
// to trouble KMS v2 is refused roughly twice as early. The assertion on the error text is the
// point of the test: it pins down *which* layer rejects, so this stays a deliberate property
// rather than an accident that survives a future change to either constant.
func TestUserKeyIDTooLongForKMSv2IsRejected(t *testing.T) {
	cases := []struct {
		name    string
		hexLen  int
		wantErr string
	}{
		{"at PKCS#11 limit, well under KMS v2 limit", maxCkaIDHexLen, ""},
		{"over PKCS#11 limit, still under KMS v2 limit", maxCkaIDHexLen + 2, "exceeds PKCS#11 maximum"},
		{"exactly at KMS v2 limit", maxKMSv2KeyIDSize, "exceeds PKCS#11 maximum"},
		{"over KMS v2 limit", maxKMSv2KeyIDSize + 2, "exceeds PKCS#11 maximum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &P11{}
			err := p.SetKekKeyIDString(strings.Repeat("a", tc.hexLen))
			if tc.wantErr == "" {
				require.NoError(t, err)
				assert.NoError(t, validateKMSv2KeyID(p.GetKekKeyIDString()),
					"a CKA_ID this plugin accepts must always be a usable KMS v2 KeyId")
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr,
				"the PKCS#11 bound is stricter, so it must be the layer that rejects")
		})
	}
}

// TestPKCS11BoundSubsumesKMSv2Bound states the layering above as a single invariant, at the
// boundary values where it would break first.
func TestPKCS11BoundSubsumesKMSv2Bound(t *testing.T) {
	require.Less(t, maxCkaIDHexLen, maxKMSv2KeyIDSize,
		"the PKCS#11 hex bound must stay under the KMS v2 KeyId bound; see the compile-time assertion in p11.go")

	for _, hexLen := range []int{2, maxCkaIDHexLen - 2, maxCkaIDHexLen} {
		hexKeyID := strings.Repeat("a", hexLen)
		require.NoError(t, validateHexKeyID(hexKeyID))
		assert.NoError(t, validateKMSv2KeyID(hexKeyID),
			"validateHexKeyID accepted %d chars that validateKMSv2KeyID rejects", hexLen)
	}
}

// TestSetKekKeyIDFromBytes_KMSv2Bound covers the one path where the KMS v2 check does the
// rejecting rather than merely agreeing with PKCS#11: raw CKA_ID bytes that never pass through
// validateHexKeyID. This is the shape of the value GetKeyIDAndLabel receives from the token
// when the operator starts the plugin with --p11-key-label instead of --p11-key-id.
func TestSetKekKeyIDFromBytes_KMSv2Bound(t *testing.T) {
	cases := []struct {
		name    string
		ckaID   []byte
		wantErr string
	}{
		{"nil", nil, "keyID cannot be nil"},
		{"empty", []byte{}, "KeyId is empty"},
		{"typical 8-byte CKA_ID", bytes.Repeat([]byte{0xAB}, 8), ""},
		{"hex length exactly at KMS v2 limit", bytes.Repeat([]byte{0xAB}, maxKMSv2KeyIDSize/2), ""},
		{"hex length one byte over KMS v2 limit", bytes.Repeat([]byte{0xAB}, maxKMSv2KeyIDSize/2+1), "exceeds the Kubernetes API server maximum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &P11{}
			err := p.SetKekKeyIDFromBytes(tc.ckaID)
			if tc.wantErr == "" {
				require.NoError(t, err)
				assert.LessOrEqual(t, len(p.GetKekKeyIDString()), maxKMSv2KeyIDSize)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Nil(t, p.kekCkaID, "a rejected CKA_ID must not be stored")
		})
	}
}

// Tests for P11 struct methods
func TestP11_SetKekKeyIdString(t *testing.T) {
	p := &P11{}

	hexKeyID := "abcd1234"
	err := p.SetKekKeyIDString(hexKeyID)

	assert.NoError(t, err)
	expected, _ := hex.DecodeString(hexKeyID)
	assert.Equal(t, expected, p.kekCkaID)
}

func TestP11_SetKekKeyIdString_Validation(t *testing.T) {
	tooLong := strings.Repeat("a", maxCkaIDHexLen+2) // even length, over limit
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "hex key ID is empty"},
		{"odd length", "abc", "even number of characters"},
		{"too long", tooLong, "exceeds PKCS#11 maximum"},
		{"invalid hex chars even length", "zzzz", "invalid hex KeyID"},
		{"valid", "abcd1234", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &P11{}
			err := p.SetKekKeyIDString(tc.input)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestP11_SetHmacKeyIdString_Validation(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "hex key ID is empty"},
		{"odd length", "a", "even number of characters"},
		{"valid", "ef567890", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &P11{}
			err := p.SetHmacKeyIDString(tc.input)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestP11_SetOldHmacKeyIdString_Validation(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "hex key ID is empty"},
		{"odd length", "a", "even number of characters"},
		{"valid", "1234abcd", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &P11{}
			err := p.SetOldHmacKeyIDString(tc.input)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestP11_SetOldKekKeyIdString_Validation(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "hex key ID is empty"},
		{"odd length", "a", "even number of characters"},
		{"valid", "5678cdef", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &P11{}
			err := p.SetOldKekKeyIDString(tc.input)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// TestP11_DecryptWithContext_InvalidKeyId verifies that validateHexKeyID is enforced
// on the DecryptRequest.KeyId when the decryptor is not yet cached.
func TestP11_DecryptWithContext_InvalidKeyId(t *testing.T) {
	p := &P11{
		kekCkaID:        []byte{0x01},
		algorithmFamily: AlgAESGCM,
		decryptors:      map[string]gose.JweDecryptor{},
	}

	cases := []struct {
		name  string
		keyID string
	}{
		{"empty key ID", ""},
		{"odd length key ID", "abc"},
		{"oversized key ID", strings.Repeat("a", maxCkaIDHexLen+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &k8skmsv2.DecryptRequest{
				KeyId:      tc.keyID,
				Ciphertext: []byte("mock"),
			}
			_, err := p.decryptWithContext(req, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid key ID")
		})
	}
}

func TestP11_GetKekKeyIdString(t *testing.T) {
	p := &P11{
		kekCkaID: []byte{0xab, 0xcd, 0x12, 0x34},
	}

	result := p.GetKekKeyIDString()

	assert.Equal(t, "abcd1234", result)
}

func TestP11_GetKekCkaLabelByteA(t *testing.T) {
	p := &P11{
		kekCkaLabel: "test-label",
	}

	result := p.GetKekCkaLabelByteA()

	assert.Equal(t, []byte("test-label"), result)
}

func TestP11_SetHmacKeyIdString(t *testing.T) {
	p := &P11{}

	hexHmacKeyID := "ef567890"
	err := p.SetHmacKeyIDString(hexHmacKeyID)

	assert.NoError(t, err)
	expected, _ := hex.DecodeString(hexHmacKeyID)
	assert.Equal(t, expected, p.hmacCkaID)
}

func TestP11_GetHmacKeyIdString(t *testing.T) {
	p := &P11{
		hmacCkaID: []byte{0xef, 0x56, 0x78, 0x90},
	}

	result := p.GetHmacKeyIDString()

	assert.Equal(t, "ef567890", result)
}

func TestP11_SetOldHmacKeyIdString(t *testing.T) {
	p := &P11{}

	hexOldHmacKeyID := "1234abcd"
	err := p.SetOldHmacKeyIDString(hexOldHmacKeyID)

	assert.NoError(t, err)
	expected, _ := hex.DecodeString(hexOldHmacKeyID)
	assert.Equal(t, expected, p.oldHmacCkaID)
}

func TestP11_SetOldKekKeyIdString(t *testing.T) {
	p := &P11{}

	hexOldKeyID := "5678cdef"
	err := p.SetOldKekKeyIDString(hexOldKeyID)

	assert.NoError(t, err)
	expected, _ := hex.DecodeString(hexOldKeyID)
	assert.Equal(t, expected, p.oldKekCkaID)
}

// Tests for Status method
func TestP11_Status_Success(t *testing.T) {
	p := &P11{
		kekCkaID: []byte{0x12, 0x34, 0x56, 0x78},
	}

	ctx := context.Background()
	req := &k8skmsv2.StatusRequest{}

	resp, err := p.Status(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "v2", resp.Version)
	assert.Equal(t, "ok", resp.Healthz)
	assert.Equal(t, "12345678", resp.KeyId)
}

func TestP11_Status_NilKekId(t *testing.T) {
	p := &P11{
		kekCkaID: nil,
	}

	ctx := context.Background()
	req := &k8skmsv2.StatusRequest{}

	_, err := p.Status(ctx, req)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "KEK ID is nil")
}

func TestP11_Status_EmptyKekId(t *testing.T) {
	p := &P11{
		kekCkaID: []byte{},
	}

	ctx := context.Background()
	req := &k8skmsv2.StatusRequest{}

	_, err := p.Status(ctx, req)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "KEK ID is empty")
}

// Create a mock JWE with a valid IV
var validJWEs = []string{
	"eyJhbGciOiJBMjU2Q0JDIiwia2lkIjoiNjQ2MzYxMzgzNTM5MzEzMjYzNjMzNTY1MzczMTMyNjQiLCJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJfdGhhbGVzX2FhZCI6IkFBQUFBQUFBQUNBIiwiZW5jIjoiQTI1NkNCQyJ9..RCs4v0hOW9lHFwDOo7itNA.encrypted_data.tag",
}

// Tests for getIVFromDecryptRequest function
func TestP11_GetIVFromDecryptRequest_ValidIV(t *testing.T) {

	for _, mockJWE := range validJWEs {
		t.Run(mockJWE, func(t *testing.T) {
			// Expected IV
			realIv, err := base64.RawURLEncoding.DecodeString("RCs4v0hOW9lHFwDOo7itNA")
			assert.NoError(t, err)

			req := &k8skmsv2.DecryptRequest{
				Ciphertext: []byte(mockJWE),
			}

			// get IV from DecryptRequest
			iv, err := getIVFromDecryptRequest(req)

			// Expect no error
			assert.NoError(t, err)
			assert.Equalf(t, realIv, iv, "getIVFromDecryptRequest() = %v, want %v", iv, realIv)
		})
	}
}

// a list of invalid JWEs, with a focus on the invalid IV
var invalidJWEs = []string{
	// Invalid base64 encoding
	"eyJhbGciOiJBMjU2Q0JDIiwia2lkIjoiNjQ2MzYxMzgzNTM5MzEzMjYzNjMzNTY1MzczMTMyNjQiLCJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJfdGhhbGVzX2FhZCI6IkFBQUFBQUFBQUNBIiwiZW5jIjoiQTI1NkNCQyJ9..!.encrypted_data.tag",

	// Missing IV segment
	"eyJhbGciOiJBMjU2Q0JDIiwia2lkIjoiNjQ2MzYxMzgzNTM5MzEzMjYzNjMzNTY1MzczMTMyNjQiLCJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJfdGhhbGVzX2FhZCI6IkFBQUFBQUFBQUNBIiwiZW5jIjoiQTI1NkNCQyJ9.encrypted_data.tag",

	// Invalid JSON structure
	"eyJhbGciOiJBMjU2Q0JDIiwia2lkIjoiNjQ2MzYxMzgzNTM5MzEzMjYzNjMzNTY1MzczMTMyNjQiLCJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJfdGhhbGVzX2FhZCI6IkFBQUFBQUFBQUNBIiwiZW5jIjoiQTI1NkNCQyJ9..IV..encrypted_data.tag",

	// missing IV (empty IV segment)
	"eyJhbGciOiJBMjU2Q0JDIiwia2lkIjoiNjQ2MzYxMzgzNTM5MzEzMjYzNjMzNTY1MzczMTMyNjQiLCJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJfdGhhbGVzX2FhZCI6IkFBQUFBQUFBQUNBIiwiZW5jIjoiQTI1NkNCQyJ9...encrypted_data.tag",

	// Empty JWE
	".....",
	"",
}

func TestP11_GetIVFromDecryptRequest_InvalidIV(t *testing.T) {
	for _, mockJWE := range invalidJWEs {
		t.Run(mockJWE, func(t *testing.T) {

			req := &k8skmsv2.DecryptRequest{
				Ciphertext: []byte(mockJWE),
			}

			// get IV from DecryptRequest
			_, err := getIVFromDecryptRequest(req)

			// Expect an error since the IV is invalid
			assert.Error(t, err)
		})
	}
}

func TestP11_NewP11_AllEmptyArgs(t *testing.T) {

	emptyActiveCfg := &crypto11.Config{}
	emptyOldCfg := &crypto11.Config{}

	_, err := NewP11(emptyActiveCfg, "", "", "", "", "", false, emptyOldCfg, "", "", "", "", "")
	assert.Error(t, err)
}

// TestAlgSentinelValues verifies that all routing sentinels carry the expected
// slug strings. Changing these values would break backwards-compatible config files.
func TestAlgSentinelValues(t *testing.T) {
	assert.Equal(t, jose.Alg("aes-gcm"), AlgAESGCM)
	assert.Equal(t, jose.Alg("aes-cbc"), AlgAESCBC)
	assert.Equal(t, jose.Alg("rsa-oaep"), AlgRSAOAEP)
	assert.Equal(t, jose.Alg("ml-kem"), AlgMLKEM)
}

// TestIsPKCS11AuthenticationError covers nil, non-pkcs11, and CKR_PIN_INCORRECT inputs.
func TestIsPKCS11AuthenticationError(t *testing.T) {
	assert.False(t, IsPKCS11AuthenticationError(nil))
	assert.False(t, IsPKCS11AuthenticationError(errors.New("plain error")))

	// Wrap a pkcs11.Error so errors.Unwrap returns it.
	pinErr := fmt.Errorf("login: %w", pkcs11.Error(pkcs11.CKR_PIN_INCORRECT))
	assert.True(t, IsPKCS11AuthenticationError(pinErr))

	otherErr := fmt.Errorf("login: %w", pkcs11.Error(pkcs11.CKR_GENERAL_ERROR))
	assert.False(t, IsPKCS11AuthenticationError(otherErr))
}

// TestPutEncapsulation_NilAnnotations covers the common case: a freshly built
// EncryptResponse with a nil Annotations map must be lazily initialized.
func TestPutEncapsulation_NilAnnotations(t *testing.T) {
	resp := &k8skmsv2.EncryptResponse{}
	ct := []byte{0x01, 0x02, 0x03}

	putEncapsulation(resp, ct)

	require.NotNil(t, resp.Annotations)
	assert.Equal(t, ct, resp.Annotations[KemCiphertextAnnotationKey])
	assert.Len(t, resp.Annotations, 1, "putEncapsulation must not touch any other annotation key")
}

// TestPutEncapsulation_ExistingAnnotations covers a pre-populated Annotations map: the
// KEM ciphertext must be added alongside existing entries, not replace the map.
func TestPutEncapsulation_ExistingAnnotations(t *testing.T) {
	resp := &k8skmsv2.EncryptResponse{
		Annotations: map[string][]byte{"other.example.org": []byte("keep-me")},
	}
	ct := []byte{0xAA, 0xBB}

	putEncapsulation(resp, ct)

	assert.Equal(t, []byte("keep-me"), resp.Annotations["other.example.org"])
	assert.Equal(t, ct, resp.Annotations[KemCiphertextAnnotationKey])
}

// TestGetEncapsulation_Present covers a DecryptRequest carrying the kem-ciphertext annotation
// round-tripped from a prior Encrypt call.
func TestGetEncapsulation_Present(t *testing.T) {
	ct := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	req := &k8skmsv2.DecryptRequest{
		Annotations: map[string][]byte{KemCiphertextAnnotationKey: ct},
	}

	got, ok := getEncapsulation(req)
	assert.True(t, ok)
	assert.Equal(t, ct, got)
}

// TestGetEncapsulation_Absent covers a DecryptRequest for an object produced by a
// classical (non-ML-KEM) algorithm family, which never carries this annotation.
func TestGetEncapsulation_Absent(t *testing.T) {
	req := &k8skmsv2.DecryptRequest{}

	got, ok := getEncapsulation(req)
	assert.False(t, ok)
	assert.Nil(t, got)
}

// TestPutAlgorithmFamily_NilAnnotations covers the common case: a freshly built
// EncryptResponse with a nil Annotations map must be lazily initialized.
func TestPutAlgorithmFamily_NilAnnotations(t *testing.T) {
	resp := &k8skmsv2.EncryptResponse{}

	putAlgorithmFamily(resp, AlgMLKEM)

	require.NotNil(t, resp.Annotations)
	assert.Equal(t, []byte("ml-kem"), resp.Annotations[AlgorithmFamilyAnnotationKey])
}

// TestPutAlgorithmFamily_ExistingAnnotations covers a pre-populated Annotations map (e.g.
// one that already carries the ML-KEM kem-ciphertext annotation): the algorithm-family entry must be
// added alongside existing entries, not replace the map.
func TestPutAlgorithmFamily_ExistingAnnotations(t *testing.T) {
	resp := &k8skmsv2.EncryptResponse{
		Annotations: map[string][]byte{KemCiphertextAnnotationKey: {0x01, 0x02}},
	}

	putAlgorithmFamily(resp, AlgAESGCM)

	assert.Equal(t, []byte{0x01, 0x02}, resp.Annotations[KemCiphertextAnnotationKey])
	assert.Equal(t, []byte("aes-gcm"), resp.Annotations[AlgorithmFamilyAnnotationKey])
}

// TestMlkemAAD_Layout pins the additional authenticated data encoding: the version-bearing
// context string followed by the KEM ciphertext, with nothing between them.
func TestMlkemAAD_Layout(t *testing.T) {
	kemCt := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	aad := mlkemAAD(kemCt)

	assert.Equal(t, append([]byte(mlkemAADContext), kemCt...), aad)
	assert.True(t, strings.HasPrefix(string(aad), mlkemAADContext),
		"the context string must come first so it domain-separates the envelope format")
}

// TestMlkemAAD_DistinctPerKemCiphertext covers the property the binding relies on: two
// different KEM ciphertexts must never produce the same AAD.
func TestMlkemAAD_DistinctPerKemCiphertext(t *testing.T) {
	assert.NotEqual(t, mlkemAAD([]byte{0x01, 0x02}), mlkemAAD([]byte{0x01, 0x03}))
	// A KEM ciphertext that is a prefix of another must not collide either.
	assert.NotEqual(t, mlkemAAD([]byte{0x01}), mlkemAAD([]byte{0x01, 0x00}))
}

// TestMlkemAAD_EmptyKemCiphertext covers the degenerate input: the context string alone still
// yields a usable, non-empty AAD rather than panicking or returning nil.
func TestMlkemAAD_EmptyKemCiphertext(t *testing.T) {
	assert.Equal(t, []byte(mlkemAADContext), mlkemAAD(nil))
	assert.Equal(t, []byte(mlkemAADContext), mlkemAAD([]byte{}))
}

// TestMlkemAAD_BindsEnvelopeToKemCiphertext exercises the whole point of the AAD against a
// real AES-GCM instance, without needing an HSM: an envelope sealed under one KEM ciphertext
// must not open under another, even though the key and nonce are unchanged.
//
// This is the failure the HSM path would otherwise reach only indirectly, via a mismatched
// shared secret. Here the derived key is held constant so the AAD is the only thing that
// differs, which is what isolates the binding itself.
func TestMlkemAAD_BindsEnvelopeToKemCiphertext(t *testing.T) {
	key := make([]byte, 32) // fixed all-zero key: this test is about the AAD, not the KDF
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := make([]byte, mlkemNonceSize)
	seed := []byte("32-byte-DEK-seed-goes-right-here")
	kemCt := []byte{0x01, 0x02, 0x03, 0x04}

	sealed := aead.Seal(nil, nonce, seed, mlkemAAD(kemCt))

	// The matching KEM ciphertext opens the envelope.
	got, err := aead.Open(nil, nonce, sealed, mlkemAAD(kemCt))
	require.NoError(t, err)
	assert.Equal(t, seed, got)

	// A tampered KEM ciphertext annotation does not.
	tampered := []byte{0x01, 0x02, 0x03, 0x05}
	_, err = aead.Open(nil, nonce, sealed, mlkemAAD(tampered))
	assert.Error(t, err, "swapping the kem-ciphertext annotation must fail the tag check")

	// So does dropping the AAD entirely, which is what a pre-v1 envelope reader would pass.
	_, err = aead.Open(nil, nonce, sealed, nil)
	assert.Error(t, err, "an envelope sealed with AAD must not open without it")
}

// mockJweEncryptor is a no-op gose.JweEncryptor used in concurrency tests.
type mockJweEncryptor struct{}

func (m *mockJweEncryptor) Encrypt(_, _ []byte) (string, error) { return "mock.jwe.token", nil }

// mockJweDecryptor is a no-op gose.JweDecryptor used in concurrency tests.
type mockJweDecryptor struct{}

func (m *mockJweDecryptor) Decrypt(_ string) ([]byte, []byte, error) {
	return []byte("plaintext"), nil, nil
}

// TestP11_MapAccess_Race verifies that concurrent reads (Encrypt, Decrypt) and
// writes (SetEncryptors, SetDecryptors) on the encryptor/decryptor maps do not
// produce data races. Run with: go test -race ./pkg/providers/...
//
// The test avoids any HSM interaction by pre-populating the maps so that
// Encrypt and Decrypt find a cached entry and return early without calling
// into crypto11.
func TestP11_MapAccess_Race(_ *testing.T) {
	const hexID = "01"
	p := &P11{kekCkaID: []byte{0x01}}

	_ = p.SetEncryptors(map[string]gose.JweEncryptor{hexID: &mockJweEncryptor{}})
	_ = p.SetDecryptors(map[string]gose.JweDecryptor{hexID: &mockJweDecryptor{}})

	ctx := context.Background()
	encReq := &k8skmsv2.EncryptRequest{Plaintext: []byte("hello")}
	decReq := &k8skmsv2.DecryptRequest{KeyId: hexID, Ciphertext: []byte("mock.jwe.token")}

	var wg sync.WaitGroup
	const n = 50

	for i := 0; i < n; i++ {
		wg.Add(4)

		// writers: replace the whole map
		go func() {
			defer wg.Done()
			_ = p.SetEncryptors(map[string]gose.JweEncryptor{hexID: &mockJweEncryptor{}})
		}()
		go func() {
			defer wg.Done()
			_ = p.SetDecryptors(map[string]gose.JweDecryptor{hexID: &mockJweDecryptor{}})
		}()

		// readers: hit the cached-entry path — no HSM calls needed
		go func() {
			defer wg.Done()
			_, _ = p.Encrypt(ctx, encReq)
		}()
		go func() {
			defer wg.Done()
			_, _ = p.Decrypt(ctx, decReq)
		}()
	}

	wg.Wait()
}

// TestP11_SetEncryptor_Race verifies that single-entry writes (SetEncryptor,
// SetDecryptor) racing against full-map replacements (SetEncryptors,
// SetDecryptors) do not produce data races.
func TestP11_SetEncryptor_Race(_ *testing.T) {
	p := &P11{kekCkaID: []byte{0x01}}
	_ = p.SetEncryptors(map[string]gose.JweEncryptor{})
	_ = p.SetDecryptors(map[string]gose.JweDecryptor{})

	var wg sync.WaitGroup
	const n = 50

	for i := 0; i < n; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			_ = p.SetEncryptor(&mockJweEncryptor{})
		}()
		go func() {
			defer wg.Done()
			_ = p.SetEncryptors(map[string]gose.JweEncryptor{"01": &mockJweEncryptor{}})
		}()
		go func() {
			defer wg.Done()
			_ = p.SetDecryptor(&mockJweDecryptor{})
		}()
		go func() {
			defer wg.Done()
			_ = p.SetDecryptors(map[string]gose.JweDecryptor{"01": &mockJweDecryptor{}})
		}()
	}

	wg.Wait()
}

func TestP11_NewP11_ConfigEmptyArgs(t *testing.T) {

	validActiveCfg := &crypto11.Config{
		Path:       "/some/path/to/lib.so",
		TokenLabel: "label",
		Pin:        "1234",
	}
	validOldCfg := &crypto11.Config{
		Path:       "/some/path/to/oldlib.so",
		TokenLabel: "oldlabel",
		Pin:        "5678",
	}

	_, err := NewP11(validActiveCfg, "", "", "", "", "", false, validOldCfg, "", "", "", "", "")
	assert.Error(t, err)
}

// TestValidateCkaLabel covers all branches of the CKA_LABEL validator.
func TestValidateCkaLabel(t *testing.T) {
	atLimit := strings.Repeat("a", maxCkaLabelSize)
	overLimit := strings.Repeat("a", maxCkaLabelSize+1)
	// "é" is 2 bytes in UTF-8; len() counts bytes, not runes.
	multibyteOver := strings.Repeat("é", maxCkaLabelSize/2+1) // 128×2 = 256 bytes

	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "CKA_LABEL is empty"},
		{"at limit", atLimit, ""},
		{"over limit", overLimit, "exceeds PKCS#11 maximum"},
		{"valid short", "my-key-label", ""},
		{"multibyte over limit", multibyteOver, "exceeds PKCS#11 maximum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCkaLabel(tc.input)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// TestGetKeyIdAndLabel_LabelTooLong confirms that validateCkaLabel fires in
// GetKeyIDAndLabel before any HSM call is attempted.
func TestGetKeyIdAndLabel_LabelTooLong(t *testing.T) {
	p := &P11{algorithmFamily: AlgAESGCM}
	tooLong := strings.Repeat("a", maxCkaLabelSize+1)

	_, _, err := GetKeyIDAndLabel(p, "", tooLong)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds PKCS#11 maximum")
}

// noopHandler is a grpc.UnaryHandler stub that returns success without side effects.
var noopHandler grpc.UnaryHandler = func(_ context.Context, _ interface{}) (interface{}, error) {
	return nil, nil
}

// requireGRPCCode is a test helper that asserts a gRPC status code on an error.
func requireGRPCCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok, "expected a gRPC status error")
	assert.Equal(t, want, st.Code())
}

// TestUnaryInterceptor_EncryptRequest_Validation checks that empty and oversized
// plaintext are rejected before the handler is reached.
func TestUnaryInterceptor_EncryptRequest_Validation(t *testing.T) {
	p := &P11{}
	ctx := context.Background()
	info := &grpc.UnaryServerInfo{}

	cases := []struct {
		name     string
		req      *k8skmsv2.EncryptRequest
		wantCode codes.Code // codes.OK means no interceptor error expected
	}{
		{"nil plaintext", &k8skmsv2.EncryptRequest{}, codes.InvalidArgument},
		{"empty plaintext", &k8skmsv2.EncryptRequest{Plaintext: []byte{}}, codes.InvalidArgument},
		{"plaintext too large", &k8skmsv2.EncryptRequest{Plaintext: make([]byte, maxPlaintextSize+1)}, codes.InvalidArgument},
		{"valid plaintext", &k8skmsv2.EncryptRequest{Plaintext: []byte("hello")}, codes.OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.UnaryInterceptor(ctx, tc.req, info, noopHandler)
			if tc.wantCode == codes.OK {
				assert.NoError(t, err)
			} else {
				requireGRPCCode(t, err, tc.wantCode)
			}
		})
	}
}

// TestUnaryInterceptor_DecryptRequest_Validation checks that missing key ID,
// empty ciphertext, and oversized ciphertext are rejected before the handler.
func TestUnaryInterceptor_DecryptRequest_Validation(t *testing.T) {
	p := &P11{kekCkaID: []byte{0x01}}
	ctx := context.Background()
	info := &grpc.UnaryServerInfo{}
	validKeyID := p.GetKekKeyIDString()

	cases := []struct {
		name     string
		req      *k8skmsv2.DecryptRequest
		wantCode codes.Code
	}{
		{"empty key ID", &k8skmsv2.DecryptRequest{KeyId: "", Ciphertext: []byte("data")}, codes.InvalidArgument},
		{"empty ciphertext", &k8skmsv2.DecryptRequest{KeyId: validKeyID, Ciphertext: []byte{}}, codes.InvalidArgument},
		{"ciphertext too large", &k8skmsv2.DecryptRequest{KeyId: validKeyID, Ciphertext: make([]byte, maxKMSv2CiphertextSize+1)}, codes.InvalidArgument},
		{"valid request", &k8skmsv2.DecryptRequest{KeyId: validKeyID, Ciphertext: []byte("mock")}, codes.OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.UnaryInterceptor(ctx, tc.req, info, noopHandler)
			if tc.wantCode == codes.OK {
				assert.NoError(t, err)
			} else {
				requireGRPCCode(t, err, tc.wantCode)
			}
		})
	}
}
