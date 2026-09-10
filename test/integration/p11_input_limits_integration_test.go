// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package integration

import (
	"strings"
	"testing"

	"github.com/eclipse-keypont/crypto11/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/providers"
)

// PKCS#11 attribute bounds, restated here because the providers package keeps them unexported.
// Names follow the same rule as the originals: *HexLen counts HEX CHARACTERS, *Size counts
// BYTES. Drift between these and the real constants shows up as a test failure, which is the
// point of restating them.
const (
	maxCkaIDHexLen  = 510 // hex characters; encodes 255 raw CKA_ID bytes
	maxCkaLabelSize = 255 // bytes of UTF-8 label text, no hex encoding involved
)

// Values one byte past each PKCS#11 bound, and the largest values that must still be accepted.
// The CKA_ID helpers build hex strings, so each "ab" pair is one raw byte — hence /2.
func overMaxHexID() string { return strings.Repeat("ab", maxCkaIDHexLen/2+1) }
func atMaxHexID() string   { return strings.Repeat("ab", maxCkaIDHexLen/2) }

// The CKA_LABEL helpers build plain text, so one character is one byte — no halving.
func overMaxLabel() string { return strings.Repeat("L", maxCkaLabelSize+1) }
func atMaxLabel() string   { return strings.Repeat("L", maxCkaLabelSize) }

// newRealKEK provisions an AES-256 KEK on the token and returns its CKA_LABEL.
//
// Every case below needs the lookups that run *before* the flag under test to succeed —
// NewP11 resolves the active KEK first, so without a real key it fails there and the parameter
// being tested is never reached. That is a trap worth naming: an earlier version of this test
// passed for the wrong reason, reporting "key ... was not found" instead of a length error.
//
// There is deliberately no HMAC counterpart to this helper. The AES-CBC cases look like they
// need one, but every HMAC length validator in NewP11 runs before the corresponding HMAC
// lookup, so an over-long HMAC identifier is rejected without the key ever being resolved.
// Only the KEK is resolved early enough to need provisioning.
func newRealKEK(t *testing.T) string {
	t.Helper()
	label := newTestLabel(t)
	key, err := testCtx.GenerateSecretKeyWithLabel(newTestID(t), []byte(label), 256, crypto11.CipherAES)
	require.NoError(t, err, "provision AES-256 KEK")
	t.Cleanup(func() { _ = key.Delete() })
	return label
}

// TestNewP11_RejectsOverMaxKeyIdentifiers drives NewP11 against a live token with each of the
// eight CKA_ID / CKA_LABEL flags set one byte past its PKCS#11 bound, and asserts the plugin
// refuses to start with a length error.
//
// These are operator inputs, so the goal is a clear startup failure rather than an oversized
// attribute handed to the token, which may truncate it, reject it obscurely, or accept it and
// produce a KeyId that KMS v2 later refuses. Reaching this code needs a real crypto11 context,
// which is why it lives in the integration suite: NewP11 calls crypto11.Configure first.
//
// Flag -> NewP11 parameter mapping:
//
//	--p11-key-id         kekkeyid          --old-p11-key-id     oldKekkeyid
//	--p11-key-label      k8sKekLabel       --old-p11-key-label  oldKekCkaLabel
//	--p11-hmac-id        hmacCkaID         --old-p11-hmac-id    oldHmacCkaID
//	--p11-hmac-label     hmacKeyLabel      --old-p11-hmac-label oldHmacKeyLabel
//
// The HMAC parameters are only consulted for AES-CBC, so those cases select that family for the
// relevant (active or old) side.
func TestNewP11_RejectsOverMaxKeyIdentifiers(t *testing.T) {
	skipIfNoLibrary(t)

	const wantHexErr = "exceeds PKCS#11 maximum"
	const wantLabelErr = "CKA_LABEL length"

	cases := []struct {
		name    string
		flag    string
		wantErr string
		build   func(t *testing.T) (*providers.P11, error)
	}{
		{
			name: "over-max CKA_ID", flag: "--p11-key-id", wantErr: wantHexErr,
			build: func(_ *testing.T) (*providers.P11, error) {
				return providers.NewP11(testConfig,
					overMaxHexID(), "", "", "", providers.AlgAESGCM,
					false, nil, "", "", "", "", "")
			},
		},
		{
			name: "over-max CKA_LABEL", flag: "--p11-key-label", wantErr: wantLabelErr,
			build: func(_ *testing.T) (*providers.P11, error) {
				return providers.NewP11(testConfig,
					"", overMaxLabel(), "", "", providers.AlgAESGCM,
					false, nil, "", "", "", "", "")
			},
		},
		{
			name: "over-max CKA_ID", flag: "--p11-hmac-id", wantErr: wantHexErr,
			build: func(t *testing.T) (*providers.P11, error) {
				return providers.NewP11(testConfig,
					"", newRealKEK(t), "", overMaxHexID(), providers.AlgAESCBC,
					false, nil, "", "", "", "", "")
			},
		},
		{
			name: "over-max CKA_LABEL", flag: "--p11-hmac-label", wantErr: wantLabelErr,
			build: func(t *testing.T) (*providers.P11, error) {
				return providers.NewP11(testConfig,
					"", newRealKEK(t), overMaxLabel(), "", providers.AlgAESCBC,
					false, nil, "", "", "", "", "")
			},
		},
		{
			name: "over-max CKA_ID", flag: "--old-p11-key-id", wantErr: wantHexErr,
			build: func(t *testing.T) (*providers.P11, error) {
				return providers.NewP11(testConfig,
					"", newRealKEK(t), "", "", providers.AlgAESGCM,
					true, testConfig, overMaxHexID(), "", "", "", providers.AlgAESGCM)
			},
		},
		{
			name: "over-max CKA_LABEL", flag: "--old-p11-key-label", wantErr: wantLabelErr,
			build: func(t *testing.T) (*providers.P11, error) {
				return providers.NewP11(testConfig,
					"", newRealKEK(t), "", "", providers.AlgAESGCM,
					true, testConfig, "", overMaxLabel(), "", "", providers.AlgAESGCM)
			},
		},
		{
			name: "over-max CKA_ID", flag: "--old-p11-hmac-id", wantErr: wantHexErr,
			build: func(t *testing.T) (*providers.P11, error) {
				return providers.NewP11(testConfig,
					"", newRealKEK(t), "", "", providers.AlgAESGCM,
					true, testConfig, "", newRealKEK(t), "", overMaxHexID(), providers.AlgAESCBC)
			},
		},
		{
			name: "over-max CKA_LABEL", flag: "--old-p11-hmac-label", wantErr: wantLabelErr,
			build: func(t *testing.T) (*providers.P11, error) {
				return providers.NewP11(testConfig,
					"", newRealKEK(t), "", "", providers.AlgAESGCM,
					true, testConfig, "", newRealKEK(t), overMaxLabel(), "", providers.AlgAESCBC)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.flag+" "+tc.name, func(t *testing.T) {
			p, err := tc.build(t)
			if p != nil {
				defer func() { _ = p.Close() }()
			}
			require.Error(t, err, "%s past its PKCS#11 bound must stop the plugin from starting", tc.flag)
			assert.Contains(t, err.Error(), tc.wantErr,
				"%s must be rejected by the length validator, not by an incidental HSM lookup failure", tc.flag)
		})
	}
}

// TestNewP11_AcceptsMaxSizedKeyIdentifiers is the other half of the boundary: an identifier of
// exactly the maximum length must not be rejected *for its length*.
//
// No key carries these identifiers, so NewP11 still fails — but on lookup, not validation.
// Asserting the error is not a length complaint is what keeps the bound from silently drifting
// off by one.
func TestNewP11_AcceptsMaxSizedKeyIdentifiers(t *testing.T) {
	skipIfNoLibrary(t)

	cases := []struct {
		flag  string
		build func() (*providers.P11, error)
	}{
		{
			flag: "--p11-key-id",
			build: func() (*providers.P11, error) {
				return providers.NewP11(testConfig,
					atMaxHexID(), "", "", "", providers.AlgAESGCM,
					false, nil, "", "", "", "", "")
			},
		},
		{
			flag: "--p11-key-label",
			build: func() (*providers.P11, error) {
				return providers.NewP11(testConfig,
					"", atMaxLabel(), "", "", providers.AlgAESGCM,
					false, nil, "", "", "", "", "")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.flag+" at PKCS#11 maximum", func(t *testing.T) {
			p, err := tc.build()
			if p != nil {
				defer func() { _ = p.Close() }()
			}
			if err == nil {
				return // a token that happens to hold such a key is fine too
			}
			assert.NotContains(t, err.Error(), "exceeds PKCS#11 maximum",
				"an identifier of exactly the maximum length must not be rejected for its length")
			assert.NotContains(t, err.Error(), "CKA_LABEL length",
				"a label of exactly the maximum length must not be rejected for its length")
		})
	}
}
