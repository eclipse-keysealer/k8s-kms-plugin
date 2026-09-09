// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAlgorithmFamily_Set_Valid verifies that every documented slug is accepted.
func TestAlgorithmFamily_Set_Valid(t *testing.T) {
	valid := []string{"aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem"}
	for _, v := range valid {
		a := AlgorithmFamilyAESGCM // start from a known state
		assert.NoErrorf(t, a.Set(v), "Set(%q) should succeed", v)
		assert.Equal(t, AlgorithmFamily(v), a)
	}
}

// TestAlgorithmFamily_Set_Invalid verifies that jose constants, size-qualified names,
// and empty strings are all rejected.
func TestAlgorithmFamily_Set_Invalid(t *testing.T) {
	invalid := []string{
		"",            // empty
		"aes",         // incomplete
		"aes-256-gcm", // size-qualified — user should not need to know the size
		"A256GCM",     // jose constant
		"RSA-OAEP",    // jose constant (wrong case)
		"MLKEM768",    // jose constant
		"unknown",
	}
	for _, v := range invalid {
		a := AlgorithmFamilyAESGCM
		assert.Errorf(t, a.Set(v), "Set(%q) should fail", v)
	}
}

// TestAlgorithmFamily_Set_DoesNotMutateOnError verifies that a failed Set() leaves
// the receiver unchanged.
func TestAlgorithmFamily_Set_DoesNotMutateOnError(t *testing.T) {
	a := AlgorithmFamilyRSAOAEP
	_ = a.Set("invalid")
	assert.Equal(t, AlgorithmFamilyRSAOAEP, a)
}

func TestAlgorithmFamily_String(t *testing.T) {
	cases := []struct {
		a    AlgorithmFamily
		want string
	}{
		{AlgorithmFamilyAESGCM, "aes-gcm"},
		{AlgorithmFamilyAESCBC, "aes-cbc"},
		{AlgorithmFamilyRSAOAEP, "rsa-oaep"},
		{AlgorithmFamilyMLKEM, "ml-kem"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.a.String())
	}
}

func TestAlgorithmFamily_Type(t *testing.T) {
	a := AlgorithmFamilyAESGCM
	assert.Equal(t, "algorithmFamily", a.Type())
}

// TestValidateAlgorithmFamily covers all valid slugs and a representative set of
// invalid inputs.
func TestValidateAlgorithmFamily(t *testing.T) {
	valid := []string{"aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem"}
	for _, v := range valid {
		assert.NoErrorf(t, validateAlgorithmFamily(v), "validateAlgorithmFamily(%q) should succeed", v)
	}

	invalid := []string{
		"",
		"aes-256-gcm",
		"A256GCM",
		"RSA-OAEP",
		"MLKEM768",
		"aes gcm", // space instead of dash
	}
	for _, v := range invalid {
		err := validateAlgorithmFamily(v)
		assert.Errorf(t, err, "validateAlgorithmFamily(%q) should fail", v)
		assert.Contains(t, err.Error(), "must be one of")
	}
}

// TestSanitizeServeFlags_Valid confirms that a valid AlgorithmFamily passes
// without error.
func TestSanitizeServeFlags_Valid(t *testing.T) {
	for _, v := range []string{"aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem"} {
		f := &ServeFlags{AlgorithmFamily: v}
		assert.NoErrorf(t, sanitizeServeFlags(f), "sanitize should accept %q", v)
	}
}

// TestSanitizeServeFlags_Invalid verifies that an unsupported value (e.g. from
// a config file) is rejected with a flag-prefixed error message.
func TestSanitizeServeFlags_Invalid(t *testing.T) {
	f := &ServeFlags{AlgorithmFamily: "aes-256-gcm"}
	err := sanitizeServeFlags(f)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--algorithm-family")
	assert.Contains(t, err.Error(), "must be one of")
}

// TestSanitizeServeFlags_Empty verifies that an empty string (e.g. missing
// config key) is rejected.
func TestSanitizeServeFlags_Empty(t *testing.T) {
	f := &ServeFlags{AlgorithmFamily: ""}
	err := sanitizeServeFlags(f)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--algorithm-family")
}

// TestSanitizeServeFlags_LabelLimits verifies that CKA_LABEL strings over the
// PKCS#11 255-byte maximum are rejected with flag-prefixed error messages.
func TestSanitizeServeFlags_LabelLimits(t *testing.T) {
	atLimit := strings.Repeat("a", maxCkaLabelBytes)
	overLimit := strings.Repeat("a", maxCkaLabelBytes+1)

	cases := []struct {
		name    string
		flags   ServeFlags
		wantErr string
	}{
		{
			"all labels at limit",
			ServeFlags{AlgorithmFamily: "aes-gcm", P11Label: atLimit, DekKeyLabel: atLimit, HmacKeyLabel: atLimit},
			"",
		},
		{
			"p11-label over limit",
			ServeFlags{AlgorithmFamily: "aes-gcm", P11Label: overLimit},
			"--p11-label",
		},
		{
			"p11-key-label over limit",
			ServeFlags{AlgorithmFamily: "aes-gcm", DekKeyLabel: overLimit},
			"--p11-key-label",
		},
		{
			"p11-hmac-label over limit",
			ServeFlags{AlgorithmFamily: "aes-gcm", HmacKeyLabel: overLimit},
			"--p11-hmac-label",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := sanitizeServeFlags(&tc.flags)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// TestSanitizeServeFlags_SocketPathLimit verifies that Unix socket paths over
// 107 bytes are rejected.
func TestSanitizeServeFlags_SocketPathLimit(t *testing.T) {
	atLimit := strings.Repeat("a", maxUnixSocketPathLen)
	overLimit := strings.Repeat("a", maxUnixSocketPathLen+1)

	cases := []struct {
		name    string
		flags   ServeFlags
		wantErr string
	}{
		{
			"at limit",
			ServeFlags{AlgorithmFamily: "aes-gcm", SocketPath: atLimit},
			"",
		},
		{
			"over limit",
			ServeFlags{AlgorithmFamily: "aes-gcm", SocketPath: overLimit},
			"--socket",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := sanitizeServeFlags(&tc.flags)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}
