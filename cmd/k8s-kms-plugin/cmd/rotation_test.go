// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeRotationFlags_Valid(t *testing.T) {
	f := &RotationFlags{OldAlgorithmFamily: "aes-gcm"}
	assert.NoError(t, sanitizeRotationFlags(f))
}

func TestSanitizeRotationFlags_InvalidAlgorithm(t *testing.T) {
	f := &RotationFlags{OldAlgorithmFamily: "unknown"}
	err := sanitizeRotationFlags(f)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--old-algorithm-family")
}

// TestSanitizeRotationFlags_LabelLimits verifies that oversized old-KEK labels
// are rejected with flag-prefixed error messages.
func TestSanitizeRotationFlags_LabelLimits(t *testing.T) {
	atLimit := strings.Repeat("a", maxCkaLabelBytes)
	overLimit := strings.Repeat("a", maxCkaLabelBytes+1)

	cases := []struct {
		name    string
		flags   RotationFlags
		wantErr string
	}{
		{
			"labels at limit",
			RotationFlags{
				OldAlgorithmFamily: "aes-gcm",
				OldP11Label:        atLimit,
				OldDekKeyLabel:     atLimit,
				OldHmacKeyLabel:    atLimit,
			},
			"",
		},
		{
			"old-p11-label over limit",
			RotationFlags{OldAlgorithmFamily: "aes-gcm", OldP11Label: overLimit},
			"--old-p11-label",
		},
		{
			"old-p11-key-label over limit",
			RotationFlags{OldAlgorithmFamily: "aes-gcm", OldDekKeyLabel: overLimit},
			"--old-p11-key-label",
		},
		{
			"old-p11-hmac-label over limit",
			RotationFlags{OldAlgorithmFamily: "aes-gcm", OldHmacKeyLabel: overLimit},
			"--old-p11-hmac-label",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := sanitizeRotationFlags(&tc.flags)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// ── provider wiring ───────────────────────────────────────────────────────────

// withRotationFlags installs a serve/rotation flag pair naming two *different* tokens and
// restores the package state afterwards. Two different tokens is the case that matters: when both
// KEKs live on the same one — which every existing rotation test does, by design — crossing the
// two configurations is invisible.
func withRotationFlags(t *testing.T, activeLib, oldLib string) {
	t.Helper()
	savedServe, savedRotation := flagsServe, flagsRotation
	t.Cleanup(func() { flagsServe, flagsRotation = savedServe, savedRotation })

	flagsServe = ServeFlags{
		Provider:        "p11",
		P11Lib:          activeLib,
		P11Label:        "active-token",
		P11Pin:          "1234",
		DekKeyLabel:     "active-kek",
		AlgorithmFamily: string(AlgorithmFamilyAESGCM),
	}
	flagsRotation = RotationFlags{
		OldProvider:        "p11",
		OldP11Lib:          oldLib,
		OldP11Label:        "old-token",
		OldP11Pin:          "5678",
		OldDekKeyLabel:     "old-kek",
		OldAlgorithmFamily: string(AlgorithmFamilyAESGCM),
	}
}

// TestInitRotatedProvider_ActiveTokenIsOpenedFromServeFlags is the regression test for the bug
// where initRotatedProvider built an activeConfig, never used it, and passed oldConfig to NewP11
// as *both* the active and the rotation configuration. `serve rotation` then opened the old
// KEK's token for everything — including encryption under the active KEK — whenever the two KEKs
// were not already on the same token, which is precisely what the second set of --old-* flags
// exists to allow.
//
// NewP11 configures the active token first, so a PKCS #11 library path that cannot be loaded
// makes the failure name the token it actually tried to open. No HSM is needed: the assertion is
// about which library path reaches crypto11, not about anything succeeding.
func TestInitRotatedProvider_ActiveTokenIsOpenedFromServeFlags(t *testing.T) {
	const activeLib, oldLib = "/nonexistent-active-token.so", "/nonexistent-old-token.so"
	withRotationFlags(t, activeLib, oldLib)

	_, err := initRotatedProvider()

	require.Error(t, err, "loading a nonexistent PKCS #11 library must fail")
	assert.Contains(t, err.Error(), activeLib,
		"the active KEK must be opened with the token from the serve flags")
	assert.NotContains(t, err.Error(), oldLib,
		"the old KEK's token must not stand in for the active one")
}

// TestInitRotatedProvider_RejectsUnknownProvider checks both --provider and --old-provider,
// naming the offending value. They are validated where the token is configured, which is the
// only place that knows the set of drivers.
func TestInitRotatedProvider_RejectsUnknownProvider(t *testing.T) {
	t.Run("active", func(t *testing.T) {
		withRotationFlags(t, "/nonexistent-active-token.so", "/nonexistent-old-token.so")
		flagsServe.Provider = "not-a-provider"

		_, err := initRotatedProvider()

		require.Error(t, err)
		assert.Contains(t, err.Error(), `unknown provider "not-a-provider"`)
	})

	t.Run("old", func(t *testing.T) {
		withRotationFlags(t, "/nonexistent-active-token.so", "/nonexistent-old-token.so")
		flagsRotation.OldProvider = "not-a-provider"

		_, err := initRotatedProvider()

		require.Error(t, err)
		assert.Contains(t, err.Error(), `unknown provider "not-a-provider"`)
		assert.NotContains(t, err.Error(), "cryptoki",
			"an unknown provider must be rejected before any token is opened")
	})
}
