// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
