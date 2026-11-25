// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The config file may hold the PIN and selects the PKCS#11 module, so it must not be writable
// by anyone but its owner.
func TestConfigFileIsTrusted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k8s-kms-plugin.conf.yaml")
	require.NoError(t, os.WriteFile(path, []byte("k8s-kms-plugin:\n"), 0o600))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.NoError(t, configFileIsTrusted(info), "an owner-only file is trusted")

	for _, mode := range []os.FileMode{0o666, 0o664, 0o620, 0o602} {
		require.NoError(t, os.Chmod(path, mode))
		info, err = os.Stat(path)
		require.NoError(t, err)
		err = configFileIsTrusted(info)
		require.Error(t, err, "mode %o is group/other writable and must be refused", mode)
		require.Contains(t, err.Error(), "writable by group or others")
	}

	// Read-only to group/others is fine (the content still cannot be changed).
	require.NoError(t, os.Chmod(path, 0o644))
	info, err = os.Stat(path)
	require.NoError(t, err)
	require.NoError(t, configFileIsTrusted(info))
}
