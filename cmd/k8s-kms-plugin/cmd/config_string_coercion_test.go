// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"testing"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

// A string flag must not be fed a YAML scalar that parsed as a number or boolean, because it
// would be stringified into a value the operator did not write (e.g. the octal 0123 -> "83").
func TestRejectCoercedStringFlags(t *testing.T) {
	newFlags := func() *pflag.FlagSet {
		fs := pflag.NewFlagSet("serve", pflag.ContinueOnError)
		fs.String("p11-pin", "", "")
		fs.String("p11-key-id", "", "")
		return fs
	}

	coerced := []string{
		"k8s-kms-plugin:\n  serve:\n    p11-pin: 0123\n",    // octal -> 83
		"k8s-kms-plugin:\n  serve:\n    p11-pin: 1e3\n",     // float -> 1000
		"k8s-kms-plugin:\n  serve:\n    p11-pin: true\n",    // bool
		"k8s-kms-plugin:\n  serve:\n    p11-key-id: 0x10\n", // hex -> 16
	}
	for _, raw := range coerced {
		k, err := parseConfig([]byte(raw), yaml.Parser())
		require.NoError(t, err)
		err = rejectCoercedStringFlags(k.Cut("k8s-kms-plugin.serve"), newFlags())
		require.Error(t, err, "coerced value %q should be rejected", raw)
	}

	// A quoted string, and an absent value, are both fine.
	ok, err := parseConfig([]byte("k8s-kms-plugin:\n  serve:\n    p11-pin: \"0123\"\n"), yaml.Parser())
	require.NoError(t, err)
	require.NoError(t, rejectCoercedStringFlags(ok.Cut("k8s-kms-plugin.serve"), newFlags()))
	require.Equal(t, "0123", ok.String("k8s-kms-plugin.serve.p11-pin"))
}
