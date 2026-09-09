// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"testing"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/spf13/cobra"
)

// FuzzAlgorithmFamilySet drives the --algorithm-family flag parser with arbitrary strings.
//
// This value crosses into the PKCS#11 stack, which is cgo, so a value that slips past
// validation does not stay in Go. The property asserted is that AlgorithmFamily.Set is a gate,
// not a filter: it either rejects the input or stores it verbatim, never silently coercing a
// near-miss like "AES-GCM" or "aes-gcm\n" into a supported family.
func FuzzAlgorithmFamilySet(f *testing.F) {
	f.Add("aes-gcm")
	f.Add("AES-GCM")
	f.Add("ml-kem")
	f.Add("ml-kem\n")
	f.Add(" rsa-oaep ")
	f.Add("")

	supported := map[string]bool{
		string(AlgorithmFamilyAESGCM):  true,
		string(AlgorithmFamilyAESCBC):  true,
		string(AlgorithmFamilyRSAOAEP): true,
		string(AlgorithmFamilyMLKEM):   true,
	}

	f.Fuzz(func(t *testing.T, value string) {
		var alg AlgorithmFamily
		err := alg.Set(value)

		if supported[value] != (err == nil) {
			t.Fatalf("AlgorithmFamily.Set(%q) returned err=%v, but supported=%v", value, err, supported[value])
		}
		if err != nil {
			if alg != "" {
				t.Fatalf("AlgorithmFamily.Set(%q) failed but still stored %q", value, alg)
			}
			return
		}
		if alg.String() != value {
			t.Fatalf("AlgorithmFamily.Set(%q) stored %q; the flag value must round-trip verbatim", value, alg.String())
		}
	})
}

// FuzzResolveCmdConfig drives the configuration file path with arbitrary YAML.
//
// resolveCmdConfigE composes the priority chain by hand (config file section, then environment
// variables, then flags), so it meets config shapes a well-formed file never has: a "serve" key
// that is a scalar rather than a map, a value whose type does not match the flag it lands on,
// deep nesting, keys that are themselves dotted paths. Any of those reaching koanf's merge or
// mapstructure's decoder is a plausible panic source, and a malformed config file must produce
// an error rather than take the process down.
//
// The target asserts the crash-freedom contract only. Which source wins is a priority-chain
// question the table tests in config_test.go cover with realistic inputs.
func FuzzResolveCmdConfig(f *testing.F) {
	f.Add("k8s-kms-plugin:\n  serve:\n    p11-lib: /usr/lib/softhsm/libsofthsm2.so\n    p11-slot: 0\n")
	f.Add("k8s-kms-plugin:\n  serve:\n    algorithm-family: ml-kem\n    p11-key-id: dca85912cc5e712d\n")
	f.Add("k8s-kms-plugin.serve.socket: /run/k8s-kms-plugin.sock\n") // section spelled as one dotted key
	f.Add("k8s-kms-plugin:\n  serve: not-a-map\n")                   // section is a scalar
	f.Add("k8s-kms-plugin:\n  serve:\n    p11-slot: not-an-int\n")   // type mismatch against ServeFlags
	f.Add("k8s-kms-plugin:\n  serve:\n    serve:\n      serve: {}\n")
	f.Add("k8s-kms-plugin:\n  serve: {}\n")
	f.Add("")

	// The target asserts crash-freedom only, so it never reports through t.
	f.Fuzz(func(_ *testing.T, config string) {
		k, err := parseConfig([]byte(config), yaml.Parser())
		if err != nil {
			return // not valid YAML; the CLI rejects it before any command is resolved
		}

		// resolveCmdConfigE reads the config file layer from the package-level instance.
		saved := configK
		configK = k
		defer func() { configK = saved }()

		// A throwaway command tree so the fuzzer never mutates the real one, with the same
		// command path — and therefore the same config section — as `k8s-kms-plugin serve`.
		root := &cobra.Command{Use: "k8s-kms-plugin"}
		serve := &cobra.Command{Use: "serve"}
		root.AddCommand(serve)
		alg := AlgorithmFamilyAESGCM
		serve.Flags().Var(&alg, "algorithm-family", "")
		serve.Flags().String("p11-lib", "", "")
		serve.Flags().String("p11-key-id", "", "")
		serve.Flags().String("socket", "/tmp/k8s-kms-plugin.sock", "")
		serve.Flags().Int("p11-slot", 0, "")
		serve.Flags().Bool("auto-create", false, "")

		var target ServeFlags
		// An error is a valid outcome for a malformed config; a panic is not.
		_, _ = resolveCmdConfigE(serve, &target)
	})
}
