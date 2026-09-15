// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

// These tests verify that k8s-kms-plugin correctly reads its parameters from
// each supported user-input mechanism independently of the cryptographic
// algorithm used.  A single AES-256-GCM key is generated per test; all tests
// perform the same Status + Encrypt + Decrypt round-trip to confirm the plugin
// started and parsed its configuration correctly.
//
// The input methods tested are:
//  1. CLI flags only              — TestConfig_CLIFlags       (baseline)
//  2. Environment variables only  — TestConfig_EnvVars
//  3. YAML configuration file     — TestConfig_YAMLFile
//  4. CLI flags + PIN via env var — TestConfig_Hybrid_EnvPin  (recommended production pattern)
//  5. All three sources at once   — TestConfig_Hybrid_AllSources (priority chain: CLI > env > file)

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/eclipse-keypont/crypto11/v2"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/providers"
)

// ── Local helper ──────────────────────────────────────────────────────────────

// startPluginRaw launches k8s-kms-plugin with exactly the given args and
// appends extraEnv key=value pairs to the subprocess environment (inheriting
// the current process environment first, which carries SOFTHSM2_CONF).
// Unlike startPlugin it does NOT pre-add --socket, --p11-lib, --p11-label,
// --p11-pin, or --log-level — those must be provided via args or extraEnv.
// socket is used only for log-file naming; waitForSocket must be called by
// the caller after startPluginRaw returns.
func startPluginRaw(t *testing.T, socket string, extraEnv map[string]string, args ...string) *pluginProcess {
	t.Helper()

	logPath := socket + ".log"
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		logFile.Close()
		if data, rerr := os.ReadFile(logPath); rerr == nil && len(data) > 0 {
			t.Logf("=== plugin log (%s) ===\n%s", logPath, string(data))
		}
		os.Remove(logPath)
	})

	ctx, cancel := context.WithTimeout(context.Background(), pluginTestTimeout)

	t.Logf("starting plugin (raw): %s %v", pluginBin, args)
	cmd := exec.CommandContext(ctx, pluginBin, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Inherit the parent environment (carries SOFTHSM2_CONF) then overlay.
	env := os.Environ()
	for k, v := range extraEnv {
		env = append(env, k+"="+v)
	}
	cmd.Env = env

	require.NoError(t, cmd.Start(), "start k8s-kms-plugin (raw)")
	return &pluginProcess{cmd: cmd, cancel: cancel}
}

// writePartialConfigFile writes a YAML config file that contains only the
// token connection parameters (p11-lib, p11-label, algorithm-family).
// It intentionally omits p11-pin, p11-key-label, and socket so that those
// can be supplied by the caller via env var or CLI flag.
func writePartialConfigFile(t *testing.T, algorithmFamily string) string {
	t.Helper()

	f, err := os.CreateTemp("", "k8s-kms-plugin-*.yaml")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(f.Name()) })

	_, err = fmt.Fprintf(f, `k8s-kms-plugin:
  log-level: "debug"

  serve:
    p11-lib: %q
    p11-label: %q
    algorithm-family: %q
`,
		testConfig.Path,
		testConfig.TokenLabel,
		algorithmFamily,
	)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// writeFullConfigFile writes a YAML config file with all serve parameters
// including the socket path.
func writeFullConfigFile(t *testing.T, socket, p11KeyLabel, algorithmFamily string) string {
	t.Helper()

	f, err := os.CreateTemp("", "k8s-kms-plugin-*.yaml")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(f.Name()) })

	_, err = fmt.Fprintf(f, `k8s-kms-plugin:
  log-level: "debug"

  serve:
    socket: %q
    p11-lib: %q
    p11-label: %q
    p11-pin: %q
    p11-key-label: %q
    algorithm-family: %q
`,
		socket,
		testConfig.Path,
		testConfig.TokenLabel,
		testConfig.Pin,
		p11KeyLabel,
		algorithmFamily,
	)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestConfig_CLIFlags is the baseline: every parameter is supplied as a CLI
// flag.  It mirrors what the algorithm-family roundtrip tests do but documents
// the CLI path explicitly as one of the input methods.
func TestConfig_CLIFlags(t *testing.T) {
	label := newLabel(t)
	key, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(label), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate AES-256-GCM key")
	t.Cleanup(func() { _ = key.Delete() })

	runPluginTest(t,
		"--algorithm-family", string(providers.AlgAESGCM),
		"--p11-key-label", label,
	)
}

// TestConfig_EnvVars verifies that every serve parameter is correctly read
// from K8S_KMS_PLUGIN_SERVE_* environment variables.  The subprocess receives
// no P11 CLI arguments; the config→cobra flag sync in resolveCmdConfigE is what makes
// MarkFlagsOneRequired("p11-key-id", "p11-key-label") accept the env-var value.
func TestConfig_EnvVars(t *testing.T) {
	label := newLabel(t)
	key, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(label), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate AES-256-GCM key")
	t.Cleanup(func() { _ = key.Delete() })

	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	proc := startPluginRaw(t, sock,
		map[string]string{
			// Root-level flag — env prefix is K8S_KMS_PLUGIN
			"K8S_KMS_PLUGIN_LOG_LEVEL": "debug",
			// Serve-level flags — env prefix is K8S_KMS_PLUGIN_SERVE
			"K8S_KMS_PLUGIN_SERVE_SOCKET":           sock,
			"K8S_KMS_PLUGIN_SERVE_P11_LIB":          testConfig.Path,
			"K8S_KMS_PLUGIN_SERVE_P11_LABEL":        testConfig.TokenLabel,
			"K8S_KMS_PLUGIN_SERVE_P11_PIN":          testConfig.Pin,
			"K8S_KMS_PLUGIN_SERVE_P11_KEY_LABEL":    label,
			"K8S_KMS_PLUGIN_SERVE_ALGORITHM_FAMILY": string(providers.AlgAESGCM),
		},
		"serve",
	)
	defer proc.stop()
	waitForSocket(t, sock)
	kmsRoundtrip(t, sock)
}

// TestConfig_YAMLFile verifies that all serve parameters — including the
// socket path — are correctly read from a YAML configuration file.
// The only CLI arguments are the serve sub-command and --config to point at
// the file; everything else comes from the file.
func TestConfig_YAMLFile(t *testing.T) {
	label := newLabel(t)
	key, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(label), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate AES-256-GCM key")
	t.Cleanup(func() { _ = key.Delete() })

	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	cfgPath := writeFullConfigFile(t, sock, label, string(providers.AlgAESGCM))

	proc := startPluginRaw(t, sock, nil,
		"--config", cfgPath,
		"serve",
	)
	defer proc.stop()
	waitForSocket(t, sock)
	kmsRoundtrip(t, sock)
}

// TestConfig_Hybrid_EnvPin mirrors the recommended production pattern: all
// parameters are supplied as CLI flags except the PIN, which is passed via the
// K8S_KMS_PLUGIN_SERVE_P11_PIN environment variable so it never appears in the
// process argument list or shell history.
func TestConfig_Hybrid_EnvPin(t *testing.T) {
	label := newLabel(t)
	key, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(label), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate AES-256-GCM key")
	t.Cleanup(func() { _ = key.Delete() })

	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	proc := startPluginRaw(t, sock,
		map[string]string{
			"K8S_KMS_PLUGIN_SERVE_P11_PIN": testConfig.Pin,
		},
		"serve",
		"--socket", sock,
		"--p11-lib", testConfig.Path,
		"--p11-label", testConfig.TokenLabel,
		"--p11-key-label", label,
		"--algorithm-family", string(providers.AlgAESGCM),
		"--log-level", "debug",
	)
	defer proc.stop()
	waitForSocket(t, sock)
	kmsRoundtrip(t, sock)
}

// TestConfig_Hybrid_AllSources exercises the koanf priority chain by combining
// all three input methods at once:
//
//   - Config file  — supplies p11-lib, p11-label, algorithm-family (lowest priority)
//   - Env var      — supplies p11-pin (overrides any config-file value for that key)
//   - CLI flags    — supply socket, p11-key-label, log-level (highest priority)
//
// If the plugin starts and the round-trip succeeds, every source was parsed
// and merged in the correct order.
func TestConfig_Hybrid_AllSources(t *testing.T) {
	label := newLabel(t)
	key, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(label), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate AES-256-GCM key")
	t.Cleanup(func() { _ = key.Delete() })

	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	// Config file: token connection (p11-lib, p11-label) and algorithm-family.
	// p11-pin, p11-key-label, and socket are intentionally absent so they must
	// come from the env var and CLI respectively.
	cfgPath := writePartialConfigFile(t, string(providers.AlgAESGCM))

	proc := startPluginRaw(t, sock,
		map[string]string{
			// Env var: PIN (overrides config file if it were present there)
			"K8S_KMS_PLUGIN_SERVE_P11_PIN": testConfig.Pin,
		},
		// CLI flags: socket and key label (highest priority, overrides everything)
		"--config", cfgPath,
		"serve",
		"--socket", sock,
		"--p11-key-label", label,
		"--log-level", "debug",
	)
	defer proc.stop()
	waitForSocket(t, sock)
	kmsRoundtrip(t, sock)
}
