// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/eclipse-keypont/crypto11/v2"
	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/providers"
)

const (
	e2ePlaintext = "the quick brown fox jumps over the lazy dog — k8s-kms-plugin e2e"

	// pluginStartTimeout is the maximum time to wait for the plugin unix socket.
	// PKCS#11 library loading + token connection can be slow.
	pluginStartTimeout = 20 * time.Second

	// pluginTestTimeout is the context deadline for the entire plugin subprocess.
	pluginTestTimeout = 60 * time.Second
)

// ── Unique-name helpers ───────────────────────────────────────────────────────

func newKeyID(t *testing.T) []byte {
	t.Helper()
	id, err := uuid.NewRandom()
	require.NoError(t, err)
	b, err := id.MarshalText()
	require.NoError(t, err)
	return b
}

// newLabel returns a short unique label safe for PKCS#11 CKA_LABEL.
func newLabel(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewRandom()
	require.NoError(t, err)
	return "e2e-" + id.String()[:8]
}

// socketPath returns a unique, short unix socket path under /tmp.
func socketPath(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewRandom()
	require.NoError(t, err)
	return fmt.Sprintf("/tmp/kms-%s.sock", id.String()[:8])
}

// ── Plugin subprocess management ──────────────────────────────────────────────

type pluginProcess struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

// startPlugin launches k8s-kms-plugin serve. Stdout+stderr go to a log file
// that is printed via t.Log after every test (visible with -v, diagnosable on failure).
func startPlugin(t *testing.T, socket string, extraArgs ...string) *pluginProcess {
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

	args := append(
		[]string{
			"serve",
			"--socket", socket,
			"--p11-lib", testConfig.Path,
			"--p11-label", testConfig.TokenLabel,
			"--p11-pin", testConfig.Pin,
			"--log-level", "debug",
		},
		extraArgs...,
	)

	t.Logf("starting plugin: %s %v", pluginBin, args)
	cmd := exec.CommandContext(ctx, pluginBin, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start(), "start k8s-kms-plugin")

	return &pluginProcess{cmd: cmd, cancel: cancel}
}

func (p *pluginProcess) stop() {
	p.cancel()
	_ = p.cmd.Wait()
}

// waitForSocket polls every 200 ms until the unix socket file appears.
func waitForSocket(t *testing.T, socket string) {
	t.Helper()
	t.Logf("waiting for socket %s (timeout %s)", socket, pluginStartTimeout)
	deadline := time.Now().Add(pluginStartTimeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socket); err == nil {
			t.Logf("socket ready: %s", socket)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timeout (%s) waiting for plugin socket %s", pluginStartTimeout, socket)
}

// ── gRPC helpers ──────────────────────────────────────────────────────────────

type statusResponse struct {
	KeyID string `json:"keyID"`
}
type encryptResponse struct {
	Ciphertext string `json:"ciphertext"`
	KeyID      string `json:"keyID"`
	// Annotations values are base64-encoded bytes (protojson map<string,bytes> encoding).
	// ML-KEM populates exactly one entry here (the KEM ciphertext); other algorithm
	// families leave it empty.
	Annotations map[string]string `json:"annotations"`
}
type decryptResponse struct {
	Plaintext string `json:"plaintext"` // base64-encoded bytes field
}

// marshalAnnotations renders an EncryptResponse.Annotations map (already base64-encoded
// strings, as decoded from protojson) back into the JSON object literal grpcurl expects for
// DecryptRequest.annotations. Mirrors the apiserver's round-trip guarantee: whatever Encrypt
// returned in annotations must be sent back unchanged on the matching Decrypt.
func marshalAnnotations(t *testing.T, annotations map[string]string) string {
	t.Helper()
	if len(annotations) == 0 {
		return "{}"
	}
	b, err := json.Marshal(annotations)
	require.NoError(t, err)
	return string(b)
}

// callGrpcurl invokes grpcurl and returns the combined stdout+stderr output.
// Mirrors the format used in scripts/grpcurl/grpcurl-roundtrip-test.sh.
func callGrpcurl(t *testing.T, socket, method, body string) []byte {
	t.Helper()
	cmd := exec.Command(
		"grpcurl",
		"-plaintext",
		"-import-path", filepath.Dir(protoFile),
		"-proto", filepath.Base(protoFile),
		"-d", body,
		"-unix",
		"unix://"+socket,
		"v2.KeyManagementService."+method,
	)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "grpcurl %s failed\ncmd: %s\noutput:\n%s",
		method, cmd.String(), string(out))
	t.Logf("grpcurl %s: %s", method, string(out))
	return out
}

// ── KMS v2 request sub-tests ──────────────────────────────────────────────────
//
// kmsRoundtrip runs Status, Encrypt and Decrypt as named sub-tests against a
// running plugin socket. Each request is an independent t.Run so failures are
// reported individually. Encrypt and Decrypt are skipped when an earlier step
// fails (t.Failed guard) since they depend on the prior response values.

func kmsRoundtrip(t *testing.T, socket string) {
	t.Helper()

	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(e2ePlaintext))

	// Shared state passed between sequential sub-tests.
	var keyID, ciphertext string
	var annotations map[string]string

	t.Run("Status", func(t *testing.T) {
		var resp statusResponse
		require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Status", `{}`), &resp))
		require.NotEmpty(t, resp.KeyID, "Status.keyID must not be empty")
		keyID = resp.KeyID
	})
	if t.Failed() {
		return // Encrypt / Decrypt would fail without a valid keyID
	}

	t.Run("Encrypt", func(t *testing.T) {
		body := fmt.Sprintf(`{"plaintext":%q,"uid":"e2e-enc"}`, plaintextB64)
		var resp encryptResponse
		require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Encrypt", body), &resp))
		require.NotEmpty(t, resp.Ciphertext, "Encrypt.ciphertext must not be empty")
		ciphertext = resp.Ciphertext
		keyID = resp.KeyID // prefer the keyID from EncryptResponse
		annotations = resp.Annotations
	})
	if t.Failed() {
		return // Decrypt would fail without a valid ciphertext
	}

	t.Run("Decrypt", func(t *testing.T) {
		body := fmt.Sprintf(`{"ciphertext":%q,"uid":"e2e-dec","key_id":%q,"annotations":%s}`,
			ciphertext, keyID, marshalAnnotations(t, annotations))
		var resp decryptResponse
		require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Decrypt", body), &resp))
		recovered, err := base64.StdEncoding.DecodeString(resp.Plaintext)
		require.NoError(t, err, "base64-decode Decrypt.plaintext")
		assert.Equal(t, e2ePlaintext, string(recovered))
	})
}

// ── Per-algorithm test setup ──────────────────────────────────────────────────

// runPluginTest is the shared harness: it starts the plugin with the given
// flags, waits for the socket, then delegates to kmsRoundtrip.
func runPluginTest(t *testing.T, extraArgs ...string) {
	t.Helper()

	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	proc := startPlugin(t, sock, extraArgs...)
	defer proc.stop()

	waitForSocket(t, sock)
	kmsRoundtrip(t, sock)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestPlugin_AESGCM tests all three AES-GCM key sizes (128 / 192 / 256 bit).
// The key size is auto-detected by the plugin from CKA_VALUE_LEN; the user
// only specifies --algorithm-family aes-gcm.
func TestPlugin_AESGCM(t *testing.T) {
	for _, bitSize := range []int{128, 192, 256} {
		t.Run(fmt.Sprintf("%dbit", bitSize), func(t *testing.T) {
			label := newLabel(t)
			key, err := testCtx.GenerateSecretKeyWithLabel(
				newKeyID(t), []byte(label), bitSize, crypto11.CipherAES)
			require.NoErrorf(t, err, "GenerateSecretKeyWithLabel AES-%d", bitSize)
			t.Cleanup(func() { _ = key.Delete() })

			runPluginTest(t,
				"--algorithm-family", string(providers.AlgAESGCM),
				"--p11-key-label", label,
			)
		})
	}
}

// TestPlugin_AESCBC tests AES-256-CBC + HMAC-SHA256.
func TestPlugin_AESCBC(t *testing.T) {
	kekLabel := newLabel(t)
	hmacLabel := newLabel(t)

	kek, err := testCtx.GenerateSecretKeyWithLabel(
		newKeyID(t), []byte(kekLabel), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate AES-256 CBC KEK")
	t.Cleanup(func() { _ = kek.Delete() })

	// HMAC key: CKK_GENERIC_SECRET with CKA_SIGN=true so CKM_SHA256_HMAC is permitted.
	hmacAttrs, err := crypto11.NewAttributeSetWithIDAndLabel(newKeyID(t), []byte(hmacLabel))
	require.NoError(t, err)
	require.NoError(t, hmacAttrs.Set(pkcs11.CKA_SIGN, true))
	require.NoError(t, hmacAttrs.Set(pkcs11.CKA_VERIFY, true))
	hmac, err := testCtx.GenerateSecretKeyWithAttributes(hmacAttrs, 256, crypto11.CipherGeneric)
	require.NoError(t, err, "generate HMAC key")
	t.Cleanup(func() { _ = hmac.Delete() })

	runPluginTest(t,
		"--algorithm-family", string(providers.AlgAESCBC),
		"--p11-key-label", kekLabel,
		"--p11-hmac-label", hmacLabel,
	)
}

// TestPlugin_RSAOAEP tests RSA-2048 OAEP.
func TestPlugin_RSAOAEP(t *testing.T) {
	label := newLabel(t)

	kp, err := testCtx.GenerateRSAKeyPairWithLabel(newKeyID(t), []byte(label), 2048)
	require.NoError(t, err, "GenerateRSAKeyPairWithLabel 2048")
	t.Cleanup(func() { _ = kp.Delete() })

	runPluginTest(t,
		"--algorithm-family", string(providers.AlgRSAOAEP),
		"--p11-key-label", label,
	)
}

// TestPlugin_MLKEM tests ML-KEM-768. Skipped automatically on tokens that do
// not support CKM_ML_KEM_KEY_PAIR_GEN (SoftHSMv2 and earlier).
// Requires SoftHSMv3: https://github.com/pqctoday-org/pqctoday-hsm
func TestPlugin_MLKEM(t *testing.T) {
	label := newLabel(t)

	kp, err := testCtx.GenerateMLKEMKeyPairWithLabel(newKeyID(t), []byte(label), crypto11.MLKEM768)
	if err != nil {
		t.Skipf("ML-KEM key generation not supported by this token: %v"+
			" — requires SoftHSMv3 from https://github.com/pqctoday-org/pqctoday-hsm", err)
	}
	t.Cleanup(func() { _ = kp.Delete() })

	runPluginTest(t,
		"--algorithm-family", string(providers.AlgMLKEM),
		"--p11-key-label", label,
	)
}
