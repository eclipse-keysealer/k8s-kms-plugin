// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

// TODO replace github imports for :
//   - gose
//   - crypto11
import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/eclipse-keypont/crypto11/v2"
	"github.com/eclipse-keypont/gose/jose"

	k8skmsv2 "k8s.io/kms/apis/v2"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/logging"
	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/providers"
	version "github.com/eclipse-keysealer/k8s-kms-plugin/pkg/version"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// ServeFlags holds the resolved values of the serve command flags. The koanf tags are the long
// flag names, which are also the keys of the k8s-kms-plugin.serve section of the config file.
type ServeFlags struct {
	// PKCS #11 & KMS plugin parameters
	AlgorithmFamily string `koanf:"algorithm-family"`
	P11Label        string `koanf:"p11-label"`
	P11Lib          string `koanf:"p11-lib"`
	P11Pin          string `koanf:"p11-pin"`
	P11Slot         int    `koanf:"p11-slot"`
	Provider        string `koanf:"provider"`
	SocketPath      string `koanf:"socket"` // Unix socket path

	// PKCS #11 CKA_ID and CKA_LABEL of active KEK key
	DekKeyLabel  string `koanf:"p11-key-label"`  // active DEK key CKA_LABEL
	HmacKeyID    string `koanf:"p11-hmac-id"`    // active HMAC key CKA_ID
	HmacKeyLabel string `koanf:"p11-hmac-label"` // active HMAC key CKA_LABEL
	KekKeyID     string `koanf:"p11-key-id"`     // active KEK key CKA_ID
}

// flagsServe holds the resolved serve command configuration.
var flagsServe ServeFlags

// cfgServe reports which serve settings the user actually provided; see cmdConfig.
var cfgServe *cmdConfig

// AlgorithmFamily is the user-facing algorithm selector. It names the cryptographic
// mechanism only — key size and parameter set are derived from the HSM key at runtime.
type AlgorithmFamily string

// Supported AlgorithmFamily values.
const (
	AlgorithmFamilyAESGCM  AlgorithmFamily = "aes-gcm"
	AlgorithmFamilyAESCBC  AlgorithmFamily = "aes-cbc"
	AlgorithmFamilyRSAOAEP AlgorithmFamily = "rsa-oaep"
	AlgorithmFamilyMLKEM   AlgorithmFamily = "ml-kem"
)

// String implements pflag.Value.
func (a *AlgorithmFamily) String() string { return string(*a) }

// Type implements pflag.Value.
func (a *AlgorithmFamily) Type() string { return "algorithmFamily" }

// Set implements pflag.Value so cobra validates the flag at parse time.
func (a *AlgorithmFamily) Set(s string) error {
	if err := validateAlgorithmFamily(s); err != nil {
		return err
	}
	*a = AlgorithmFamily(s)
	return nil
}

// validateAlgorithmFamily is used both by AlgorithmFamily.Set (CLI flag path) and
// PersistentPreRunE (config file / env var path).
func validateAlgorithmFamily(s string) error {
	switch AlgorithmFamily(s) {
	case AlgorithmFamilyAESGCM, AlgorithmFamilyAESCBC, AlgorithmFamilyRSAOAEP, AlgorithmFamilyMLKEM:
		return nil
	default:
		return fmt.Errorf("must be one of aes-gcm, aes-cbc, rsa-oaep, ml-kem; got %q", s)
	}
}

const (
	// maxCkaLabelBytes is the PKCS#11 CKA_LABEL maximum (mirrored from pkg/providers).
	maxCkaLabelBytes = 255
	// maxUnixSocketPathLen is the Linux UNIX_PATH_MAX minus one byte for the null terminator.
	maxUnixSocketPathLen = 107
)

// sanitizeServeFlags validates all user-controlled fields in ServeFlags after koanf has
// resolved them from all input sources (CLI flags, env vars, config file, defaults).
func sanitizeServeFlags(f *ServeFlags) error {
	if err := validateAlgorithmFamily(f.AlgorithmFamily); err != nil {
		return fmt.Errorf("--algorithm-family: %w", err)
	}
	if len(f.P11Label) > maxCkaLabelBytes {
		return fmt.Errorf("--p11-label: length %d exceeds maximum of %d bytes", len(f.P11Label), maxCkaLabelBytes)
	}
	if len(f.DekKeyLabel) > maxCkaLabelBytes {
		return fmt.Errorf("--p11-key-label: length %d exceeds maximum of %d bytes", len(f.DekKeyLabel), maxCkaLabelBytes)
	}
	if len(f.HmacKeyLabel) > maxCkaLabelBytes {
		return fmt.Errorf("--p11-hmac-label: length %d exceeds maximum of %d bytes", len(f.HmacKeyLabel), maxCkaLabelBytes)
	}
	if len(f.SocketPath) > maxUnixSocketPathLen {
		return fmt.Errorf("--socket: path length %d exceeds Unix socket maximum of %d bytes", len(f.SocketPath), maxUnixSocketPathLen)
	}
	return nil
}

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the Kubernetes KMS v2 API over a unix socket",
	Long: `Serve the Kubernetes KMS v2 API on a unix socket, wrapping and unwrapping the data
encryption key with a key encryption key (KEK) held on a PKCS #11 token.

This command serves one active KEK. To keep decrypting data written under a previous KEK while
a rotation is in progress, use "k8s-kms-plugin serve rotation" instead.

Identify the KEK with exactly one of --p11-key-id (CKA_ID) or --p11-key-label (CKA_LABEL); the
plugin looks up whichever you leave out. --p11-hmac-id / --p11-hmac-label follow the same rule
and are only used by --algorithm-family=aes-cbc, which authenticates the ciphertext separately.

The PIN is a secret: prefer K8S_KMS_PLUGIN_SERVE_P11_PIN, or omit it and be prompted, over
--p11-pin, which any user on the host can read out of the process arguments.

Reference:

- Kubernetes KMS provider guide: https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#configuring-the-kms-provider-kms-v2
- KMS v2 API: https://pkg.go.dev/k8s.io/kms/apis/v2
- CKA_ID vs CKA_LABEL: https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/docs/cli-user-interface/cka-id-vs-cka-label.md
`,
	Example: `
  # Everything on the command line, PIN prompted interactively (input hidden).
  k8s-kms-plugin serve \
    --socket /run/user/1000/k8s-kms-plugin.sock \
    --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --p11-label mytoken \
    --p11-key-label rsa0 \
    --algorithm-family rsa-oaep

  # AES-CBC with HMAC authentication, both keys identified by CKA_ID.
  k8s-kms-plugin serve \
    --log-level trace \
    --socket /run/user/1000/k8s-kms-plugin.sock \
    --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --p11-label mytoken \
    --p11-key-id 64636138353931326363356537313264 \
    --p11-hmac-id 30663536623936326235663530363234 \
    --algorithm-family aes-cbc

  # Everything from a configuration file, PIN from the environment.
  export K8S_KMS_PLUGIN_SERVE_P11_PIN=mypin
  k8s-kms-plugin --config my-kms-plugin-config.yaml serve

  # Config file for the token, environment for the PIN, flags for what changes per host.
  export K8S_KMS_PLUGIN_SERVE_P11_PIN=mypin
  k8s-kms-plugin --log-format json --config my-kms-plugin-config.yaml serve \
    --socket /run/user/1000/k8s-kms-plugin.sock
`,
	GroupID: "kmscmdsgrpmain",
	// Resolve the serve flags from all input sources during the persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		var err error
		if cfgServe, err = resolveCmdConfigE(cmd, &flagsServe); err != nil {
			slog.Error("error resolving configuration", "cobra_cmd", cmd.Name(), "error", err)
			return err
		}
		return sanitizeServeFlags(&flagsServe)
	},
	RunE: func(cmd *cobra.Command, _ []string) (err error) {
		silenceUsage(cmd)

		// Show the version of the k8s-kms-plugin and commit ID
		version.LogVersion()

		if flagsServe.P11Pin, err = resolvePin(cfgServe, "p11-pin", "Enter HSM PIN: "); err != nil {
			return
		}

		// Don't panic/exit if we have a PKCS#11 error.
		// Sleep forever instead.
		var p providers.Provider
		p, err = initProvider()
		if err != nil && providers.IsPKCS11AuthenticationError(err) {
			slog.Error("PKCS11 authentication error detected. Further retries may cause the token to be erased.", "cobra_cmd", cmd.Use, "error", err)
			slog.Warn("Process will now sleep indefinitely to prevent further damage...", "cobra_cmd", cmd.Use)
			time.Sleep(8760 * time.Hour)
		}

		if err != nil {
			logging.Fatal("failed to initialize provider", "cobra_cmd", cmd.Use, "error", err)
		}

		_ = os.Remove(flagsServe.SocketPath)
		var grpcUNIX net.Listener
		if grpcUNIX, err = net.Listen("unix", flagsServe.SocketPath); err != nil {
			return
		}
		// Grant group read/write so a co-located client (e.g. kube-apiserver
		// running under a shared gid) can connect to the socket.
		if chmodErr := os.Chmod(flagsServe.SocketPath, 0775); chmodErr != nil { //nolint:gosec // group access is intentional, see comment above
			slog.Error("error setting socket permissions", "path", flagsServe.SocketPath, "error", chmodErr)
		}

		if err = grpcServe(grpcUNIX, p); err != nil {
			slog.Error("gRPC server error", "cobra_cmd", cmd.Use, "error", err)
		}

		return
	},
}

func init() {
	// rootCmd is the parent command
	rootCmd.AddCommand(serveCmd)

	// Flag values are read from the ServeFlags struct that koanf populates, so flags are registered
	// without "Flags().*Var" (StringVar, BoolVar, Uint16Var, ...).

	// The token to open
	serveCmd.PersistentFlags().String("provider", "p11",
		"PKCS #11 driver quirks to apply. One of: p11 (generic), softhsm, luna, dpod. "+
			"luna and dpod take the GCM IV from the HSM.")
	registerFixedCompletion(serveCmd, "provider", "p11", "softhsm", "luna", "dpod")

	serveCmd.PersistentFlags().String("p11-lib", "",
		"Path to the PKCS #11 library of the TPM or HSM, e.g. /usr/lib/softhsm/libsofthsm2.so.")
	markFlagFilename(serveCmd, "p11-lib", "so", "dylib", "dll")

	serveCmd.PersistentFlags().String("p11-label", "",
		"Token label (CKA_LABEL of the token, not of the key) identifying which token to open. "+
			"Takes precedence over --p11-slot.")
	serveCmd.PersistentFlags().Int("p11-slot", 0,
		"Slot number to open. Only used when --p11-label is empty.")
	serveCmd.PersistentFlags().String("p11-pin", "",
		"PIN of the token. Omit it to be prompted with hidden input; pass an empty string for a "+
			"token that takes no PIN. Prefer the environment variable: process arguments are "+
			"world-readable.")

	// The KEK, and the HMAC key that aes-cbc needs alongside it
	algFamilyDefault := AlgorithmFamilyAESGCM
	serveCmd.PersistentFlags().Var(&algFamilyDefault, "algorithm-family",
		"Mechanism the KEK is used with. One of: aes-gcm, aes-cbc, rsa-oaep, ml-kem. Key size and "+
			"ML-KEM parameter set are read from the key on the token, not configured here.")
	registerFixedCompletion(serveCmd, "algorithm-family", "aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem")

	serveCmd.PersistentFlags().String("p11-key-id", "",
		"CKA_ID of the KEK, hex. Mutually exclusive with --p11-key-label, one of the two required. "+
			"This is the ID Kubernetes stores in etcd alongside the data.")
	serveCmd.PersistentFlags().String("p11-key-label", "",
		"CKA_LABEL of the KEK. Mutually exclusive with --p11-key-id, one of the two required. The "+
			"key must also carry a CKA_ID on the token: that is what is stored in etcd.")
	serveCmd.PersistentFlags().String("p11-hmac-id", "",
		"CKA_ID of the HMAC key authenticating the ciphertext, hex. aes-cbc only. Mutually "+
			"exclusive with --p11-hmac-label.")
	serveCmd.PersistentFlags().String("p11-hmac-label", "",
		"CKA_LABEL of the HMAC key authenticating the ciphertext. aes-cbc only. Mutually exclusive "+
			"with --p11-hmac-id. The key must also carry a CKA_ID on the token.")
	registerNoFileCompletion(serveCmd,
		"p11-label", "p11-slot", "p11-pin", "p11-key-id", "p11-key-label", "p11-hmac-id", "p11-hmac-label")

	// Where to listen. A unix socket is the only transport: KMS v2 supports nothing else.
	serveCmd.PersistentFlags().String("socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"),
		"Unix socket the gRPC server listens on, e.g. /run/user/$(id -u)/k8s-kms-plugin.sock. "+
			"Created with mode 0775 so a client under a shared gid can connect.")

	// At least one of KEK CKA_ID or CKA_LABEL must be provided by the user
	serveCmd.MarkFlagsOneRequired("p11-key-id", "p11-key-label")

	// To prevent mismatch between user provided CKA_ID and user provided CKA_LABEL, flags are Mutually Exclusive.
	// NewP11 make sure to retrieve the ID by label, or label by ID.
	serveCmd.MarkFlagsMutuallyExclusive("p11-key-id", "p11-key-label")
	serveCmd.MarkFlagsMutuallyExclusive("p11-hmac-id", "p11-hmac-label")
}

// newCrypto11Config builds the crypto11 configuration that opens one PKCS #11 token.
//
// `serve` needs one of these and `serve rotation` needs two — the active KEK's token and the old
// KEK's, which may be a different token on a different HSM. It is one function rather than a
// copy of the same switch per token precisely because the copies are what allowed the old KEK's
// configuration to be handed to NewP11 as the active one; see
// TestInitRotatedProvider_ActiveTokenIsOpenedFromServeFlags.
func newCrypto11Config(providerName, lib, pin, tokenLabel string, slot int) (*crypto11.Config, error) {
	config := &crypto11.Config{Path: lib, Pin: pin}

	switch providerName {
	case "p11", "softhsm":
		slog.Log(context.Background(), logging.LevelTrace, "crypto11 config: case p11 or softhsm", "p11_lib", lib)
		config.UseGCMIVFromHSM = false

	case "luna", "dpod":
		// These generate the GCM IV on the HSM: it must not be supplied for encryption, and must
		// be supplied back to the HSM for decryption.
		slog.Log(context.Background(), logging.LevelTrace, "crypto11 config: case luna HSM or dpod", "p11_lib", lib)
		config.UseGCMIVFromHSM = true
		config.GCMIVFromHSMControl = crypto11.GCMIVFromHSMConfig{
			SupplyIvForHSMGCMEncrypt: false,
			SupplyIvForHSMGCMDecrypt: true,
		}

	default:
		return nil, fmt.Errorf("unknown provider %q: must be one of p11, softhsm, luna, dpod", providerName)
	}

	// The token label identifies the token on its own; the slot number is the fallback for a
	// label that does not identify exactly one token.
	if tokenLabel != "" {
		config.TokenLabel = tokenLabel
	} else {
		config.SlotNumber = &slot
	}

	return config, nil
}

func initProvider() (p providers.Provider, err error) {
	// Validated by sanitizeServeFlags; cast directly to the provider sentinel.
	alg := jose.Alg(flagsServe.AlgorithmFamily)

	var config *crypto11.Config
	if config, err = newCrypto11Config(
		flagsServe.Provider, flagsServe.P11Lib, flagsServe.P11Pin, flagsServe.P11Label, flagsServe.P11Slot,
	); err != nil {
		return
	}

	// init the provider for active key only (no key rotation)
	// TODO: See https://github.com/eclipse-keysealer/k8s-kms-plugin/issues/40#issuecomment-2593267852
	if p, err = providers.NewP11(
		config,
		flagsServe.KekKeyID,
		flagsServe.DekKeyLabel,
		flagsServe.HmacKeyLabel,
		flagsServe.HmacKeyID,
		alg,
		false, // no key rotation
		nil,
		"",
		"",
		"",
		"",
		"",
	); err != nil {
		return
	}
	return
}

func grpcServe(gl net.Listener, p providers.Provider) (err error) {
	slog.Log(context.Background(), logging.LevelTrace, "grpcServe")

	// Create a gRPC server to host the services
	serverOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(p.UnaryInterceptor),
		grpc.UnknownServiceHandler(unknownServiceHandler),
	}
	gs := grpc.NewServer(serverOptions...)

	k8skmsv2.RegisterKeyManagementServiceServer(gs, p)
	reflection.Register(gs)

	slog.Info("serving on socket", "address", gl.Addr().String())

START:
	if err = gs.Serve(gl); err != nil {
		slog.Error("gRPC serve error", "error", err)
		goto START
	}
	return
}

func unknownServiceHandler(srv interface{}, _ grpc.ServerStream) error {
	typeOfSrv := reflect.TypeOf(srv)
	slog.Info("unknown service handler", "type", typeOfSrv, "service", srv)
	return nil
}
