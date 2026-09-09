// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

// TODO replace github imports for :
//   - gose
//   - crypto11
import (
	"context"
	"errors"
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
	NativePath      string `koanf:"native-path"`
	P11Label        string `koanf:"p11-label"`
	P11Lib          string `koanf:"p11-lib"`
	P11Pin          string `koanf:"p11-pin"`
	P11Slot         int    `koanf:"p11-slot"`
	Provider        string `koanf:"provider"`
	SocketPath      string `koanf:"socket"` // Unix socket path

	// PKCS #11 CKA_ID and CKA_LABEL of active KEK key
	CreateKey    bool   `koanf:"auto-create"`
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
	Short: "Handles Kubernetes KMS v2 requests",
	Long: `Handles Kubernetes KMS v2 requests but do not support key rotation.
Use "k8s-kms-plugin serve rotation" subcommand to support key rotation.
Kubernetes KMS documentation: https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#configuring-the-kms-provider-kms-v2

KMS v2 API: https://pkg.go.dev/k8s.io/kms@v0.34.1/apis/v2

How --p11-key-id / --p11-key-label (and --p11-hmac-id / --p11-hmac-label) are resolved:
docs/cli-user-interface/cka-id-vs-cka-label.md
`,
	Example: `
Using flags and serving on unix socket (gRPC plaintext):
	k8s-kms-plugin
	  serve \
		--log-level=info \
		--socket /run/user/1000/k8s-kms-plugin.sock \
		--p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
		--p11-label mylabel \
		--p11-pin mypin \
		--p11-key-label rsa0 \
		--algorithm-family rsa-oaep

Using both environment variables and configuration file and serving on unix socket:
	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin serve --config my-kms-plugin-config.yaml

Using both CLI Flags, environment variables and configuration file and serving on unix socket:
	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin --log-format=json serve --config my-kms-plugin-config.yaml

Using AES-CBC with HMAC authentication, using CKA_ID, using CLI flags and serving on unix socket:
	k8s-kms-plugin
	  serve \
		--log-level=trace  \
		--socket /run/user/1000/k8s-kms-plugin.sock \
		--p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
		--p11-label mylabel \
		--p11-pin mypin \
		--p11-key-id 64636138353931326363356537313264 \
		--p11-hmac-id 30663536623936326235663530363234 \
		--algorithm-family aes-cbc
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

	algFamilyDefault := AlgorithmFamilyAESGCM
	serveCmd.PersistentFlags().Var(&algFamilyDefault, "algorithm-family", "Encryption mechanism. Possible values: aes-gcm, aes-cbc, rsa-oaep, ml-kem.")
	if err := serveCmd.RegisterFlagCompletionFunc("algorithm-family", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem"}, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		slog.Error("error registering flag completion function", "flag", "algorithm-family", "error", err)
	}

	// These flags do not store their values in a variable: they are read from ServeFlags.
	serveCmd.PersistentFlags().Bool("auto-create", false, "Auto create the keys if needed.")
	serveCmd.PersistentFlags().String("p11-key-label", "", "Key Label (CKA_LABEL) for the KMS KEK. The key must have a CKA_ID set on the HSM — it is stored as the KEK ID in Kubernetes etcd.")
	serveCmd.PersistentFlags().String("p11-hmac-label", "", "Key Label (CKA_LABEL) for the HMAC key. The key must have a CKA_ID set on the HSM.")
	serveCmd.PersistentFlags().String("p11-key-id", "", "Key ID CKA_ID for KMS KEK.")
	serveCmd.PersistentFlags().String("p11-hmac-id", "", "Key ID CKA_ID for KMS HMAC.")
	serveCmd.PersistentFlags().StringP("native-path", "p", ".keys", "Path to key store for native provider(Files only).")
	serveCmd.PersistentFlags().String("p11-label", "", "P11 token label.")
	serveCmd.PersistentFlags().String("p11-lib", "", "Path to p11 library/client.")
	serveCmd.PersistentFlags().String("p11-pin", "", "HSM PIN. If omitted, prompted interactively (input hidden). Pass an empty string explicitly to use a no-PIN token.")
	serveCmd.PersistentFlags().Int("p11-slot", 0, "P11 token slot.")
	// Provider
	serveCmd.PersistentFlags().String("provider", "p11", "Provider. Possible values: p11, softhsm, luna, dpod.")
	if err := serveCmd.RegisterFlagCompletionFunc("provider", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"p11", "softhsm", "luna", "dpod"}, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		slog.Error("error registering flag completion function", "flag", "provider", "error", err)
	}

	// Socket
	serveCmd.PersistentFlags().String("socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock.")

	// At least one of KEK CKA_ID or CKA_LABEL must be provided by the user
	serveCmd.MarkFlagsOneRequired("p11-key-id", "p11-key-label")

	// To prevent mismatch between user provided CKA_ID and user provided CKA_LABEL, flags are Mutually Exclusive.
	// NewP11 make sure to retrieve the ID by label, or label by ID.
	serveCmd.MarkFlagsMutuallyExclusive("p11-key-id", "p11-key-label")
	serveCmd.MarkFlagsMutuallyExclusive("p11-hmac-id", "p11-hmac-label")
}

func initProvider() (p providers.Provider, err error) {
	// Validated by sanitizeServeFlags; cast directly to the provider sentinel.
	alg := jose.Alg(flagsServe.AlgorithmFamily)

	// init the provider config from user input
	config := &crypto11.Config{}
	switch flagsServe.Provider {
	case "p11", "softhsm":
		slog.Log(context.Background(), logging.LevelTrace, "initProvider: case p11 or softhsm")
		config = &crypto11.Config{
			Path:            flagsServe.P11Lib,
			Pin:             flagsServe.P11Pin,
			UseGCMIVFromHSM: false,
		}

	case "luna", "dpod":
		slog.Log(context.Background(), logging.LevelTrace, "initProvider: case luna HSM or dpod")
		config = &crypto11.Config{
			Path:            flagsServe.P11Lib,
			Pin:             flagsServe.P11Pin,
			UseGCMIVFromHSM: true,
			GCMIVFromHSMControl: crypto11.GCMIVFromHSMConfig{
				SupplyIvForHSMGCMEncrypt: false,
				SupplyIvForHSMGCMDecrypt: true,
			},
		}
	default:
		slog.Error("unknown provider", "provider", flagsServe.Provider)
		err = errors.New("unknown provider")
		return
	}

	if flagsServe.P11Label != "" {
		config.TokenLabel = flagsServe.P11Label
	} else {
		config.SlotNumber = &flagsServe.P11Slot
	}
	// init the provider for active key only (no key rotation)
	// TODO: See https://github.com/eclipse-keysealer/k8s-kms-plugin/issues/40#issuecomment-2593267852
	if p, err = providers.NewP11(
		config,
		flagsServe.CreateKey,
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
