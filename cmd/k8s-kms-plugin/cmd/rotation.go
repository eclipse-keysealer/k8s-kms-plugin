// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/eclipse-keypont/crypto11/v2"
	"github.com/eclipse-keypont/gose/jose"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	k8skmsv2 "k8s.io/kms/apis/v2"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/logging"
	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/providers"
	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/version"
)

// RotationFlags holds the resolved values of the serve rotation command flags. The koanf tags are
// the long flag names, which are also the keys of the k8s-kms-plugin.serve.rotation section of the
// config file.
// These are the parameters of the KEK key that is being rotated, which means it is the old KEK.
// Use ServeFlags for the current new KEK.
type RotationFlags struct {
	// PKCS #11 & KMS plugin parameters
	OldAlgorithmFamily string `koanf:"old-algorithm-family"`
	OldP11Label        string `koanf:"old-p11-label"`
	OldP11Lib          string `koanf:"old-p11-lib"`
	OldP11Pin          string `koanf:"old-p11-pin"`
	OldP11Slot         int    `koanf:"old-p11-slot"`
	OldProvider        string `koanf:"old-provider"`

	// CKA_ID and CKA_LABEL
	OldDekKeyLabel  string `koanf:"old-p11-key-label"`
	OldHmacKeyID    string `koanf:"old-p11-hmac-id"`
	OldHmacKeyLabel string `koanf:"old-p11-hmac-label"`
	OldKekKeyID     string `koanf:"old-p11-key-id"`
}

// flagsRotation holds the resolved serve rotation command configuration.
var flagsRotation RotationFlags

// cfgRotation reports which rotation settings the user actually provided; see cmdConfig.
var cfgRotation *cmdConfig

// rotationCmd represents the keyRotation command
var rotationCmd = &cobra.Command{
	Use:   "rotation",
	Short: "Serve KMS v2 and also decrypt data written under a previous KEK",
	Long: `Serve the Kubernetes KMS v2 API exactly as "k8s-kms-plugin serve" does, and additionally
decrypt data that was written under one previous KEK.

Every DecryptRequest is routed by the key_id Kubernetes stored with the data: the active KEK
decrypts its own data, the old KEK decrypts everything older. Encryption always uses the active
KEK, so this command does not re-encrypt anything by itself — kube-apiserver rewrites the
objects, and once it has rewritten them all the old KEK can be dropped.

The old KEK is described by a second, complete set of --old-* flags, so it may live on another
token or another HSM than the active one. The active KEK keeps the flags of the parent "serve"
command, including --socket: this command listens on that one socket.

Reference:

- Kubernetes KMS rotation notes: https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#developing-a-kms-plugin-gRPC-server-notes-kms-v2
- KMS v2 API: https://pkg.go.dev/k8s.io/kms/apis/v2
- CKA_ID vs CKA_LABEL: https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/docs/cli-user-interface/cka-id-vs-cka-label.md
`,
	Example: `
  # Active KEK on the command line, old KEK after the "rotation" subcommand.
  # Both PINs are prompted for, in that order, unless they come from the environment.
  k8s-kms-plugin serve \
    --socket /run/user/1000/k8s-kms-plugin.sock \
    --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --p11-label mytoken \
    --p11-key-label rsa0 \
    --algorithm-family rsa-oaep \
    rotation \
      --old-p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
      --old-p11-label mytoken \
      --old-p11-key-id 64636138353931326363356537313264 \
      --old-p11-hmac-id 30663536623936326235663530363234 \
      --old-algorithm-family aes-cbc

  # Both KEKs from a configuration file, both PINs from the environment.
  export K8S_KMS_PLUGIN_SERVE_P11_PIN=mypin
  export K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_PIN=myoldpin
  k8s-kms-plugin --config my-kms-plugin-config.yaml serve rotation
`,
	// Resolve the rotation flags from all input sources during the persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Manually call parent's PersistentPreRunE
		if cmd.Parent() != nil && cmd.Parent().PersistentPreRunE != nil {
			if err := cmd.Parent().PersistentPreRunE(cmd.Parent(), args); err != nil {
				return err
			}
		}

		var err error
		if cfgRotation, err = resolveCmdConfigE(cmd, &flagsRotation); err != nil {
			slog.Error("error resolving configuration", "cobra_cmd", cmd.Name(), "error", err)
			return err
		}
		return sanitizeRotationFlags(&flagsRotation)
	},
	RunE: func(cmd *cobra.Command, _ []string) (err error) {
		silenceUsage(cmd)

		// Show the version of the k8s-kms-plugin and commit ID
		version.LogVersion()

		if flagsServe.P11Pin, err = resolvePin(cfgServe, "p11-pin", "Enter HSM PIN: "); err != nil {
			return
		}
		if flagsRotation.OldP11Pin, err = resolvePin(cfgRotation, "old-p11-pin", "Enter old KEK HSM PIN: "); err != nil {
			return
		}

		// provider for the KEK that is being rotated, aka the old KEK
		var p providers.Provider

		p, err = initRotatedProvider()
		if err != nil && providers.IsPKCS11AuthenticationError(err) {
			// Don't panic/exit if we have a PKCS#11 error.
			// Sleep forever instead.
			slog.Error("PKCS11 authentication error detected. Further retries may cause the token to be erased.", "cobra_cmd", cmd.Use, "error", err)
			slog.Warn("Process will now sleep indefinitely to prevent further damage...", "cobra_cmd", cmd.Use)
			time.Sleep(8760 * time.Hour)
		}

		if err != nil {
			logging.Fatal("failed to initialize rotated provider for old KEK", "cobra_cmd", cmd.Use, "error", err)
		}

		_ = os.Remove(flagsServe.SocketPath)
		var grpcUNIX net.Listener
		if grpcUNIX, err = net.Listen("unix", flagsServe.SocketPath); err != nil {
			return
		}
		// Grant group read/write so a co-located client (e.g. kube-apiserver
		// running under a shared gid) can connect to the socket.
		if err := os.Chmod(flagsServe.SocketPath, 0775); err != nil { //nolint:gosec // group access is intentional, see comment above
			slog.Error("error setting socket permissions", "path", flagsServe.SocketPath, "error", err)
		}

		if err = grpcRotation(grpcUNIX, p); err != nil {
			slog.Error("gRPC server error", "cobra_cmd", cmd.Use, "error", err)
		}

		return nil
	},
}

func init() {
	serveCmd.AddCommand(rotationCmd)

	// The old KEK is described by a complete second set of flags, so it can live on a different
	// token — or a different HSM — than the active one. Their usage text mirrors the serve flags
	// they shadow; see "k8s-kms-plugin serve --help" for the shared rules.

	// The token holding the old KEK
	rotationCmd.Flags().String("old-provider", "p11",
		"PKCS #11 driver quirks to apply to the old KEK's token. One of: p11, softhsm, luna, dpod.")
	registerFixedCompletion(rotationCmd, "old-provider", "p11", "softhsm", "luna", "dpod")

	rotationCmd.Flags().String("old-p11-lib", "",
		"Path to the PKCS #11 library of the old KEK's TPM or HSM.")
	markFlagFilename(rotationCmd, "old-p11-lib", "so", "dylib", "dll")

	rotationCmd.Flags().String("old-p11-label", "",
		"Token label of the old KEK's token. Takes precedence over --old-p11-slot.")
	rotationCmd.Flags().Int("old-p11-slot", 0,
		"Slot number of the old KEK's token. Only used when --old-p11-label is empty.")
	rotationCmd.Flags().String("old-p11-pin", "",
		"PIN of the old KEK's token. If omitted, prompted interactively with hidden input; pass an "+
			"empty string explicitly for a token that takes no PIN.")

	// The old KEK itself
	oldAlgFamilyDefault := AlgorithmFamilyAESGCM
	rotationCmd.Flags().Var(&oldAlgFamilyDefault, "old-algorithm-family",
		"Mechanism the old KEK was used with. One of: aes-gcm, aes-cbc, rsa-oaep, ml-kem. Required: "+
			"data written under it cannot be read back with the wrong mechanism.")
	registerFixedCompletion(rotationCmd, "old-algorithm-family", "aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem")
	if err := rotationCmd.MarkFlagRequired("old-algorithm-family"); err != nil {
		slog.Error("error marking flag required", "flag", "old-algorithm-family", "error", err)
	}

	rotationCmd.Flags().String("old-p11-key-id", "",
		"CKA_ID of the old KEK, as a hex string. Mutually exclusive with --old-p11-key-label; "+
			"exactly one of the two is required.")
	rotationCmd.Flags().String("old-p11-key-label", "",
		"CKA_LABEL of the old KEK. Mutually exclusive with --old-p11-key-id; exactly one of the two "+
			"is required. The key must also carry a CKA_ID on the token.")
	rotationCmd.Flags().String("old-p11-hmac-id", "",
		"CKA_ID of the old HMAC key, as a hex string. aes-cbc only. Mutually exclusive with "+
			"--old-p11-hmac-label.")
	rotationCmd.Flags().String("old-p11-hmac-label", "",
		"CKA_LABEL of the old HMAC key. aes-cbc only. Mutually exclusive with --old-p11-hmac-id.")
	registerNoFileCompletion(rotationCmd,
		"old-p11-label", "old-p11-slot", "old-p11-pin",
		"old-p11-key-id", "old-p11-key-label", "old-p11-hmac-id", "old-p11-hmac-label")

	// At least one of the old KEK CKA_ID or old CKA_LABEL must be provided by the user
	rotationCmd.MarkFlagsOneRequired("old-p11-key-id", "old-p11-key-label")

	// To prevent mismatch between user provided CKA_ID and user provided CKA_LABEL, flags are Mutually Exclusive.
	// NewP11 make sure to retrieve the ID by label, or label by ID.
	rotationCmd.MarkFlagsMutuallyExclusive("old-p11-key-id", "old-p11-key-label")
	rotationCmd.MarkFlagsMutuallyExclusive("old-p11-hmac-id", "old-p11-hmac-label")
}

// sanitizeRotationFlags validates all user-controlled fields in RotationFlags.
func sanitizeRotationFlags(f *RotationFlags) error {
	if err := validateAlgorithmFamily(f.OldAlgorithmFamily); err != nil {
		return fmt.Errorf("--old-algorithm-family: %w", err)
	}
	if len(f.OldP11Label) > maxCkaLabelBytes {
		return fmt.Errorf("--old-p11-label: length %d exceeds maximum of %d bytes", len(f.OldP11Label), maxCkaLabelBytes)
	}
	if len(f.OldDekKeyLabel) > maxCkaLabelBytes {
		return fmt.Errorf("--old-p11-key-label: length %d exceeds maximum of %d bytes", len(f.OldDekKeyLabel), maxCkaLabelBytes)
	}
	if len(f.OldHmacKeyLabel) > maxCkaLabelBytes {
		return fmt.Errorf("--old-p11-hmac-label: length %d exceeds maximum of %d bytes", len(f.OldHmacKeyLabel), maxCkaLabelBytes)
	}
	return nil
}

func initRotatedProvider() (pRot providers.Provider, err error) {
	// Active key — validated by sanitizeServeFlags; cast directly to provider sentinel.
	activeAlg := jose.Alg(flagsServe.AlgorithmFamily)
	// Rotated old key — validated by sanitizeRotationFlags; cast directly to provider sentinel.
	rotatedAlg := jose.Alg(flagsRotation.OldAlgorithmFamily)

	// Two tokens, described by two disjoint sets of flags: the active KEK keeps the flags of the
	// parent `serve` command, the old KEK has its own --old-* set. They may be different tokens on
	// different HSMs, which is the whole reason the second set exists, so the two configurations
	// must not be crossed or shared.
	var activeConfig, oldConfig *crypto11.Config
	if activeConfig, err = newCrypto11Config(
		flagsServe.Provider, flagsServe.P11Lib, flagsServe.P11Pin, flagsServe.P11Label, flagsServe.P11Slot,
	); err != nil {
		return
	}
	if oldConfig, err = newCrypto11Config(
		flagsRotation.OldProvider, flagsRotation.OldP11Lib, flagsRotation.OldP11Pin,
		flagsRotation.OldP11Label, flagsRotation.OldP11Slot,
	); err != nil {
		return
	}

	// init the provider
	// TODO: See https://github.com/eclipse-keysealer/k8s-kms-plugin/issues/40#issuecomment-2593267852
	if pRot, err = providers.NewP11(
		activeConfig,
		flagsServe.KekKeyID,
		flagsServe.DekKeyLabel,
		flagsServe.HmacKeyLabel,
		flagsServe.HmacKeyID,
		activeAlg,
		true, // key rotation
		oldConfig,
		flagsRotation.OldKekKeyID,
		flagsRotation.OldDekKeyLabel,
		flagsRotation.OldHmacKeyLabel,
		flagsRotation.OldHmacKeyID,
		rotatedAlg,
	); err != nil {
		return
	}
	return
}

func grpcRotation(gl net.Listener, p providers.Provider) (err error) {
	slog.Log(context.Background(), logging.LevelTrace, "grpcRotation")

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
