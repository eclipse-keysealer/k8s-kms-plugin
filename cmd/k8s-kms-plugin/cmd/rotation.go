// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"context"
	"errors"
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
	OldNativePath      string `koanf:"old-native-path"`
	OldP11Label        string `koanf:"old-p11-label"`
	OldP11Lib          string `koanf:"old-p11-lib"`
	OldP11Pin          string `koanf:"old-p11-pin"`
	OldP11Slot         int    `koanf:"old-p11-slot"`
	OldProvider        string `koanf:"old-provider"`
	OldSocketPath      string `koanf:"old-socket"` // Unix socket path for old KEK HSM

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
	Short: "KEK Key rotation for KMS v2",
	Long: `Handles Kubernetes KMS v2 requests and support KEK key rotation with x1 old KEK key and x1 active KEK key.
"k8s-kms-pluginc serve rotation" is very similar to the "k8s-kms-plugin serve" command, but adds key rotation support.
Refer to the kubernetes KMS v2 documentation for more details about key rotation.
https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#developing-a-kms-plugin-gRPC-server-notes-kms-v2

KMS v2 API: https://pkg.go.dev/k8s.io/kms@v0.34.1/apis/v2

How --old-p11-key-id / --old-p11-key-label (and --old-p11-hmac-id / --old-p11-hmac-label) are resolved:
docs/cli-user-interface/cka-id-vs-cka-label.md
`,
	Example: `
Using flags and serving on unix socket (gRPC plaintext):
	k8s-kms-plugin \
	  serve \
		--log-level=trace \
		--socket /run/user/1000/k8s-kms-plugin.sock \
		--p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
		--p11-label mylabel \
		--p11-pin mypin \
		--p11-key-label rsa0 \
		--algorithm-family rsa-oaep \
		  rotation \
			--old-p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
			--old-p11-label mylabel \
			--old-p11-pin mypin \
			--old-p11-key-id 64636138353931326363356537313264 \
			--old-p11-hmac-id 30663536623936326235663530363234 \
			--old-algorithm-family aes-cbc

Using environment variables and configuration file:
	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin serve rotation --config my-kms-plugin-config.yaml

Using both CLI Flags, environment variables and configuration file and serving on unix socket:
	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin --log-format=json serve rotation --config my-kms-plugin-config.yaml
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

	oldAlgFamilyDefault := AlgorithmFamilyAESGCM
	rotationCmd.Flags().Var(&oldAlgFamilyDefault, "old-algorithm-family", "Encryption mechanism of the old KEK. Possible values: aes-gcm, aes-cbc, rsa-oaep, ml-kem.")
	if err := rotationCmd.RegisterFlagCompletionFunc("old-algorithm-family", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem"}, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		slog.Error("error registering flag completion function", "flag", "old-algorithm-family", "error", err)
	}
	if err := rotationCmd.MarkFlagRequired("old-algorithm-family"); err != nil {
		slog.Error("error marking flag required", "flag", "old-algorithm-family", "error", err)
	}
	rotationCmd.Flags().String("old-native-path", "", "Native path for old KEK")
	rotationCmd.Flags().String("old-p11-label", "", "P11 token label for old KEK")
	rotationCmd.Flags().String("old-p11-lib", "", "Path to P11 library/client for old KEK")
	rotationCmd.Flags().String("old-p11-pin", "", "HSM PIN for old KEK. If omitted, prompted interactively (input hidden). Pass an empty string explicitly to use a no-PIN token.")

	rotationCmd.Flags().Int("old-p11-slot", 0, "P11 token slot for old KEK")
	rotationCmd.Flags().String("old-provider", "p11", "Provider for old KEK")
	rotationCmd.Flags().String("old-socket", "", "Unix socket path for old KEK")
	rotationCmd.Flags().String("old-p11-key-label", "", "Key Label (CKA_LABEL) for the old KEK. The key must have a CKA_ID set on the HSM.")
	rotationCmd.Flags().String("old-p11-hmac-id", "", "Key ID CKA_ID for old KEK HMAC")
	rotationCmd.Flags().String("old-p11-hmac-label", "", "Key Label (CKA_LABEL) for the old KEK HMAC. The key must have a CKA_ID set on the HSM.")
	rotationCmd.Flags().String("old-p11-key-id", "", "Key ID CKA_ID for old KEK")

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

	// init the provider activeConfig from user input
	activeConfig := &crypto11.Config{}
	switch flagsServe.Provider {
	case "p11", "softhsm":
		slog.Log(context.Background(), logging.LevelTrace, "initProvider: case p11 or softhsm")
		activeConfig = &crypto11.Config{
			Path:            flagsServe.P11Lib,
			Pin:             flagsServe.P11Pin,
			UseGCMIVFromHSM: false,
		}

	case "luna", "dpod":
		slog.Log(context.Background(), logging.LevelTrace, "initProvider: case luna HSM or dpod")
		activeConfig = &crypto11.Config{
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
		activeConfig.TokenLabel = flagsServe.P11Label
	} else {
		activeConfig.SlotNumber = &flagsServe.P11Slot
	}

	// Rotated old key — validated by sanitizeRotationFlags; cast directly to provider sentinel.
	rotatedAlg := jose.Alg(flagsRotation.OldAlgorithmFamily)

	// init the provider oldConfig from user input
	oldConfig := &crypto11.Config{}
	switch flagsRotation.OldProvider {
	case "p11", "softhsm":
		slog.Log(context.Background(), logging.LevelTrace, "initProvider: case p11 or softhsm")
		oldConfig = &crypto11.Config{
			Path:            flagsRotation.OldP11Lib,
			Pin:             flagsRotation.OldP11Pin,
			UseGCMIVFromHSM: false,
		}

	case "luna", "dpod":
		slog.Log(context.Background(), logging.LevelTrace, "initProvider: case luna HSM or dpod")
		oldConfig = &crypto11.Config{
			Path:            flagsRotation.OldP11Lib,
			Pin:             flagsRotation.OldP11Pin,
			UseGCMIVFromHSM: true,
			GCMIVFromHSMControl: crypto11.GCMIVFromHSMConfig{
				SupplyIvForHSMGCMEncrypt: false,
				SupplyIvForHSMGCMDecrypt: true,
			},
		}
	default:
		slog.Error("unknown provider", "provider", flagsRotation.OldProvider)
		err = errors.New("unknown provider")
		return
	}

	if flagsRotation.OldP11Label != "" {
		oldConfig.TokenLabel = flagsRotation.OldP11Label
	} else {
		oldConfig.SlotNumber = &flagsRotation.OldP11Slot
	}
	// init the provider
	// TODO: See https://github.com/eclipse-keysealer/k8s-kms-plugin/issues/40#issuecomment-2593267852
	if pRot, err = providers.NewP11(
		oldConfig,
		flagsServe.CreateKey,
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
