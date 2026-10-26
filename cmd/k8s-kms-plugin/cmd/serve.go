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
	"strings"
	"syscall"
	"time"

	"github.com/eclipse-keypont/crypto11/v2"
	"github.com/eclipse-keypont/gose/jose"

	k8skmsv2 "k8s.io/kms/apis/v2"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/logging"
	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/providers"
	version "github.com/eclipse-keysealer/k8s-kms-plugin/pkg/version"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
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

	// socketPerm is the mode the gRPC unix socket is created with. Connecting to a unix
	// socket requires write permission, so 0775 lets the owner and the group connect — a
	// co-located client such as a kube-apiserver running under a shared gid — and nobody
	// else. The read and execute bits granted to others convey no ability to connect.
	socketPerm = 0o775

	// socketUmask is the complement of socketPerm within the 0777 a socket is created with.
	socketUmask = 0o777 &^ socketPerm

	// maxGRPCMsgSize caps a single gRPC message in BYTES, in both directions.
	//
	// gRPC's own default is 4 MiB received, and unlimited sent. Nothing this plugin speaks
	// comes close: the largest legal KMS v2 message is a request carrying the 32 KiB
	// annotations budget plus a 1 kB ciphertext and a 1 kB key ID, so roughly 34 KiB. 64 KiB
	// leaves that comfortable headroom while refusing — before any of it is buffered — the
	// multi-megabyte message a local process could otherwise make the plugin allocate.
	//
	// The interceptor's per-field checks stay where they are. They run after a message has
	// been received and decoded, so they bound what is processed, not what is allocated.
	maxGRPCMsgSize = 64 * 1024

	// maxGRPCConcurrentStreams caps in-flight RPCs per connection. The only client is a
	// co-located kube-apiserver issuing small, short unary calls, so this is generous; it
	// exists to stop one client pinning the HSM session with unbounded concurrency.
	maxGRPCConcurrentStreams = 64

	// grpcMaxConnectionIdle closes a connection that has had no active RPC for this long, so
	// a client that goes away without closing does not hold resources indefinitely. gRPC
	// clients reconnect transparently, so this is invisible to a healthy apiserver.
	grpcMaxConnectionIdle = 15 * time.Minute

	// grpcConnectionTimeout bounds how long a connection may take to complete its setup.
	grpcConnectionTimeout = 30 * time.Second
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
	if f.SocketPath == "" {
		return fmt.Errorf("--socket: path is empty")
	}
	// A leading "@" or NUL makes this an abstract socket. An abstract socket lives in the
	// network namespace instead of the filesystem, so it has no owner and no mode: every
	// process in the namespace may connect and ask the plugin to unwrap DEKs, and there is
	// no permission to set that would prevent it. Reject it rather than serve one.
	if strings.HasPrefix(f.SocketPath, "@") || strings.HasPrefix(f.SocketPath, "\x00") {
		return fmt.Errorf("--socket: %q is an abstract socket; abstract sockets have no filesystem permissions "+
			"and cannot be access-controlled, so a filesystem path is required", f.SocketPath)
	}
	return nil
}

// listenOnUnixSocket creates the gRPC listener, with the socket's final permissions already in
// place.
//
// The mode is applied through the umask rather than by calling os.Chmod after net.Listen.
// A chmod resolves the path a second time, so anything able to swap the socket for a symlink in
// between — a world-writable parent directory such as the default under $TMPDIR is enough —
// has the mode applied to the symlink's target instead. Creating the socket under a umask
// closes that window: bind(2) sets the final mode itself and the path is never resolved twice.
//
// Every failure here is returned rather than logged. The previous code logged a failed chmod and
// carried on, which meant a socket whose permissions nobody had chosen still went on to serve
// unwrap requests.
func listenOnUnixSocket(socketPath string) (net.Listener, error) {
	// Clear a socket left behind by a previous run, but only a socket: anything else at that
	// path was not put there by this plugin, and unlinking it is exactly the arbitrary-file
	// removal this function is meant to avoid.
	if fi, err := os.Lstat(socketPath); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to remove %s: it is not a socket (mode %s)", socketPath, fi.Mode())
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("removing stale socket %s: %w", socketPath, err)
		}
	}

	// syscall.Umask is process-wide, so it is held for exactly the one call that needs it.
	// Startup is single-threaded with respect to file creation here, and no goroutine this
	// process starts creates files.
	oldMask := syscall.Umask(socketUmask)
	l, err := net.Listen("unix", socketPath)
	syscall.Umask(oldMask)
	if err != nil {
		return nil, fmt.Errorf("listening on unix socket %s: %w", socketPath, err)
	}

	// Confirm what actually reached the filesystem. A umask constrains the mode but a
	// filesystem is free to widen it (a default ACL, for instance), and this socket is the
	// only thing standing between a local process and DEK unwrapping. Only extra bits are
	// an error: a stricter mode is the operator's own umask and takes nothing away.
	if fi, err := os.Lstat(socketPath); err == nil {
		if extra := fi.Mode().Perm() &^ os.FileMode(socketPerm); extra != 0 {
			_ = l.Close()
			_ = os.Remove(socketPath)
			return nil, fmt.Errorf("socket %s was created with mode %#o, which grants more than the intended %#o; refusing to serve",
				socketPath, fi.Mode().Perm(), socketPerm)
		}
	}

	return l, nil
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

		var grpcUNIX net.Listener
		if grpcUNIX, err = listenOnUnixSocket(flagsServe.SocketPath); err != nil {
			return
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

// newKMSGRPCServer builds the gRPC server that both `serve` and `serve rotation` run.
//
// The two commands register the same single service on the same kind of listener and differ
// only in which provider they hand it, so they share one constructor: the resource bounds below
// are a property of the KMS v2 protocol, not of either command, and duplicating them invites
// the two copies to drift.
//
// Server reflection is deliberately not registered. It exists to let a generic client discover
// the service schema at runtime, which is a debugging affordance rather than something
// kube-apiserver uses — it is compiled against the KMS v2 protobuf. Leaving it on told any
// local process that reached the socket exactly which methods to call. The e2e suite drives the
// plugin with `grpcurl -proto`, passing the api.proto it resolves from k8s.io/kms, so it does
// not depend on reflection either.
func newKMSGRPCServer(p providers.Provider) *grpc.Server {
	serverOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(p.UnaryInterceptor),
		grpc.UnknownServiceHandler(unknownServiceHandler),
		grpc.MaxRecvMsgSize(maxGRPCMsgSize),
		grpc.MaxSendMsgSize(maxGRPCMsgSize),
		grpc.MaxConcurrentStreams(maxGRPCConcurrentStreams),
		grpc.ConnectionTimeout(grpcConnectionTimeout),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: grpcMaxConnectionIdle,
		}),
	}

	// No keepalive.EnforcementPolicy: it terminates a connection whose client pings more often
	// than the server permits, and the client here is a kube-apiserver whose ping cadence is
	// not this plugin's to assume. Guessing it wrong would drop a working apiserver connection,
	// which is a worse outcome than the ping traffic it would prevent.

	gs := grpc.NewServer(serverOptions...)
	k8skmsv2.RegisterKeyManagementServiceServer(gs, p)
	return gs
}

func grpcServe(gl net.Listener, p providers.Provider) (err error) {
	slog.Log(context.Background(), logging.LevelTrace, "grpcServe")

	gs := newKMSGRPCServer(p)

	slog.Info("serving on socket", "address", gl.Addr().String())

	// grpc.Server.Serve returns only on a non-temporary listener error or once the server
	// is stopped, and it closes the listener before returning. The previous `goto START`
	// re-entered Serve on that same closed listener, which returned immediately and span,
	// turning one Accept failure into a busy loop and a log flood with no recovery. Surface
	// the error so the process can exit and be restarted by its supervisor; grpc already
	// retries genuinely temporary Accept errors internally with backoff.
	if err = gs.Serve(gl); err != nil {
		slog.Error("gRPC serve error", "error", err)
		return err
	}
	return nil
}

// unknownServiceHandler answers a call to a service or method this plugin does not implement.
//
// It used to log the service object itself and return nil. Returning nil reported success for a
// call that did nothing, leaving the caller to infer failure from an empty response, and logging
// the object rendered the provider implementation — an internal structure — into the log at
// Info. It now names the method that was attempted and answers with the status code gRPC
// defines for it, so a misdirected client gets a real error and the log line carries only the
// method string the client itself supplied.
func unknownServiceHandler(_ interface{}, stream grpc.ServerStream) error {
	method, ok := grpc.MethodFromServerStream(stream)
	if !ok {
		method = "unknown"
	}
	slog.Warn("rejected call to an unimplemented service or method", "method", method)
	return status.Errorf(codes.Unimplemented, "unknown service or method: %s", method)
}
