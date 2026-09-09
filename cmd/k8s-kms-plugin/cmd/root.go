// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

// Package cmd implements the k8s-kms-plugin cobra CLI: the root command plus
// the serve, serve rotation, docs, and version subcommands.
package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
	"github.com/spf13/cobra"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/logging"
)

// cfgFile is the only cobra flag variable the code reads directly: the configuration file has
// to be known before koanf can resolve anything else. Every other flag value is read from the
// per-command structs below, which koanf populates from all four input sources.
var cfgFile string

// RootFlags holds the resolved values of the root command flags. The koanf tags are the long
// flag names, which are also the keys of the k8s-kms-plugin section of the config file.
type RootFlags struct {
	ConfigFile string `koanf:"config"`
	Debug      bool   `koanf:"debug"`
	LogFormat  string `koanf:"log-format"`
	LogLevel   string `koanf:"log-level"`
}

// flagsRoot holds the resolved root command configuration.
var flagsRoot RootFlags

// activeLogLevel is the runtime-adjustable log level shared by all slog handlers.
var activeLogLevel = new(slog.LevelVar)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "k8s-kms-plugin",
	Short: "Thales KMS Server for K8S",
	Long: `Use k8s-kms-plugin to connect a kubernetes cluster to a PKCS  #11 TPM or HSM
using KMS v2.

k8s-kms-plugin prioritizes configuration sources as follows: CLI flags > environment variables > configuration files > default settings.

Project Page: https://github.com/eclipse-keysealer/k8s-kms-plugin
`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		slog.Warn("No subcommand provided. Please use one of the available subcommands. Showing help message.")
		return cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Ensure initConfig runs before anything else
	cobra.OnInitialize(initConfig)

	// Define cobra commands groups
	kmsCmdsGrpMain := &cobra.Group{
		ID:    "kmscmdsgrpmain", // ID needs to be lowercase
		Title: "Main KMS Commands:",
	}

	// Add groups to the root command
	rootCmd.AddGroup(kmsCmdsGrpMain)

	// Flag values are read from the RootFlags struct that koanf populates, so flags are registered
	// without "Flags().*Var" (StringVar, BoolVar, Uint16Var, ...) unless the value is needed before
	// koanf runs, which is only the case for --config.

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "k8s-kms-plugin.config.yaml", "ConfigFile. Env var: K8S_KMS_PLUGIN_CONFIG_FILE")

	// logging level
	rootCmd.PersistentFlags().Bool("debug", false, "Set log level to \"debug\". This is equivalent to using --log-level=debug. Flags --log-level and --debug flag are mutually exclusive. Env var: K8S_KMS_PLUGIN_DEBUG.")
	rootCmd.PersistentFlags().String("log-level", "info", "Set log level. Possible values: trace, debug, info, warn, error, quiet. Flags --log-level and --debug flag are mutually exclusive. Env var: K8S_KMS_PLUGIN_LOG_LEVEL.")
	if err := rootCmd.RegisterFlagCompletionFunc("log-level", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"trace", "debug", "info", "warn", "error", "quiet"}, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		slog.Error("error registering flag completion function", "flag", "log-level", "error", err)
	}
	rootCmd.PersistentFlags().String("log-format", "text", "Log output format. Possible values: text, json. Env var: K8S_KMS_PLUGIN_LOG_FORMAT")
	if err := rootCmd.RegisterFlagCompletionFunc("log-format", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"text", "json"}, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		slog.Error("error registering flag completion function", "flag", "log-format", "error", err)
	}
	rootCmd.MarkFlagsMutuallyExclusive("log-level", "debug") // --log-level and --debug flag are mutually exclusive since debug is an alias for log-level=debug
}

// initConfig loads the configuration file and resolves the root command flags from it, from the
// environment and from the command line. It runs through cobra.OnInitialize, before the
// PersistentPreRunE of the command being executed, so the config file is parsed once and every
// subcommand resolves its own section from it.
func initConfig() {
	// Parse the configuration file, if there is one
	if err := loadConfigFileE(rootCmd); err != nil {
		slog.Error("error reading config file", "error", err)
	}

	// Resolve the root command flags: CLI flags > env vars > config file > defaults
	if _, err := resolveCmdConfigE(rootCmd, &flagsRoot); err != nil {
		slog.Error("error resolving configuration", "cobra_cmd", rootCmd.Name(), "error", err)
	}

	// Determine log level. --debug is an alias for --log-level=debug, and cobra rejects the two
	// being set together, so the resolved value alone decides.
	if flagsRoot.Debug {
		activeLogLevel.Set(slog.LevelDebug)
	} else {
		level, err := logging.ParseLevel(flagsRoot.LogLevel)
		if err != nil {
			slog.Error("unknown log level", "error", err)
		}
		activeLogLevel.Set(level)
		if level == logging.LevelQuiet {
			slog.SetDefault(slog.New(slog.DiscardHandler))
			return
		}
	}

	// Build slog handler based on requested format
	opts := &tint.Options{
		Level:       activeLogLevel,
		TimeFormat:  time.DateTime,
		AddSource:   true,
		ReplaceAttr: logging.ReplaceAttr,
	}
	var handler slog.Handler
	switch flagsRoot.LogFormat {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level:       activeLogLevel,
			AddSource:   true,
			ReplaceAttr: logging.ReplaceAttr,
		})
	case "text":
		handler = tint.NewTextHandler(os.Stderr, opts)
	default:
		handler = tint.NewTextHandler(os.Stderr, opts)
		slog.Error("unknown log format", "format", flagsRoot.LogFormat)
	}
	slog.SetDefault(slog.New(handler))

	slog.Debug("log format configured", "log_format", flagsRoot.LogFormat)
	slog.Debug("log level configured", "log_level", flagsRoot.LogLevel)
}
