// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

// Configuration plumbing: koanf + cobra.
//
// The CLI resolves every setting from four sources, in this order of decreasing priority:
//
//	CLI flag  >  environment variable  >  configuration file  >  flag default
//
// Both the environment variable and the configuration file key of a flag derive from the
// *command path* the flag is declared on, so the hierarchy of subcommands is mirrored in
// both spellings:
//
//	k8s-kms-plugin serve rotation --old-p11-pin
//	  env var    K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_PIN
//	  file key   k8s-kms-plugin.serve.rotation.old-p11-pin
//
// koanf builds that priority chain by layering providers into one instance per command, in
// increasing order of priority:
//
//  1. the configuration file subsection for the command path (koanf.Merge of a Cut subtree),
//  2. the environment variables whose name matches a flag the command declares,
//  3. the pflag set (posflag), which only overrides a key when the user actually typed the
//     flag, and otherwise supplies the flag default for keys no other layer provided.
//
// This is why there is no equivalent of the former viper-patch-sub.go: viper.Sub() dropped the
// flag/env/default chain for a config subsection, which had to be worked around by merging the
// subsection back into the global config layer. koanf composes the layers explicitly, so a
// subsection is just another provider and the ordering is the one written above.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/parsers/toml/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/logging"
)

const (
	// keyDelim separates the segments of a configuration key. It matches the separator used
	// between command names in a config file section path (k8s-kms-plugin.serve.rotation).
	keyDelim = "."

	// configFileBaseName is the file name, without extension, searched for in the default
	// locations when neither --config nor K8S_KMS_PLUGIN_CONFIG names a file.
	configFileBaseName = "k8s-kms-plugin.conf"

	// envVarConfigFile names the configuration file when --config is not passed.
	envVarConfigFile = "K8S_KMS_PLUGIN_CONFIG"

	// structTag is the struct tag the per-command flag structs are unmarshalled through.
	structTag = "koanf"
)

// configFileExts are the extensions searched for in the default locations, and the extensions
// recognised on an explicitly named file. Anything else is parsed as YAML, which is a superset
// of JSON.
var configFileExts = []string{"yaml", "yml", "json", "toml"}

// configK holds the parsed configuration file, or an empty instance when no file was found.
// It is the config-file layer every command draws its own subsection from.
var configK = koanf.New(keyDelim)

// configFileUsed is the path of the configuration file that was loaded, empty when none was.
var configFileUsed string

// cmdConfig is the resolved configuration of one cobra command: the merged koanf instance plus
// the set of keys a user actually provided through a flag, an environment variable or the
// configuration file.
//
// The distinction matters because posflag seeds every key that no other layer provided with the
// flag default, so a key existing in the merged instance says nothing about whether the user
// configured it. --p11-pin relies on that difference: an explicitly configured empty PIN is a
// valid no-PIN token, while an absent PIN means "prompt for it".
type cmdConfig struct {
	k        *koanf.Koanf
	explicit map[string]bool
}

// IsSet reports whether key was provided by a CLI flag, an environment variable or the
// configuration file. Flag defaults do not count as set.
func (c *cmdConfig) IsSet(key string) bool {
	if c == nil {
		return false
	}
	return c.explicit[key]
}

// String returns the resolved value of key as a string, empty when the key is unknown.
func (c *cmdConfig) String(key string) string {
	if c == nil {
		return ""
	}
	return c.k.String(key)
}

// sectionPath returns the configuration file section of a command, which is its command path
// with the spaces replaced by the key delimiter: "k8s-kms-plugin serve rotation" becomes
// "k8s-kms-plugin.serve.rotation".
func sectionPath(cmd *cobra.Command) string {
	return strings.ReplaceAll(cmd.CommandPath(), " ", keyDelim)
}

// envPrefix returns the environment variable prefix of a command: the section path uppercased,
// with both the key delimiter and the dashes of a command name turned into underscores.
// "k8s-kms-plugin.serve.rotation" becomes "K8S_KMS_PLUGIN_SERVE_ROTATION_".
func envPrefix(section string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", keyDelim, "_").Replace(section)) + "_"
}

// envVarName returns the environment variable of a flag declared on the command whose
// environment prefix is prefix.
func envVarName(prefix, flagName string) string {
	return prefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// resolveCmdConfigE resolves the configuration of one cobra command and unmarshals it into
// target, a struct whose `koanf` tags are the long flag names of that command.
//
// Only the flags the command declares itself are resolved — cobra's LocalFlags(), which is its
// own local and persistent flags but not the persistent flags it inherits. A flag therefore has
// exactly one environment variable and one config file key, the ones documented for the command
// it is declared on, and each parent command resolves its own flags in its own pass.
//
// The returned cmdConfig reports which keys the user actually set; see cmdConfig.
func resolveCmdConfigE(cmd *cobra.Command, target any) (*cmdConfig, error) {
	ctx := context.Background()
	section := sectionPath(cmd)
	prefix := envPrefix(section)
	flags := cmd.LocalFlags()

	slog.Log(ctx, logging.LevelTrace, "resolving command configuration",
		"cobra_cmd", cmd.Name(), "section_path", section, "env_prefix", prefix)

	k := koanf.New(keyDelim)

	// Layer 1 — the configuration file subsection for this command path. A section holding the
	// subsections of child commands is fine: keys that match no struct field are ignored.
	if configK.Exists(section) {
		if err := k.Merge(configK.Cut(section)); err != nil {
			return nil, fmt.Errorf("failed to merge config section %q: %w", section, err)
		}
	} else {
		slog.Log(ctx, logging.LevelTrace, "no config file section for command", "section_path", section)
	}

	// Layer 2 — environment variables. Only the variables that name a flag this command declares
	// are read: mapping back from an environment variable to a flag name is ambiguous in general
	// (an underscore may stand for a dash or for itself), and restricting the mapping to known
	// flags keeps it exact and matches the documented table.
	byEnvVar := make(map[string]string)
	flags.VisitAll(func(f *pflag.Flag) {
		byEnvVar[envVarName(prefix, f.Name)] = f.Name
	})
	envProvider := env.ProviderWithValue(prefix, keyDelim, func(envKey, value string) (string, any) {
		name, ok := byEnvVar[envKey]
		if !ok {
			return "", nil // not a flag of this command: ignore
		}
		return name, value
	})
	if err := k.Load(envProvider, nil); err != nil {
		return nil, fmt.Errorf("failed to load environment variables with prefix %q: %w", prefix, err)
	}

	// Everything present at this point came from the user rather than from a flag default.
	explicit := make(map[string]bool, len(byEnvVar))
	flags.VisitAll(func(f *pflag.Flag) {
		if k.Exists(f.Name) {
			explicit[f.Name] = true
		}
	})

	// Layer 3 — the flags themselves. posflag only writes a key when the flag was typed on the
	// command line, or when no layer below provided it, in which case it contributes the default.
	if err := k.Load(posflag.Provider(flags, keyDelim, k), nil); err != nil {
		return nil, fmt.Errorf("failed to load flags of %q: %w", cmd.CommandPath(), err)
	}
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			explicit[f.Name] = true
		}
	})

	cfg := &cmdConfig{k: k, explicit: explicit}

	if err := k.UnmarshalWithConf("", target, koanf.UnmarshalConf{Tag: structTag}); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration of %q: %w", cmd.CommandPath(), err)
	}

	syncFlagsFromConfig(cmd, flags, cfg)

	return cfg, nil
}

// syncFlagsFromConfig writes back into the cobra flag set the values that reached the command
// through an environment variable or the configuration file.
//
// Cobra's MarkFlagsOneRequired and MarkFlagsMutuallyExclusive decide from pflag's Changed bit,
// which only the command line sets. Without this write-back, a --p11-key-label supplied through
// K8S_KMS_PLUGIN_SERVE_P11_KEY_LABEL or through the config file would leave
// MarkFlagsOneRequired("p11-key-id", "p11-key-label") unsatisfied and the command would fail
// with a flag it was in fact given. This is a cobra limitation rather than a koanf one, so it
// survives the migration away from viper.
//
// A value equal to the one the flag already carries is skipped: writing it would mark the flag
// as changed without changing anything, which would make a configuration file that merely
// restates a default (debug: false) collide with a mutually exclusive flag.
func syncFlagsFromConfig(cmd *cobra.Command, flags *pflag.FlagSet, cfg *cmdConfig) {
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Changed || !cfg.IsSet(f.Name) {
			return
		}
		value := cfg.String(f.Name)
		if value == f.Value.String() {
			return
		}
		if err := flags.Set(f.Name, value); err != nil {
			slog.Error("error applying configured value to cobra flag",
				"cobra_cmd", cmd.Name(), "flag", f.Name, "error", err)
		}
	})
}

// loadConfigFileE finds and parses the configuration file into configK.
//
// The file is looked up, in order, from the --config flag, from the K8S_KMS_PLUGIN_CONFIG
// environment variable, and finally as k8s-kms-plugin.conf.{yaml,yml,json,toml} in the home
// directory or in ~/.config/k8s-kms-plugin/. /etc is deliberately not searched: a packaged
// example has to be passed explicitly.
//
// A missing file is not an error — the CLI runs on flags, environment variables and defaults.
// A file that exists but cannot be read or parsed is.
func loadConfigFileE(cmd *cobra.Command) error {
	ctx := context.Background()
	configK = koanf.New(keyDelim)
	configFileUsed = ""

	path, explicit := findConfigFile(cmd)
	if path == "" {
		slog.Log(ctx, logging.LevelTrace, "no config file found; continuing with env vars, flags and defaults")
		return nil
	}

	raw, err := os.ReadFile(path) //nolint:gosec // the path comes from the operator, through --config, an env var or their home directory
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			// Raced against a deletion between the search and the read.
			slog.Log(ctx, logging.LevelTrace, "config file disappeared before it could be read", "config_file", path)
			return nil
		}
		return fmt.Errorf("error reading config file %s: %w", path, err)
	}

	k, err := parseConfig(raw, parserForPath(path))
	if err != nil {
		return fmt.Errorf("error parsing config file %s: %w", path, err)
	}

	configK = k
	configFileUsed = path
	slog.Log(ctx, logging.LevelTrace, "config file loaded", "config_file", path)
	return nil
}

// findConfigFile returns the path of the configuration file to read and whether the user named
// it explicitly. It returns an empty path when no file was named and none was found in the
// default locations.
func findConfigFile(cmd *cobra.Command) (path string, explicit bool) {
	ctx := context.Background()

	if f := cmd.Flags().Lookup("config"); f != nil && f.Changed && cfgFile != "" {
		slog.Log(ctx, logging.LevelTrace, "config file named by the --config flag", "config_file", cfgFile)
		return cfgFile, true
	}
	if envValue, ok := os.LookupEnv(envVarConfigFile); ok && envValue != "" {
		slog.Log(ctx, logging.LevelTrace, "config file named by an env var",
			"env_var", envVarConfigFile, "config_file", envValue)
		return envValue, true
	}

	home, err := os.UserHomeDir()
	if err != nil {
		slog.Log(ctx, logging.LevelTrace, "no home directory to search for a config file", "error", err)
		return "", false
	}
	for _, dir := range []string{home, filepath.Join(home, ".config", "k8s-kms-plugin")} {
		for _, ext := range configFileExts {
			candidate := filepath.Join(dir, configFileBaseName+keyDelim+ext)
			if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
				slog.Log(ctx, logging.LevelTrace, "config file found in a default location", "config_file", candidate)
				return candidate, false
			}
		}
	}
	slog.Log(ctx, logging.LevelTrace, "no config file in the default locations",
		"dirs", []string{home, filepath.Join(home, ".config", "k8s-kms-plugin")})
	return "", false
}

// parseConfig parses raw configuration bytes into a koanf instance.
//
// Keys are unflattened on the key delimiter, so a file may nest its sections
// (k8s-kms-plugin: {serve: {socket: ...}}) or spell a whole path in one key
// ("k8s-kms-plugin.serve.socket": ...); both reach the same section.
func parseConfig(raw []byte, parser koanf.Parser) (*koanf.Koanf, error) {
	mp, err := parser.Unmarshal(raw)
	if err != nil {
		return nil, err
	}
	k := koanf.New(keyDelim)
	if err := k.Load(confmap.Provider(mp, keyDelim), nil); err != nil {
		return nil, err
	}
	return k, nil
}

// parserForPath returns the koanf parser matching the file extension. YAML is the fallback for
// an unknown or absent extension, and parses JSON too.
func parserForPath(path string) koanf.Parser {
	switch strings.ToLower(strings.TrimPrefix(filepath.Ext(path), ".")) {
	case "json":
		return json.Parser()
	case "toml":
		return toml.Parser()
	default:
		return yaml.Parser()
	}
}
