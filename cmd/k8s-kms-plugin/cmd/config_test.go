// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestServeCmd builds a throwaway `k8s-kms-plugin serve` command tree carrying a
// representative subset of the real serve flags: one string, one int, one bool, the custom
// pflag.Value used by --algorithm-family, and the two mutually exclusive key selectors.
// Using a throwaway tree keeps the package-level rootCmd out of the tests.
func newTestServeCmd() (root, serve *cobra.Command) {
	root = &cobra.Command{Use: "k8s-kms-plugin"}
	root.PersistentFlags().String("log-level", "info", "")

	serve = &cobra.Command{Use: "serve"}
	alg := AlgorithmFamilyAESGCM
	serve.PersistentFlags().Var(&alg, "algorithm-family", "")
	serve.PersistentFlags().String("p11-lib", "", "")
	serve.PersistentFlags().String("p11-pin", "", "")
	serve.PersistentFlags().String("p11-key-id", "", "")
	serve.PersistentFlags().String("p11-key-label", "", "")
	serve.PersistentFlags().String("socket", "/tmp/default.sock", "")
	serve.PersistentFlags().Int("p11-slot", 0, "")
	serve.PersistentFlags().Bool("auto-create", false, "")
	serve.MarkFlagsOneRequired("p11-key-id", "p11-key-label")
	serve.MarkFlagsMutuallyExclusive("p11-key-id", "p11-key-label")

	root.AddCommand(serve)
	return root, serve
}

// newTestRotationCmd extends newTestServeCmd with a `rotation` subcommand, so the tests can
// check that a second level of subcommand gets its own config section and env prefix.
func newTestRotationCmd() (root, serve, rotation *cobra.Command) {
	root, serve = newTestServeCmd()
	rotation = &cobra.Command{Use: "rotation"}
	oldAlg := AlgorithmFamilyAESGCM
	rotation.Flags().Var(&oldAlg, "old-algorithm-family", "")
	rotation.Flags().String("old-p11-lib", "", "")
	rotation.Flags().String("old-p11-pin", "", "")
	rotation.Flags().String("old-p11-key-label", "", "")
	rotation.Flags().Int("old-p11-slot", 0, "")
	serve.AddCommand(rotation)
	return root, serve, rotation
}

// useConfig installs config as the package-level config file layer for the duration of the test.
func useConfig(t *testing.T, config string) {
	t.Helper()
	k, err := parseConfig([]byte(config), yaml.Parser())
	require.NoError(t, err)
	saved := configK
	configK = k
	t.Cleanup(func() { configK = saved })
}

// ── section paths and environment variable names ──────────────────────────────

func TestSectionPathMirrorsCommandPath(t *testing.T) {
	_, serve, rotation := newTestRotationCmd()

	assert.Equal(t, "k8s-kms-plugin.serve", sectionPath(serve))
	assert.Equal(t, "k8s-kms-plugin.serve.rotation", sectionPath(rotation))
}

func TestEnvVarNameMirrorsCommandPath(t *testing.T) {
	root, serve, rotation := newTestRotationCmd()

	assert.Equal(t, "K8S_KMS_PLUGIN_LOG_LEVEL", envVarName(envPrefix(sectionPath(root)), "log-level"))
	assert.Equal(t, "K8S_KMS_PLUGIN_SERVE_P11_PIN", envVarName(envPrefix(sectionPath(serve)), "p11-pin"))
	assert.Equal(t, "K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_PIN",
		envVarName(envPrefix(sectionPath(rotation)), "old-p11-pin"))
}

// ── the priority chain ────────────────────────────────────────────────────────

// TestResolveCmdConfig_Priority walks the four input sources of one flag, adding one source at
// a time, and asserts that each takes precedence over the ones below it:
// CLI flag > env var > config file > default.
func TestResolveCmdConfig_Priority(t *testing.T) {
	const configFile = `
k8s-kms-plugin:
  serve:
    socket: "/from/config.sock"
`
	cases := []struct {
		name       string
		withConfig bool
		env        string
		args       []string
		want       string
	}{
		{name: "default", want: "/tmp/default.sock"},
		{name: "config file over default", withConfig: true, want: "/from/config.sock"},
		{name: "env var over default", env: "/from/env.sock", want: "/from/env.sock"},
		{name: "env var over config file", withConfig: true, env: "/from/env.sock", want: "/from/env.sock"},
		{
			name: "flag over env var and config file", withConfig: true, env: "/from/env.sock",
			args: []string{"--socket", "/from/flag.sock"}, want: "/from/flag.sock",
		},
		{
			name: "flag over config file", withConfig: true,
			args: []string{"--socket", "/from/flag.sock"}, want: "/from/flag.sock",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.withConfig {
				useConfig(t, configFile)
			} else {
				useConfig(t, "")
			}
			if tc.env != "" {
				t.Setenv("K8S_KMS_PLUGIN_SERVE_SOCKET", tc.env)
			}

			_, serve := newTestServeCmd()
			require.NoError(t, serve.ParseFlags(tc.args))

			var flags ServeFlags
			cfg, err := resolveCmdConfigE(serve, &flags)
			require.NoError(t, err)

			assert.Equal(t, tc.want, flags.SocketPath)
			assert.Equal(t, tc.want, cfg.String("socket"))
		})
	}
}

// TestResolveCmdConfig_TypedValues verifies that a config file value and an env var value both
// land in the typed struct fields, not only in the string ones.
func TestResolveCmdConfig_TypedValues(t *testing.T) {
	useConfig(t, `
k8s-kms-plugin:
  serve:
    p11-slot: 3
    auto-create: true
    algorithm-family: "rsa-oaep"
`)
	_, serve := newTestServeCmd()
	require.NoError(t, serve.ParseFlags(nil))

	var flags ServeFlags
	_, err := resolveCmdConfigE(serve, &flags)
	require.NoError(t, err)

	assert.Equal(t, 3, flags.P11Slot)
	assert.True(t, flags.CreateKey)
	assert.Equal(t, "rsa-oaep", flags.AlgorithmFamily)
}

// TestResolveCmdConfig_EnvVarTypeCoercion covers the same typed fields arriving as strings
// through the environment, which is the only shape an env var can have.
func TestResolveCmdConfig_EnvVarTypeCoercion(t *testing.T) {
	useConfig(t, "")
	t.Setenv("K8S_KMS_PLUGIN_SERVE_P11_SLOT", "7")
	t.Setenv("K8S_KMS_PLUGIN_SERVE_AUTO_CREATE", "true")

	_, serve := newTestServeCmd()
	require.NoError(t, serve.ParseFlags(nil))

	var flags ServeFlags
	_, err := resolveCmdConfigE(serve, &flags)
	require.NoError(t, err)

	assert.Equal(t, 7, flags.P11Slot)
	assert.True(t, flags.CreateKey)
}

// TestResolveCmdConfig_IgnoresForeignEnvVars checks that only the environment variables naming a
// flag of this command are read. A variable of a sibling or child command shares the prefix but
// must not reach this command's configuration.
func TestResolveCmdConfig_IgnoresForeignEnvVars(t *testing.T) {
	useConfig(t, "")
	t.Setenv("K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_LIB", "/from/rotation.so")
	t.Setenv("K8S_KMS_PLUGIN_SERVE_NOT_A_FLAG", "ignored")

	_, serve := newTestServeCmd()
	require.NoError(t, serve.ParseFlags(nil))

	var flags ServeFlags
	cfg, err := resolveCmdConfigE(serve, &flags)
	require.NoError(t, err)

	assert.Empty(t, flags.P11Lib)
	assert.False(t, cfg.IsSet("rotation-old-p11-lib"))
	assert.False(t, cfg.IsSet("not-a-flag"))
}

// ── subcommand hierarchy ──────────────────────────────────────────────────────

// TestResolveCmdConfig_SubcommandSection verifies that a nested subcommand reads its own
// section of the config file — the one whose path mirrors the command path — and that the
// parent's section does not leak into it.
func TestResolveCmdConfig_SubcommandSection(t *testing.T) {
	useConfig(t, `
k8s-kms-plugin:
  serve:
    p11-lib: "/active/token.so"
    p11-key-label: "active-kek"
    rotation:
      old-p11-lib: "/old/token.so"
      old-p11-key-label: "old-kek"
      old-algorithm-family: "aes-cbc"
      old-p11-slot: 2
`)
	_, serve, rotation := newTestRotationCmd()
	require.NoError(t, serve.ParseFlags(nil))
	require.NoError(t, rotation.ParseFlags(nil))

	var serveFlags ServeFlags
	_, err := resolveCmdConfigE(serve, &serveFlags)
	require.NoError(t, err)

	var rotationFlags RotationFlags
	_, err = resolveCmdConfigE(rotation, &rotationFlags)
	require.NoError(t, err)

	assert.Equal(t, "/active/token.so", serveFlags.P11Lib)
	assert.Equal(t, "active-kek", serveFlags.DekKeyLabel)

	assert.Equal(t, "/old/token.so", rotationFlags.OldP11Lib)
	assert.Equal(t, "old-kek", rotationFlags.OldDekKeyLabel)
	assert.Equal(t, "aes-cbc", rotationFlags.OldAlgorithmFamily)
	assert.Equal(t, 2, rotationFlags.OldP11Slot)
}

// TestResolveCmdConfig_SubcommandEnvVarPrefix verifies that the env var of a nested subcommand
// carries the whole command path, and that it beats the same key in the config file.
func TestResolveCmdConfig_SubcommandEnvVarPrefix(t *testing.T) {
	useConfig(t, `
k8s-kms-plugin:
  serve:
    rotation:
      old-p11-pin: "from-config"
`)
	t.Setenv("K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_PIN", "from-env")

	_, _, rotation := newTestRotationCmd()
	require.NoError(t, rotation.ParseFlags(nil))

	var flags RotationFlags
	_, err := resolveCmdConfigE(rotation, &flags)
	require.NoError(t, err)

	assert.Equal(t, "from-env", flags.OldP11Pin)
}

// TestResolveCmdConfig_DottedSectionKey checks that a config file spelling a whole section path
// as a single dotted key reaches the same command as the nested spelling.
func TestResolveCmdConfig_DottedSectionKey(t *testing.T) {
	useConfig(t, `"k8s-kms-plugin.serve.socket": "/from/dotted.sock"`)

	_, serve := newTestServeCmd()
	require.NoError(t, serve.ParseFlags(nil))

	var flags ServeFlags
	_, err := resolveCmdConfigE(serve, &flags)
	require.NoError(t, err)

	assert.Equal(t, "/from/dotted.sock", flags.SocketPath)
}

// TestResolveCmdConfig_InheritedFlagsAreNotResolved verifies that a command resolves only the
// flags it declares. --log-level belongs to the root command, so the serve section of the
// config file must not be able to set it.
func TestResolveCmdConfig_InheritedFlagsAreNotResolved(t *testing.T) {
	useConfig(t, `
k8s-kms-plugin:
  serve:
    log-level: "trace"
`)
	_, serve := newTestServeCmd()
	require.NoError(t, serve.ParseFlags(nil))

	var flags ServeFlags
	cfg, err := resolveCmdConfigE(serve, &flags)
	require.NoError(t, err)

	assert.False(t, cfg.IsSet("log-level"), "log-level is a root flag, not a serve flag")
	assert.Equal(t, "info", serve.Flag("log-level").Value.String())
}

// TestResolveCmdConfig_ParentFlagTypedOnSubcommand covers `serve --p11-pin x rotation ...`: the
// parent flag is parsed as part of the subcommand invocation, and the parent still has to see it
// as typed on the command line, since that is what makes it win over the config file.
func TestResolveCmdConfig_ParentFlagTypedOnSubcommand(t *testing.T) {
	useConfig(t, `
k8s-kms-plugin:
  serve:
    p11-pin: "from-config"
`)
	_, serve, rotation := newTestRotationCmd()
	// cobra parses the whole command line on the executed command, whose flag set includes the
	// persistent flags inherited from its parents.
	require.NoError(t, rotation.ParseFlags([]string{"--p11-pin", "from-flag", "--old-p11-pin", "old-from-flag"}))

	var serveFlags ServeFlags
	_, err := resolveCmdConfigE(serve, &serveFlags)
	require.NoError(t, err)

	var rotationFlags RotationFlags
	_, err = resolveCmdConfigE(rotation, &rotationFlags)
	require.NoError(t, err)

	assert.Equal(t, "from-flag", serveFlags.P11Pin)
	assert.Equal(t, "old-from-flag", rotationFlags.OldP11Pin)
}

// ── explicitly set vs. defaulted ──────────────────────────────────────────────

// TestResolveCmdConfig_IsSet distinguishes a key a user configured from one that only carries
// the flag default. --p11-pin depends on it: an explicit empty PIN is a no-PIN token, while an
// absent one means "prompt".
func TestResolveCmdConfig_IsSet(t *testing.T) {
	useConfig(t, `
k8s-kms-plugin:
  serve:
    p11-lib: "/from/config.so"
`)
	t.Setenv("K8S_KMS_PLUGIN_SERVE_P11_PIN", "")

	_, serve := newTestServeCmd()
	require.NoError(t, serve.ParseFlags([]string{"--socket", "/from/flag.sock"}))

	var flags ServeFlags
	cfg, err := resolveCmdConfigE(serve, &flags)
	require.NoError(t, err)

	assert.True(t, cfg.IsSet("p11-lib"), "set by the config file")
	assert.True(t, cfg.IsSet("p11-pin"), "set to an empty string by an env var")
	assert.True(t, cfg.IsSet("socket"), "set by a CLI flag")
	assert.False(t, cfg.IsSet("p11-key-label"), "never set: only the flag default")
	assert.False(t, cfg.IsSet("p11-slot"), "never set: only the flag default")
}

// ── write-back into the cobra flag set ────────────────────────────────────────

// TestResolveCmdConfig_SatisfiesFlagGroups verifies the one cobra workaround that survives the
// migration: a value that arrives through the config file or the environment is written back
// into the cobra flag set, so MarkFlagsOneRequired sees it as provided.
func TestResolveCmdConfig_SatisfiesFlagGroups(t *testing.T) {
	cases := []struct {
		name   string
		config string
		env    map[string]string
	}{
		{
			name: "from the config file",
			config: `
k8s-kms-plugin:
  serve:
    p11-key-label: "my-kek"
`,
		},
		{
			name:   "from an env var",
			config: "",
			env:    map[string]string{"K8S_KMS_PLUGIN_SERVE_P11_KEY_LABEL": "my-kek"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useConfig(t, tc.config)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			_, serve := newTestServeCmd()
			require.NoError(t, serve.ParseFlags(nil))

			var flags ServeFlags
			_, err := resolveCmdConfigE(serve, &flags)
			require.NoError(t, err)

			assert.Equal(t, "my-kek", flags.DekKeyLabel)
			assert.True(t, serve.Flag("p11-key-label").Changed,
				"cobra must see the flag as provided, or MarkFlagsOneRequired rejects the command")
			require.NoError(t, serve.ValidateFlagGroups())
		})
	}
}

// TestResolveCmdConfig_MutuallyExclusiveFromConfig verifies that setting both members of a
// mutually exclusive pair in the config file is rejected, exactly as passing both flags is.
func TestResolveCmdConfig_MutuallyExclusiveFromConfig(t *testing.T) {
	useConfig(t, `
k8s-kms-plugin:
  serve:
    p11-key-label: "my-kek"
    p11-key-id: "aa22334455bc"
`)
	_, serve := newTestServeCmd()
	require.NoError(t, serve.ParseFlags(nil))

	var flags ServeFlags
	_, err := resolveCmdConfigE(serve, &flags)
	require.NoError(t, err)

	assert.Error(t, serve.ValidateFlagGroups())
}

// TestResolveCmdConfig_DefaultsDoNotMarkFlagsChanged is the counterpart: a config file that
// merely restates a default must not mark that flag as provided, or it would collide with the
// flag it is mutually exclusive with.
func TestResolveCmdConfig_DefaultsDoNotMarkFlagsChanged(t *testing.T) {
	useConfig(t, `
k8s-kms-plugin:
  serve:
    p11-key-label: "my-kek"
    p11-key-id: ""
`)
	_, serve := newTestServeCmd()
	require.NoError(t, serve.ParseFlags(nil))

	var flags ServeFlags
	_, err := resolveCmdConfigE(serve, &flags)
	require.NoError(t, err)

	assert.False(t, serve.Flag("p11-key-id").Changed)
	require.NoError(t, serve.ValidateFlagGroups())
}

// TestResolveCmdConfig_RejectsInvalidCustomFlagValue verifies that a value from the config file
// still goes through the pflag.Value of --algorithm-family when it is written back, so an
// unsupported family cannot reach the cobra flag. The resolved struct is validated separately
// by sanitizeServeFlags, which is the single choke point for every input source.
func TestResolveCmdConfig_RejectsInvalidCustomFlagValue(t *testing.T) {
	useConfig(t, `
k8s-kms-plugin:
  serve:
    algorithm-family: "aes-256-gcm"
`)
	_, serve := newTestServeCmd()
	require.NoError(t, serve.ParseFlags(nil))

	var flags ServeFlags
	_, err := resolveCmdConfigE(serve, &flags)
	require.NoError(t, err)

	assert.Equal(t, "aes-gcm", serve.Flag("algorithm-family").Value.String(), "the flag keeps its default")
	assert.Error(t, sanitizeServeFlags(&flags), "the resolved value is what validation rejects")
}

// ── config file discovery and parsing ─────────────────────────────────────────

func TestParserForPath(t *testing.T) {
	yamlDoc := []byte("k8s-kms-plugin:\n  serve:\n    socket: \"/s.sock\"\n")
	jsonDoc := []byte(`{"k8s-kms-plugin":{"serve":{"socket":"/s.sock"}}}`)
	tomlDoc := []byte("[k8s-kms-plugin.serve]\nsocket = \"/s.sock\"\n")

	cases := []struct {
		path string
		raw  []byte
	}{
		{"/etc/c.yaml", yamlDoc},
		{"/etc/c.yml", yamlDoc},
		{"/etc/c.json", jsonDoc},
		{"/etc/c.toml", tomlDoc},
		{"/etc/c", yamlDoc},      // no extension: parsed as YAML
		{"/etc/c.conf", yamlDoc}, // unknown extension: parsed as YAML
		{"/etc/c.YAML", yamlDoc}, // extension matching is case-insensitive
		{"/etc/c.yaml", jsonDoc}, // YAML is a superset of JSON
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			k, err := parseConfig(tc.raw, parserForPath(tc.path))
			require.NoError(t, err)
			assert.Equal(t, "/s.sock", k.String("k8s-kms-plugin.serve.socket"))
		})
	}
}

func TestParseConfig_Malformed(t *testing.T) {
	_, err := parseConfig([]byte("k8s-kms-plugin:\n\tserve: {}\n"), yaml.Parser())
	assert.Error(t, err)
}

// TestLoadConfigFileE_FlagOverEnvOverDefaultLocation walks the three ways the configuration file
// itself is named, in priority order.
func TestLoadConfigFileE_FlagOverEnvOverDefaultLocation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, socket string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path,
			[]byte("k8s-kms-plugin:\n  serve:\n    socket: \""+socket+"\"\n"), 0o600))
		return path
	}
	fromFlag := write("flag.yaml", "/from/flag-file.sock")
	fromEnv := write("env.yaml", "/from/env-file.sock")

	t.Run("--config wins over the env var", func(t *testing.T) {
		t.Setenv(envVarConfigFile, fromEnv)
		root, _ := newTestServeCmd()
		root.PersistentFlags().StringVar(&cfgFile, "config", "", "")
		require.NoError(t, root.ParseFlags([]string{"--config", fromFlag}))

		require.NoError(t, loadConfigFileE(root))
		assert.Equal(t, fromFlag, configFileUsed)
		assert.Equal(t, "/from/flag-file.sock", configK.String("k8s-kms-plugin.serve.socket"))
	})

	t.Run("the env var is used when --config is absent", func(t *testing.T) {
		t.Setenv(envVarConfigFile, fromEnv)
		root, _ := newTestServeCmd()
		root.PersistentFlags().StringVar(&cfgFile, "config", "", "")
		require.NoError(t, root.ParseFlags(nil))

		require.NoError(t, loadConfigFileE(root))
		assert.Equal(t, fromEnv, configFileUsed)
		assert.Equal(t, "/from/env-file.sock", configK.String("k8s-kms-plugin.serve.socket"))
	})

	t.Run("the default locations are searched last", func(t *testing.T) {
		t.Setenv(envVarConfigFile, "")
		t.Setenv("HOME", dir)
		write(configFileBaseName+".yaml", "/from/home.sock")

		root, _ := newTestServeCmd()
		root.PersistentFlags().StringVar(&cfgFile, "config", "", "")
		require.NoError(t, root.ParseFlags(nil))

		require.NoError(t, loadConfigFileE(root))
		assert.Equal(t, filepath.Join(dir, configFileBaseName+".yaml"), configFileUsed)
		assert.Equal(t, "/from/home.sock", configK.String("k8s-kms-plugin.serve.socket"))
	})
}

// TestLoadConfigFileE_NoConfigFileIsNotAnError covers the ordinary case of a CLI driven entirely
// by flags and environment variables.
func TestLoadConfigFileE_NoConfigFileIsNotAnError(t *testing.T) {
	t.Setenv(envVarConfigFile, "")
	t.Setenv("HOME", t.TempDir())

	root, _ := newTestServeCmd()
	root.PersistentFlags().StringVar(&cfgFile, "config", "", "")
	require.NoError(t, root.ParseFlags(nil))

	require.NoError(t, loadConfigFileE(root))
	assert.Empty(t, configFileUsed)
	assert.Empty(t, configK.Keys())
}

// TestLoadConfigFileE_MissingExplicitFileIsAnError verifies that a file the user named but that
// does not exist fails loudly, rather than starting the plugin with a silently empty config.
func TestLoadConfigFileE_MissingExplicitFileIsAnError(t *testing.T) {
	root, _ := newTestServeCmd()
	root.PersistentFlags().StringVar(&cfgFile, "config", "", "")
	require.NoError(t, root.ParseFlags([]string{"--config", filepath.Join(t.TempDir(), "absent.yaml")}))

	assert.Error(t, loadConfigFileE(root))
}

// TestLoadConfigFileE_UnparseableFileIsAnError verifies the same for a file that exists but is
// not valid YAML.
func TestLoadConfigFileE_UnparseableFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.yaml")
	require.NoError(t, os.WriteFile(path, []byte("k8s-kms-plugin:\n\tserve: {}\n"), 0o600))

	root, _ := newTestServeCmd()
	root.PersistentFlags().StringVar(&cfgFile, "config", "", "")
	require.NoError(t, root.ParseFlags([]string{"--config", path}))

	assert.Error(t, loadConfigFileE(root))
}

// TestCmdConfig_NilIsSafe documents that the accessors tolerate a nil receiver, which is the
// state of a command's configuration if its pre-run never got the chance to resolve it.
func TestCmdConfig_NilIsSafe(t *testing.T) {
	var cfg *cmdConfig
	assert.False(t, cfg.IsSet("p11-pin"))
	assert.Equal(t, "", cfg.String("p11-pin"))
}

// TestCmdConfig_UnknownKey covers a key no flag declares.
func TestCmdConfig_UnknownKey(t *testing.T) {
	cfg := &cmdConfig{k: koanf.New(keyDelim), explicit: map[string]bool{}}
	assert.False(t, cfg.IsSet("nope"))
	assert.Equal(t, "", cfg.String("nope"))
}
