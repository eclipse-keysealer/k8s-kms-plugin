// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"

	"log/slog"

	version "github.com/eclipse-keysealer/k8s-kms-plugin/pkg/version"

	"github.com/spf13/cobra"
)

// CLI options pflags names
var outputFormat string // One of 'yaml' or 'json'.

// prettyPrintVersion defined by the user with flag --pretty
var prettyPrintVersion bool

// VersionFlags holds the resolved values of the version command flags. The koanf tags are the long
// flag names, which are also the keys of the k8s-kms-plugin.version section of the config file.
type VersionFlags struct {
	OutputFormat       string `koanf:"output"`
	PrettyPrintVersion bool   `koanf:"pretty"`
}

// flagsVersion holds the resolved version command configuration.
var flagsVersion VersionFlags

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information.",
	Long: `Print the version information with various level of details
including information of the build and git repository metadata.`,
	// Examples belong in Example, not Long: cobra's markdown generator wraps this field in a
	// fenced code block, whereas the two-space indentation they had inside Long is below the four
	// Markdown needs for a code block — so the "# ..." comment lines were parsed as level-1
	// headings and rendered as page titles on GitHub and on the documentation site.
	Example: `
Print the version with git repository details as a one-line JSON string:
	k8s-kms-plugin version -o json --pretty=false

Print the version as indented YAML:
	k8s-kms-plugin version -o yaml
`,
	// Resolve the version flags from all input sources during the persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if _, err := resolveCmdConfigE(cmd, &flagsVersion); err != nil {
			slog.Error("error resolving configuration", "cobra_cmd", cmd.Name(), "error", err)
			return err
		}
		return nil
	},
	Run: func(cmd *cobra.Command, _ []string) {
		// Output version info
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), version.OutputToString(flagsVersion.OutputFormat, flagsVersion.PrettyPrintVersion)); err != nil {
			slog.Error("error writing version output", "error", err)
		}
	},
}

func init() {
	// rootCmd is the parent command
	rootCmd.AddCommand(versionCmd)

	// Flag values are read from the VersionFlags struct that koanf populates.

	// Here you will define your flags and configuration settings.
	versionCmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Format of the version output. One of 'yaml' or 'json'. Env var: K8S_KMS_PLUGIN_VERSION_OUTPUT")
	if err := versionCmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"yaml", "json"}, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		slog.Error("error registering flag completion function", "flag", "output", "error", err)
	}
	versionCmd.Flags().BoolVarP(&prettyPrintVersion, "pretty", "P", true, "Activate pretty print output for JSON. Env var: K8S_KMS_PLUGIN_VERSION_PRETTY")
	if err := versionCmd.RegisterFlagCompletionFunc("pretty", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"true", "false"}, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		slog.Error("error registering flag completion function", "flag", "pretty", "error", err)
	}
}
