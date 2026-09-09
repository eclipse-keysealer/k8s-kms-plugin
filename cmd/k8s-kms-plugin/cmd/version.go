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
	Short: "Print version, build and git metadata",
	Long: `Print the version of k8s-kms-plugin together with the build and git repository metadata
it was compiled from: commit, build date, platform and Go toolchain.

Use -o json or -o yaml to consume it from a script; with no --output the version is printed as
a single human-readable line.`,
	// Examples belong in Example, not Long: cobra's markdown generator wraps this field in a
	// fenced code block, whereas the two-space indentation they had inside Long is below the four
	// Markdown needs for a code block — so the "# ..." comment lines were parsed as level-1
	// headings and rendered as page titles on GitHub and on the documentation site.
	Example: `
  # Version and git details as a one-line JSON string, ready to pipe into jq.
  k8s-kms-plugin version -o json --pretty=false

  # The same, as indented YAML.
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
	versionCmd.Flags().StringVarP(&outputFormat, "output", "o", "",
		"Machine-readable output format. One of: yaml, json. Omit for a single human-readable line.")
	registerFixedCompletion(versionCmd, "output", "yaml", "json")
	versionCmd.Flags().BoolVarP(&prettyPrintVersion, "pretty", "P", true,
		"Indent the JSON output. Set to false for a one-line string.")
}
