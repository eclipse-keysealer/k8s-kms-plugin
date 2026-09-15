// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/pflag"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/logging"
	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/version"

	"github.com/jedib0t/go-pretty/v6/table"
)

// DocsFlags holds the resolved values of the docs command flags. The koanf tags are the long flag
// names, which are also the keys of the k8s-kms-plugin.docs section of the config file.
type DocsFlags struct {
	Format     string `koanf:"format"`
	OutputDir  string `koanf:"output-dir"`
	Provenance bool   `koanf:"provenance"`
}

// flagsDocs holds the resolved docs command configuration.
var flagsDocs DocsFlags

// docsCmd represents the docs command
var docsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Generate the CLI reference documentation",
	Long: `Generate the CLI reference for every command and flag of k8s-kms-plugin.

The markdown tree and the flag/environment-variable table are committed to
docs/cli-user-interface/, so this command is what "make doc" runs after a flag is added,
renamed or reworded. Its default output is deterministic: two runs on the same source tree
produce byte-identical files.`,
	Example: `
  # Regenerate the committed markdown reference (what "make doc" does).
  k8s-kms-plugin docs --format markdown --output-dir docs/cli-user-interface/markdown/

  # Regenerate the committed flag/env-var table.
  k8s-kms-plugin docs --format cli-table-pretty --output-dir docs/cli-user-interface/txt/

  # Look at the flag table without writing anything you have to clean up afterwards.
  k8s-kms-plugin docs --format cli-table-pretty
`,
	// Resolve the docs flags from all input sources during the persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if _, err := resolveCmdConfigE(cmd, &flagsDocs); err != nil {
			slog.Error("error resolving configuration", "cobra_cmd", cmd.Name(), "error", err)
			return err
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, _ []string) error {
		silenceUsage(cmd)

		err := generateCobraDocs(flagsDocs.Format, flagsDocs.OutputDir, flagsDocs.Provenance)
		if err != nil {
			slog.Error("error generating docs", "format", flagsDocs.Format, "output_dir", flagsDocs.OutputDir, "error", err)
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(docsCmd)

	docsCmd.Flags().StringP("format", "f", "markdown",
		"Output format. One of: markdown (what the documentation site publishes), man, rst, yaml, "+
			"cli-table-csv, cli-table-pretty, cli-table-html, all.")
	registerFixedCompletion(docsCmd, "format",
		"markdown", "man", "rst", "yaml", "cli-table-csv", "cli-table-pretty", "cli-table-html", "all")

	docsCmd.Flags().StringP("output-dir", "o", filepath.Join(os.TempDir(), fmt.Sprintf("k8s-kms-plugin-docs-%s", time.Now().Format(time.RFC3339))),
		"Directory the generated files are written to. Defaults to a fresh timestamped directory "+
			"under $TMPDIR, so two ad hoc runs never overwrite each other.")
	markFlagDirname(docsCmd, "output-dir")

	// The real default is a fresh timestamped directory under $TMPDIR, so two ad hoc runs never
	// overwrite each other. That value cannot be allowed to reach the generated documentation:
	// cobra renders every flag's default into the page, and both the clock and $TMPDIR vary
	// between machines and runs, so the committed markdown would change on every `make doc` —
	// which it did, in cli-env-var-table.md and k8s-kms-plugin_docs.md.
	//
	// DefValue is only ever read to render help and documentation, never to resolve the flag, so
	// replacing it with a placeholder describing the default keeps the behaviour identical while
	// making the generated pages reproducible.
	docsCmd.Flags().Lookup("output-dir").DefValue = "$TMPDIR/k8s-kms-plugin-docs-<timestamp>"

	// Defaults to true inside GitHub Actions so the documentation site records the exact run that
	// built it, and to false locally so `make doc` stays byte-reproducible and its diffs stay
	// reviewable. Pass --provenance=false in CI to opt back out.
	docsCmd.Flags().Bool("provenance", os.Getenv("GITHUB_ACTIONS") == "true",
		"Stamp the build and CI run that produced the pages into the front matter of the generated "+
			"markdown. Defaults to true when GITHUB_ACTIONS=true, so the published site records its "+
			"build while the committed tree stays free of volatile data.")

	// Same reasoning as --output-dir above, for a value that varies by *environment* rather than by
	// clock: this flag's real default is derived from GITHUB_ACTIONS, and cobra renders every
	// default into the generated pages. Left alone, the committed reference says "true" when it was
	// regenerated in CI and "false" when regenerated on a laptop, so the two disagree forever and
	// whichever ran last makes the other look stale. The usage text above already states the rule,
	// so the rendered default only has to be stable.
	docsCmd.Flags().Lookup("provenance").DefValue = "auto"
}

// Front matter for the generated markdown pages.
//
// The markdown tree is committed to docs/cli-user-interface/markdown/ and regenerated by
// `make doc`, so the *default* output must be deterministic: two runs of the same source tree
// have to produce byte-identical files, otherwise every unrelated commit shows up as a diff in
// twelve generated pages and `make doc` stops being reviewable.
//
// That is why build provenance (version, commit, CI run) is gated behind --provenance rather
// than always emitted. Enable it in the pipeline that publishes the documentation site: the
// published page then records the exact CI/CD run that produced it, while the file committed to
// git stays free of volatile data.
const (
	// frontMatterWeightStep spaces out the weight of consecutive pages, leaving room to insert a
	// page between two others without renumbering the whole tree.
	frontMatterWeightStep = 10
	// frontMatterWeightIndex is reserved for the generated index (README.md) so it sorts first.
	frontMatterWeightIndex = 1
	// frontMatterWeightFlagTable is the weight of the generated flag/env-var reference table. It
	// sits between the index and the first command page.
	frontMatterWeightFlagTable = 5
)

// docPageMeta is the deterministic front matter of one generated markdown page.
type docPageMeta struct {
	Title       string // the full command path, e.g. "k8s-kms-plugin serve rotation"
	Description string // the command's Short help text
	Weight      int    // sidebar ordering
}

// buildDocPageMeta walks the cobra command tree and returns the front matter of every page
// doc.GenMarkdownTreeCustom will write, keyed by the file name cobra derives from the command
// path. The key has to be computed the same way cobra does it (spaces to underscores plus a
// .md suffix), because filePrepender only receives that file name — never the *cobra.Command.
//
// The walk is pre-order and follows cmd.Commands(), which cobra keeps sorted by name, so the
// assigned weights are stable across runs.
func buildDocPageMeta(root *cobra.Command) map[string]docPageMeta {
	meta := make(map[string]docPageMeta)
	weight := frontMatterWeightStep

	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		if !cmd.IsAvailableCommand() && cmd != root {
			// Skip hidden and deprecated commands: cobra does not write a page for them either.
			return
		}

		name := strings.ReplaceAll(cmd.CommandPath(), " ", "_") + ".md"
		meta[name] = docPageMeta{
			Title:       cmd.CommandPath(),
			Description: cmd.Short,
			Weight:      weight,
		}
		weight += frontMatterWeightStep

		for _, sub := range cmd.Commands() {
			walk(sub)
		}
	}
	walk(root)

	return meta
}

// yamlQuote renders s as a double-quoted YAML scalar. Command paths and Short help strings are
// developer-controlled, but they do contain characters that are significant in YAML (a colon in
// a Short description is enough to produce an unparseable front matter block), so every value is
// quoted rather than relying on the plain style.
func yamlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ciProvenance returns the front matter keys describing the build and, when running inside
// GitHub Actions, the exact workflow run that generated the page.
//
// The run URL is assembled from the standard GitHub Actions environment rather than hardcoding
// github.com, so it stays correct on GitHub Enterprise. Keys are omitted when the environment
// does not provide them, which keeps the output usable when --provenance is set outside CI (a
// local release rehearsal, for example) — the version and commit still come from the ldflags
// baked in by the Makefile.
func ciProvenance() []string {
	lines := []string{
		"build_version: " + yamlQuote(version.RawGitDescribe),
		"build_commit: " + yamlQuote(version.GitCommitIDLong),
		"build_date: " + yamlQuote(version.BuildDate),
	}

	repo := os.Getenv("GITHUB_REPOSITORY")
	runID := os.Getenv("GITHUB_RUN_ID")
	if repo == "" || runID == "" {
		return lines
	}

	server := os.Getenv("GITHUB_SERVER_URL")
	if server == "" {
		server = "https://github.com"
	}

	lines = append(lines,
		"ci_run_id: "+yamlQuote(runID),
		"ci_run_url: "+yamlQuote(fmt.Sprintf("%s/%s/actions/runs/%s", server, repo, runID)),
	)
	if attempt := os.Getenv("GITHUB_RUN_ATTEMPT"); attempt != "" {
		lines = append(lines, "ci_run_attempt: "+yamlQuote(attempt))
	}
	if wf := os.Getenv("GITHUB_WORKFLOW"); wf != "" {
		lines = append(lines, "ci_workflow: "+yamlQuote(wf))
	}

	return lines
}

// renderFrontMatter builds a YAML front matter block. YAML front matter (rather than Hugo's
// native TOML) is deliberate: Hugo, Astro/Starlight, Docusaurus, VitePress and Jekyll all parse
// it, so the generated tree is not tied to the static site generator eventually chosen.
//
// generator marks these pages as machine-written, so a contributor who opens one knows to change
// the cobra command and re-run `make doc` instead of editing the file.
func renderFrontMatter(meta docPageMeta, provenance bool) string {
	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString("title: ")
	b.WriteString(yamlQuote(meta.Title))
	b.WriteString("\n")
	if meta.Description != "" {
		b.WriteString("description: ")
		b.WriteString(yamlQuote(meta.Description))
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "weight: %d\n", meta.Weight)
	b.WriteString("generator: ")
	b.WriteString(yamlQuote("k8s-kms-plugin docs -f markdown"))
	b.WriteString("\n")
	if provenance {
		for _, line := range ciProvenance() {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	b.WriteString("---\n\n")
	return b.String()
}

// genMarkdownTreeWithFrontMatter generates the cobra markdown tree, prepending the front matter
// block from buildDocPageMeta to every page.
//
// A page cobra writes that buildDocPageMeta did not predict would silently lose its front matter
// and sort to the top of the sidebar, so the mismatch is reported as an error instead: it means
// the two traversals have diverged and buildDocPageMeta needs updating.
func genMarkdownTreeWithFrontMatter(root *cobra.Command, dir string, provenance bool) error {
	meta := buildDocPageMeta(root)

	var prependErr error
	filePrepender := func(filename string) string {
		base := filepath.Base(filename)
		m, ok := meta[base]
		if !ok {
			prependErr = fmt.Errorf("no front matter computed for generated page %q: buildDocPageMeta and cobra's command walk have diverged", base)
			return ""
		}
		return renderFrontMatter(m, provenance)
	}

	// Identity link handler: cobra's inter-page links keep their .md suffix, so the generated
	// tree stays browsable on GitHub. Rewriting them to clean URLs is the static site
	// generator's job (a Hugo render hook, for instance), not the generator's.
	linkHandler := func(name string) string { return name }

	if err := doc.GenMarkdownTreeCustom(root, dir, filePrepender, linkHandler); err != nil {
		return fmt.Errorf("error generating markdown documentation at %s: %w", dir, err)
	}
	if prependErr != nil {
		return prependErr
	}
	return nil
}

// getFlagTable takes a cobra command and a format string and returns a table
// displaying the command's flags, their properties and default values in the
// requested format.
//
// The table columns are:
//   - Command: the name of the command
//   - Flag: the flag name
//   - Short Flag: the short flag name
//   - Env Var: the environment variable name for the flag
//   - Config File Keys: the configuration file key path of the flag
//   - Default: the default value for the flag
//   - Type: the type of the flag
//   - Persistent Flag: whether the flag is persistent
//   - Usage: the usage string for the flag
//
// The formats supported are:
//   - markdown: renders the table in markdown format
//   - html: renders the table in html format
//   - csv: renders the table in comma-separated values format
//   - (default): renders the table in a human-readable "pretty" format
func getFlagTable(c *cobra.Command, format string) string {
	// Initialize the table
	t := table.NewWriter()
	//t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)
	// Create the header with the columns
	t.AppendHeader(table.Row{
		"Command",
		"Flags (long)",
		"Flags (short)",
		"Env Var",
		"Config File Keys",
		"Default Value",
		"Type",
		"Persistent Flag",
		"Usage",
	})

	t.AppendFooter(table.Row{
		"Command",
		"Flags (long)",
		"Flags (short)",
		"Env Var",
		"Config File Keys",
		"Default Value",
		"Type",
		"Persistent Flag",
		"Usage",
	})

	walkCobraFlagsPretty(c, t)

	// render the table in the given format
	switch format {
	case "markdown":
		return t.RenderMarkdown()
	case "html":
		return t.RenderHTML()
	case "csv":
		return t.RenderCSV()
	}
	// Default renders the Table in a human-readable "pretty" format
	return t.Render()
}

// writeFlagTableToFile renders the flag table into filename.
//
// frontMatter is prepended verbatim when non-empty; it is only ever set for the markdown table,
// since the csv, html and plain-text renderings are consumed as data rather than published as
// pages.
func writeFlagTableToFile(c *cobra.Command, format string, filename string, frontMatter string) error {
	f, err := os.Create(filename) //nolint:gosec // filename derives from the operator-supplied --output-dir CLI flag, not untrusted input
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			slog.Error("error closing file", "path", filename, "error", closeErr)
		}
	}()
	if frontMatter != "" {
		if _, err = f.WriteString(frontMatter); err != nil {
			return err
		}
	}
	_, err = f.WriteString(getFlagTable(c, format))
	return err
}

// flagTableFrontMatter is the front matter of the generated flag/env-var reference page.
func flagTableFrontMatter(provenance bool) string {
	return renderFrontMatter(docPageMeta{
		Title:       "CLI flags, environment variables and config keys",
		Description: "Every k8s-kms-plugin flag with its environment variable, config file key, type and default value.",
		Weight:      frontMatterWeightFlagTable,
	}, provenance)
}

// walkCobraFlagsPretty traverses the cobra command tree and prints a pretty table of flags -> env vars -> config file keys
// Only local and non-persistent flags are printed. Local persistent flags are printed as well, but only for the local commands
// and not its subcommands.
// The table is printed to t, which is a table.Writer
// The section is the path for a flag in a configuration file, obtained by replacing spaces with dots in the command path
func walkCobraFlagsPretty(cmd *cobra.Command, t table.Writer) {
	// section is the path (YAML, TOML, JSON) for a flag in a configuration file
	section := strings.ReplaceAll(cmd.CommandPath(), " ", ".")

	// Add only flags that are local and do not add persistent flags
	cmd.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name != "no-descriptions" {
			t.AppendRow(buildTableRow(cmd, f, section, false))
		}
	})

	// Add the persistent flags of the current but not its subcommands
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name != "no-descriptions" {
			t.AppendRow(buildTableRow(cmd, f, section, true))
		}
	})

	// Iterate recurssively on sub command but ignore inherited flags from parent commands to prevent duplication of
	// flags and persistent flags in the documentation
	for _, sub := range cmd.Commands() {
		// Skip cobra's built-in `help` command. It is not part of this CLI's surface — no page is
		// generated for it either — and cobra *adds* it to the tree while generating, so including
		// it made the table depend on whether anything had generated documentation earlier in the
		// same process.
		if sub.Name() == "help" {
			continue
		}
		// Add separator between different commands. This has no effect if the table is rendered as markdown
		t.AppendSeparator()
		walkCobraFlagsPretty(sub, t)
	}
}

// buildTableRow returns a table.Row representing a cobra flag as a row in a table.
// Inputs:
// - cmd: the cobra command that contains the flag
// - f: the flag
// - section: the path (YAML, TOML, JSON) for a flag in a configuration file
// - persistent: whether the flag is a persistent flag or not
//
// The columns of the table are:
// - Command: the path of the command. Example "k8s-kms-plugin serve"
// - Flag: the flag name. Example: --host
// - Short Flag: the short flag name. Example: -p
// - Env Var: the environment variable name that can be used to override the flag. Example: K8S_KMS_PLUGIN_SERVE_HOST.
// - Config File Keys: the full key path in a configuration file (YAML, TOML or JSON). Example: k8s-kms-plugin.serve.host
// - Default: the default value of the flag. Example: host => 0.0.0.0
// - Type: the type of the flag. Example: string
// - Persistent Flag: whether the flag is a persistent flag
// - Usage: the usage string for the flag
func buildTableRow(cmd *cobra.Command, f *pflag.Flag, section string, persistent bool) table.Row {
	// envVarPrefix include the name of the binary and the section of the cli command.
	// Example: K8S_KMS_PLUGIN_SERVE_* for the command k8s-kms-plugin serve
	envVarPrefix := strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(section))

	// envVar is the environment variable name that can be used to override the flag. Ex.: K8S_KMS_PLUGIN_SERVE_HOST
	envVar := envVarPrefix + "_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))

	// configKey is the key name and full path for the configuration file (YAML, TOML or JSON)
	// Example: k8s-kms-plugin.serve.host for the command k8s-kms-plugin serve --host
	configKey := section + "." + f.Name

	return table.Row{
		cmd.CommandPath(),
		"--" + f.Name,
		// if f.Shorthand short flag is empty, then leave cell empty
		func() string {
			if f.Shorthand != "" {
				return "-" + f.Shorthand
			}
			return ""
		}(),
		envVar,
		configKey,
		f.DefValue,
		f.Value.Type(),
		persistent,
		f.Usage,
	}
}

// writeMarkdownReadme writes the index page listing every generated markdown page.
//
// The version/commit/build-date block is only emitted when provenance is enabled. Emitting it
// unconditionally — as this function used to — made every `make doc` rewrite the committed index
// with a new commit hash and timestamp, so the file reported a diff on every unrelated commit and
// could not be used to review actual CLI changes.
func writeMarkdownReadme(dir string, provenance bool) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("unable to read markdown output directory: %w", err)
	}

	readme := strings.Builder{}
	readme.WriteString(renderFrontMatter(docPageMeta{
		Title:       "CLI reference",
		Description: "Auto-generated command reference for k8s-kms-plugin.",
		Weight:      frontMatterWeightIndex,
	}, provenance))

	// No H1 here: the front matter title supplies it, and a static site generator renders that as
	// the page heading — an H1 in the body as well would show the title twice.
	readme.WriteString("This documentation is auto-generated from `k8s-kms-plugin`.\n")
	readme.WriteString("Do not edit these files by hand: change the cobra command and run `make doc`.\n\n")
	if provenance {
		fmt.Fprintf(&readme, "Generated from version `%s`, commit `%s`, on %s.\n\n",
			version.RawGitDescribe, version.GitCommitIDLong, version.BuildDate)
	}

	readme.WriteString("## Available Command Documentation\n\n")
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".md") {
			fmt.Fprintf(&readme, "- [%s](%s)\n", strings.TrimSuffix(f.Name(), ".md"), f.Name())
		}
	}

	readme.WriteString("\n##### Auto Generated README.md file using `k8s-kms-plugin docs -f markdown`\n")

	return os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme.String()), 0600)
}

// initHelpFlags registers --help across the whole command tree before anything is generated.
//
// Cobra adds that flag lazily: Execute() adds it to the command actually being run, and
// doc.GenMarkdownCustom adds it to each command as the tree walk reaches it. The flag table is
// written before that walk, so it used to list --help for `docs` — the command being executed — and
// for nothing else, which is neither true (every command has it) nor stable: a second generation in
// the same process produced a different table, because the first walk had registered the flag
// everywhere by then.
//
// Doing it up front makes the output depend only on the command definitions. Note this deliberately
// does not call InitDefaultHelpCmd: that adds a `help` *subcommand*, which the walk would then emit
// a page for.
func initHelpFlags(cmd *cobra.Command) {
	cmd.InitDefaultHelpFlag()
	for _, c := range cmd.Commands() {
		initHelpFlags(c)
	}
}

// generateCobraDocs generates CLI documentation for the k8s-kms-plugin in the specified format.
// It supports generating documentation in "markdown", "man", "rst", "yaml", "table", or "all" formats.
// The output directory is created if it does not exist. If the format is "all",
// documentation is generated in multiple subdirectories within the given output directory.
// Returns an error if the format is unsupported or if any I/O operation fails.
//
// Parameters:
//   - format: The output format for the documentation (e.g., "markdown", "man", "rst", "yaml", "table", "all").
//   - out: The directory where the generated documentation files will be saved.
//   - provenance: Whether to stamp build and CI run provenance into the markdown front matter.
//
// Returns:
//   - error: An error object if any step of the documentation generation fails.
func generateCobraDocs(format, out string, provenance bool) error {
	// Create the output directory if it doesn't already exist
	if _, err := os.Stat(out); os.IsNotExist(err) {
		slog.Log(context.Background(), logging.LevelTrace, "creating output directory", "path", out)
		if err := os.MkdirAll(out, 0750); err != nil {
			return fmt.Errorf("error creating output directory %s: %w", out, err)
		}
	} else if err != nil {
		return fmt.Errorf("error verifying output directory %s: %w", out, err)
	}

	manHeader := &doc.GenManHeader{
		Title:   "K8S-KMS-PLUGIN",
		Section: "1",
		Manual:  version.RawGitDescribe,
	}

	initHelpFlags(rootCmd)

	// TODO: improve and clean this switch case
	switch format {
	case "markdown":
		slog.Log(context.Background(), logging.LevelTrace, "generating markdown documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, format, filepath.Join(out, "cli-env-var-table.md"), flagTableFrontMatter(provenance)); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}

		if err := genMarkdownTreeWithFrontMatter(rootCmd, out, provenance); err != nil {
			return err
		}
		if err := writeMarkdownReadme(out, provenance); err != nil {
			return fmt.Errorf("error generating markdown readme at %s: %w", out, err)
		}
		return nil
	case "man":
		slog.Log(context.Background(), logging.LevelTrace, "generating man documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, "", filepath.Join(out, "cli-env-var-table.txt"), ""); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}

		if err := doc.GenManTree(rootCmd, manHeader, out); err != nil {
			return fmt.Errorf("error generating man documentation at %s: %w", out, err)
		}
		return nil
	case "rst":
		slog.Log(context.Background(), logging.LevelTrace, "generating rst documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, "", filepath.Join(out, "cli-env-var-table.txt"), ""); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		if err := doc.GenReSTTree(rootCmd, out); err != nil {
			return fmt.Errorf("error generating rst documentation at %s: %w", out, err)
		}
		return nil
	case "yaml":
		slog.Log(context.Background(), logging.LevelTrace, "generating yaml documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, "", filepath.Join(out, "cli-env-var-table.txt"), ""); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		if err := doc.GenYamlTree(rootCmd, out); err != nil {
			return fmt.Errorf("error generating yaml documentation at %s: %w", out, err)
		}
		return nil
	case "cli-table-csv":
		slog.Log(context.Background(), logging.LevelTrace, "generating table documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, "csv", filepath.Join(out, "cli-env-var-table.csv"), ""); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		return nil
	case "cli-table-pretty":
		slog.Log(context.Background(), logging.LevelTrace, "generating table documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, "", filepath.Join(out, "cli-env-var-table.txt"), ""); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		return nil
	case "cli-table-html":
		slog.Log(context.Background(), logging.LevelTrace, "generating table documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, "html", filepath.Join(out, "cli-env-var-table.html"), ""); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		return nil
	case "all":
		for _, dir := range []string{"rst", "markdown", "man", "yaml", "csv", "html", "txt"} {
			if _, err := os.Stat(filepath.Join(out, dir)); os.IsNotExist(err) {
				slog.Log(context.Background(), logging.LevelTrace, "creating output directory", "path", filepath.Join(out, dir))
				if err := os.MkdirAll(filepath.Join(out, dir), 0750); err != nil {
					return fmt.Errorf("error creating output directory %s: %w", filepath.Join(out, dir), err)
				}
			} else if err != nil {
				return fmt.Errorf("error verifying output directory %s: %w", filepath.Join(out, dir), err)
			}
		}

		slog.Log(context.Background(), logging.LevelTrace, "generating all documentation", "path", out)
		// markdown
		if err := genMarkdownTreeWithFrontMatter(rootCmd, filepath.Join(out, "markdown"), provenance); err != nil {
			return err
		}
		if err := writeFlagTableToFile(rootCmd, "markdown", filepath.Join(out, "markdown", "cli-env-var-table.md"), flagTableFrontMatter(provenance)); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		if err := writeMarkdownReadme(filepath.Join(out, "markdown"), provenance); err != nil {
			return fmt.Errorf("error generating markdown readme at %s: %w", filepath.Join(out, "markdown"), err)
		}
		// man
		if err := doc.GenManTree(rootCmd, manHeader, filepath.Join(out, "man")); err != nil {
			return fmt.Errorf("error generating man documentation: %w", err)
		}
		// rst
		if err := doc.GenReSTTree(rootCmd, filepath.Join(out, "rst")); err != nil {
			return fmt.Errorf("error generating rst documentation: %w", err)
		}
		// yaml
		if err := doc.GenYamlTree(rootCmd, filepath.Join(out, "yaml")); err != nil {
			return fmt.Errorf("error generating yaml documentation: %w", err)
		}

		// CLI table
		if err := writeFlagTableToFile(rootCmd, "csv", filepath.Join(out, "csv", "cli-env-var-table.csv"), ""); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		if err := writeFlagTableToFile(rootCmd, "html", filepath.Join(out, "html", "cli-env-var-table.html"), ""); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		if err := writeFlagTableToFile(rootCmd, "", filepath.Join(out, "txt", "cli-env-var-table.txt"), ""); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}
