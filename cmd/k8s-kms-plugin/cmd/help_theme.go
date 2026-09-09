// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

// ANSI styling used only for the interactive --help/-h terminal output.
//
// Styling is applied to the *rendered* help text, never to the Short, Long, Example or flag
// usage strings themselves, because those are read verbatim by three other consumers: shell
// completion, the `docs` command (which renders Long/Short/flags directly, bypassing the usage
// template entirely — see doc.GenMarkdownTree) and the generated flag/env-var table. Anything
// stored with escape codes in it would leak into all three.
//
// The same rule protects column alignment: cobra's `rpad` and pflag's FlagUsages compute their
// padding from plain text, so every colour is applied *after* padding, where the zero-width
// escape codes cannot shift a column.
const (
	ansiReset   = "\033[0m"
	ansiHeading = "\033[1;36m" // bold cyan — section headers
	ansiBold    = "\033[1m"    // command names, flag names
	ansiDim     = "\033[2m"    // defaults, example comments, the footer
)

const (
	// maxHelpWidth caps how wide flag usage text is wrapped. Beyond roughly this many columns a
	// line stops being comfortable to read, so a very wide terminal gains nothing from filling it.
	maxHelpWidth = 110
	// minHelpWidth is the width below which wrapping is abandoned: the flag names and their
	// padding already take about 40 columns, so wrapping the usage text into what is left would
	// produce a column two or three words wide.
	minHelpWidth = 60
)

// flagLineRe matches the leading flag names of one line of pflag's FlagUsages output:
// optional indent, an optional "-x, " shorthand, then the "--long-name". Continuation lines of
// a wrapped usage string do not match, which is what keeps them plain.
var flagLineRe = regexp.MustCompile(`^(\s*)(-[a-zA-Z], )?(--[a-zA-Z0-9][a-zA-Z0-9._-]*)`)

// defaultRe matches the "(default …)" suffix pflag appends to a flag's usage text.
var defaultRe = regexp.MustCompile(`\(default .+\)$`)

// exampleFlagRe matches a long or short flag inside an example command line.
var exampleFlagRe = regexp.MustCompile(`(^|\s)(--?[a-zA-Z0-9][a-zA-Z0-9._-]*)`)

// colorEnabled reports whether ANSI styling should be applied. It is re-evaluated on every call
// (cheap) rather than cached, so redirecting stdout or toggling NO_COLOR between invocations is
// honored, and colors are automatically off for any non-interactive output (`--help > file`,
// CI logs, etc.).
func colorEnabled() bool {
	if _, noColor := os.LookupEnv("NO_COLOR"); noColor {
		return false
	}
	if v, forced := os.LookupEnv("CLICOLOR_FORCE"); forced && v != "0" {
		return true
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// paint wraps s in an ANSI sequence, or returns it untouched when color is off.
func paint(style, s string) string {
	if s == "" || !colorEnabled() {
		return s
	}
	return style + s + ansiReset
}

// helpWidth returns the width to wrap flag usage text to: the terminal width, capped at
// maxHelpWidth. An explicit COLUMNS is honored when the terminal size cannot be read, which
// covers a pty with no size set and `COLUMNS=100 k8s-kms-plugin --help | less`.
//
// It returns 0 — pflag's "do not wrap" — when there is no width to be had, or when it is too
// narrow to wrap without mangling the two-column layout.
func helpWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 {
		width, _ = strconv.Atoi(os.Getenv("COLUMNS"))
	}
	if width < minHelpWidth {
		return 0
	}
	return min(width, maxHelpWidth)
}

// heading styles a help/usage section header such as "Usage:" or "Main KMS Commands:".
func heading(s string) string { return paint(ansiHeading, s) }

// cmdName styles a command name in the command list. It is applied to the already-padded name,
// so the trailing padding is inside the escape sequence and the column stays put.
func cmdName(s string) string { return paint(ansiBold, s) }

// flagsBlock renders a flag set the way cobra's template would, wrapped to the terminal width,
// then styles the flag names and the "(default …)" suffixes.
func flagsBlock(fs *pflag.FlagSet) string {
	usages := strings.TrimRight(fs.FlagUsagesWrapped(helpWidth()), " \t\n")
	if !colorEnabled() {
		return usages
	}

	lines := strings.Split(usages, "\n")
	for i, line := range lines {
		if m := flagLineRe.FindStringSubmatch(line); m != nil {
			styled := m[1] + paint(ansiBold, m[2]+m[3])
			line = styled + line[len(m[0]):]
		}
		lines[i] = defaultRe.ReplaceAllStringFunc(line, func(d string) string {
			return paint(ansiDim, d)
		})
	}
	return strings.Join(lines, "\n")
}

// exampleBlock styles the Examples section: shell comment lines are dimmed so the commands
// stand out, and the flags inside those commands are bolded the same way as in the flag list.
func exampleBlock(s string) string {
	if !colorEnabled() {
		return strings.TrimRight(s, " \t\n")
	}

	lines := strings.Split(strings.TrimRight(s, " \t\n"), "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			lines[i] = paint(ansiDim, line)
			continue
		}
		lines[i] = exampleFlagRe.ReplaceAllString(line, "${1}"+ansiBold+"${2}"+ansiReset)
	}
	return strings.Join(lines, "\n")
}

// configFooter is the one-line reminder, printed under the flags, that every flag has an
// environment variable and a config file key. It replaces the "Env var: …" suffixes that used
// to be repeated inside a handful of usage strings (and were missing, or wrong, on the rest).
func configFooter() string {
	return paint(ansiDim, `Every flag can also be set by an environment variable or a configuration file, named after
the command path (e.g. "serve --p11-pin" is K8S_KMS_PLUGIN_SERVE_P11_PIN, or p11-pin under
k8s-kms-plugin.serve). Priority: flag > environment variable > configuration file > default.`)
}

// coloredUsageTemplate mirrors cobra's defaultUsageTemplate, with every section header wrapped
// in {{heading}}, and one reordering: the subcommand list comes *before* the examples, so
// "serve rotation" is visible on the first screen of `serve --help` rather than below a page of
// example command lines.
//
// The flag blocks are rendered through {{flagsBlock}} (which wraps them to the
// terminal) and the examples through {{exampleBlock}}. Only used for terminal --help/-h output.
const coloredUsageTemplate = `{{heading "Usage:"}}{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

{{heading "Aliases:"}}
  {{.NameAndAliases}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

{{heading "Available Commands:"}}{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{cmdName (rpad .Name .NamePadding)}} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{heading .Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{cmdName (rpad .Name .NamePadding)}} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

{{heading "Additional Commands:"}}{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{cmdName (rpad .Name .NamePadding)}} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasExample}}

{{heading "Examples:"}}
{{exampleBlock .Example}}{{end}}{{if .HasAvailableLocalFlags}}

{{heading "Flags:"}}
{{flagsBlock .LocalFlags}}{{end}}{{if .HasAvailableInheritedFlags}}

{{heading "Global Flags:"}}
{{flagsBlock .InheritedFlags}}{{end}}{{if .HasHelpSubCommands}}

{{heading "Additional help topics:"}}{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{cmdName (rpad .CommandPath .CommandPathPadding)}} {{.Short}}{{end}}{{end}}{{end}}

{{configFooter}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

func init() {
	cobra.AddTemplateFunc("heading", heading)
	cobra.AddTemplateFunc("cmdName", cmdName)
	cobra.AddTemplateFunc("flagsBlock", flagsBlock)
	cobra.AddTemplateFunc("exampleBlock", exampleBlock)
	cobra.AddTemplateFunc("configFooter", configFooter)
	// Setting it on rootCmd applies to every subcommand: cobra's
	// Command.UsageTemplate() walks up to the nearest ancestor that has one set.
	rootCmd.SetUsageTemplate(coloredUsageTemplate)
}
