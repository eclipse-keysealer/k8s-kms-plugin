// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forceColor turns styling on for the duration of a test without needing a terminal.
func forceColor(t *testing.T) {
	t.Helper()
	t.Setenv("CLICOLOR_FORCE", "1")
	// NO_COLOR wins on presence, not on value, so it has to be absent rather than empty.
	unsetEnv(t, "NO_COLOR")
}

// unsetEnv removes a variable for the duration of the test. t.Setenv registers the cleanup that
// restores whatever was there before, so the removal stays scoped to this test.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	require.NoError(t, os.Unsetenv(key))
}

// stripANSI removes every escape sequence, so a test can compare the styled text with what the
// plain renderer would have produced.
func stripANSI(s string) string {
	for _, code := range []string{ansiReset, ansiHeading, ansiBold, ansiDim} {
		s = strings.ReplaceAll(s, code, "")
	}
	return s
}

// testFlagSet mirrors the shape of the real serve flags: a long flag with a type and a default,
// one with a shorthand, and a boolean without a type.
func testFlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.String("p11-lib", "", "Path to the PKCS #11 library of the TPM or HSM.")
	fs.StringP("output", "o", "yaml", "Machine-readable output format.")
	fs.Bool("auto-create", false, "Generate the KEK on the token when it is missing.")
	return fs
}

// ── color gating ──────────────────────────────────────────────────────────────

// TestColorEnabled_NoColor checks that NO_COLOR wins over CLICOLOR_FORCE, as the informal
// no-color.org convention requires: presence of the variable is what counts, not its value.
func TestColorEnabled_NoColor(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("NO_COLOR", "")
	assert.False(t, colorEnabled())
}

func TestColorEnabled_ClicolorForce(t *testing.T) {
	forceColor(t)
	assert.True(t, colorEnabled())

	t.Setenv("CLICOLOR_FORCE", "0")
	assert.False(t, colorEnabled(), "CLICOLOR_FORCE=0 must not force color on")
}

// TestColorEnabled_NotATerminal is the case every piped or redirected invocation hits: the test
// binary's stdout is not a terminal, so nothing may be styled.
func TestColorEnabled_NotATerminal(t *testing.T) {
	unsetEnv(t, "NO_COLOR")
	unsetEnv(t, "CLICOLOR_FORCE")
	assert.False(t, colorEnabled())
}

// TestPaint_PlainWhenColorOff is the property the `docs` command and every redirected --help
// depend on: with color off the helpers are the identity function.
func TestPaint_PlainWhenColorOff(t *testing.T) {
	unsetEnv(t, "CLICOLOR_FORCE")
	t.Setenv("NO_COLOR", "1")

	assert.Equal(t, "Usage:", heading("Usage:"))
	assert.Equal(t, "serve  ", cmdName("serve  "))
	assert.NotContains(t, flagsBlock(testFlagSet()), "\033")
	assert.NotContains(t, exampleBlock("  # a comment\n  k8s-kms-plugin serve --socket /s.sock"), "\033")
}

// ── flag block ────────────────────────────────────────────────────────────────

// TestFlagsBlock_StylingPreservesLayout is the reason the styling is applied to the rendered
// text rather than to the usage strings: pflag computes the column padding from plain text, so
// stripping the escape sequences again has to yield exactly what pflag produced.
func TestFlagsBlock_StylingPreservesLayout(t *testing.T) {
	fs := testFlagSet()
	unsetEnv(t, "CLICOLOR_FORCE")
	t.Setenv("NO_COLOR", "1")
	plain := flagsBlock(fs)

	forceColor(t)
	styled := flagsBlock(fs)

	assert.Contains(t, styled, "\033", "expected the styled output to carry escape sequences")
	assert.Equal(t, plain, stripANSI(styled), "styling must not add or remove a single character")
}

func TestFlagsBlock_StylesNamesAndDefaults(t *testing.T) {
	forceColor(t)
	styled := flagsBlock(testFlagSet())

	assert.Contains(t, styled, ansiBold+"--p11-lib"+ansiReset, "long flag name should be bold")
	assert.Contains(t, styled, ansiBold+"-o, --output"+ansiReset, "shorthand and long name should be bold together")
	assert.Contains(t, styled, ansiDim+`(default "yaml")`+ansiReset, "the default should be dimmed")
}

// TestFlagsBlock_LeavesUsageTextAlone guards against the regex reaching into the description:
// a flag mentioned inside another flag's usage text must not be styled, or the two columns stop
// being visually distinguishable.
func TestFlagsBlock_LeavesUsageTextAlone(t *testing.T) {
	forceColor(t)
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.String("p11-key-id", "", "Mutually exclusive with --p11-key-label.")
	styled := flagsBlock(fs)

	assert.Contains(t, styled, ansiBold+"--p11-key-id"+ansiReset)
	assert.Contains(t, styled, "Mutually exclusive with --p11-key-label.",
		"a flag named inside a usage string must stay plain")
}

// ── examples ──────────────────────────────────────────────────────────────────

func TestExampleBlock_DimsCommentsAndBoldsFlags(t *testing.T) {
	forceColor(t)
	styled := exampleBlock("  # Serve with everything on the command line.\n" +
		"  k8s-kms-plugin serve --socket /run/k8s-kms-plugin.sock -p11")

	assert.Contains(t, styled, ansiDim+"  # Serve with everything on the command line."+ansiReset)
	assert.Contains(t, styled, ansiBold+"--socket"+ansiReset)
	assert.NotContains(t, styled, ansiDim+"  k8s-kms-plugin",
		"command lines must not be dimmed: they are the part worth copying")
}

func TestExampleBlock_PreservesText(t *testing.T) {
	forceColor(t)
	const example = "  # A comment.\n  k8s-kms-plugin serve \\\n    --p11-key-label rsa0\n"
	assert.Equal(t, strings.TrimRight(example, "\n"), stripANSI(exampleBlock(example)))
}

// ── width ─────────────────────────────────────────────────────────────────────

// TestHelpWidth_ColumnsFallback covers the pty-with-no-size case and an explicit
// `COLUMNS=… --help`: the test binary's stdout is not a terminal, so COLUMNS decides.
func TestHelpWidth_ColumnsFallback(t *testing.T) {
	cases := []struct {
		columns string
		want    int
	}{
		{"", 0},               // nothing to go on: do not wrap
		{"0", 0},              // a pty with no size set
		{"not-a-number", 0},   // junk in the environment must not panic or wrap oddly
		{"40", 0},             // too narrow to wrap into two columns
		{"90", 90},            // honored as-is
		{"400", maxHelpWidth}, // an ultrawide terminal is capped
		{"110", maxHelpWidth}, // exactly the cap
		{"59", 0},             // just below the minimum
		{"60", minHelpWidth},  // exactly the minimum
	}
	for _, tc := range cases {
		t.Run("COLUMNS="+tc.columns, func(t *testing.T) {
			t.Setenv("COLUMNS", tc.columns)
			assert.Equal(t, tc.want, helpWidth())
		})
	}
}

// TestFlagsBlock_WrapsToWidth checks that the width actually reaches pflag.
func TestFlagsBlock_WrapsToWidth(t *testing.T) {
	unsetEnv(t, "CLICOLOR_FORCE")
	t.Setenv("NO_COLOR", "1")
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.String("algorithm-family", "aes-gcm",
		"Mechanism the KEK is used with. One of: aes-gcm, aes-cbc, rsa-oaep, ml-kem. Key size and "+
			"ML-KEM parameter set are read from the key on the token, not configured here.")

	t.Setenv("COLUMNS", "")
	unwrapped := flagsBlock(fs)
	t.Setenv("COLUMNS", "80")
	wrapped := flagsBlock(fs)

	assert.Equal(t, 1, strings.Count(unwrapped, "\n")+1, "with no width the usage stays on one line")
	assert.Greater(t, strings.Count(wrapped, "\n")+1, 1, "with a width the usage is wrapped")
	for _, line := range strings.Split(wrapped, "\n") {
		assert.LessOrEqual(t, len(line), 80, "no line may exceed the requested width: %q", line)
	}
}
