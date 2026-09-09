// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"log/slog"

	"github.com/spf13/cobra"
)

// Shell completion helpers.
//
// Cobra completes a flag's value with file names unless it is told otherwise, which is wrong
// for most of this CLI: a PIN, a CKA_LABEL or a hex CKA_ID is not a path, and offering the
// current directory for one is noise that hides the fact that nothing can be completed. Every
// flag is therefore classified exactly once, at registration:
//
//   - registerFixedCompletion  — a closed set of values (--algorithm-family, --log-level, …)
//   - registerNoFileCompletion — an opaque value only the operator knows (--p11-pin, --p11-key-id, …)
//   - markFlagFilename         — a file, restricted to the extensions we actually read
//   - markFlagDirname          — a directory
//
// Each helper logs rather than returns: a completion that could not be registered degrades the
// shell experience but must never stop the command from running.

// registerFixedCompletion offers a closed set of values for a flag and suppresses file
// completion, so the shell proposes those values and nothing else.
func registerFixedCompletion(cmd *cobra.Command, flag string, choices ...string) {
	err := cmd.RegisterFlagCompletionFunc(flag, cobra.FixedCompletions(choices, cobra.ShellCompDirectiveNoFileComp))
	if err != nil {
		slog.Error("error registering flag completion function", "cobra_cmd", cmd.Name(), "flag", flag, "error", err)
	}
}

// registerNoFileCompletion suppresses completion for flags whose value cannot be guessed —
// PINs, labels, hex key IDs, slot numbers. Without it the shell falls back to file names.
func registerNoFileCompletion(cmd *cobra.Command, flags ...string) {
	for _, flag := range flags {
		if err := cmd.RegisterFlagCompletionFunc(flag, cobra.NoFileCompletions); err != nil {
			slog.Error("error registering flag completion function", "cobra_cmd", cmd.Name(), "flag", flag, "error", err)
		}
	}
}

// markFlagFilename completes a flag with file names, restricted to the given extensions.
//
// Cobra splits this into MarkFlagFilename and MarkPersistentFlagFilename because Command.Flags()
// holds only the local flags at registration time, so marking a persistent flag through the
// local set fails with "no such flag". Which set a flag lives in is an implementation detail of
// the command that declares it, so the helper picks the right one.
func markFlagFilename(cmd *cobra.Command, flag string, extensions ...string) {
	mark := cmd.MarkFlagFilename
	if cmd.Flags().Lookup(flag) == nil {
		mark = cmd.MarkPersistentFlagFilename
	}
	if err := mark(flag, extensions...); err != nil {
		slog.Error("error marking flag as filename", "cobra_cmd", cmd.Name(), "flag", flag, "error", err)
	}
}

// markFlagDirname completes a flag with directory names only, local or persistent alike.
func markFlagDirname(cmd *cobra.Command, flag string) {
	mark := cmd.MarkFlagDirname
	if cmd.Flags().Lookup(flag) == nil {
		mark = cmd.MarkPersistentFlagDirname
	}
	if err := mark(flag); err != nil {
		slog.Error("error marking flag as dirname", "cobra_cmd", cmd.Name(), "flag", flag, "error", err)
	}
}
