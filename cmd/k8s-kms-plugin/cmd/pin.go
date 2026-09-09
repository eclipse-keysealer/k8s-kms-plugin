// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/term"
)

// resolvePinWithFns is the testable core of resolvePin. isTermFn and readPassFn
// can be replaced in tests to avoid needing a real terminal.
func resolvePinWithFns(
	cfg *cmdConfig, key, prompt string,
	isTermFn func(int) bool,
	readPassFn func(int) ([]byte, error),
) (string, error) {
	if cfg.IsSet(key) {
		return cfg.String(key), nil
	}
	fd := int(os.Stdin.Fd())
	if !isTermFn(fd) {
		return "", fmt.Errorf("--%s not provided and stdin is not a terminal — pass the flag or set the corresponding env var", key)
	}
	slog.Debug("HSM PIN not configured, prompting interactively", "key", key)
	fmt.Fprint(os.Stderr, prompt)
	raw, err := readPassFn(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading PIN for --%s: %w", key, err)
	}
	return string(raw), nil
}

// resolvePin returns the PIN from the resolved command configuration when it was
// explicitly configured via any source (CLI flag, env var, config file), including
// an empty string (valid for no-PIN tokens and protected-authentication-path tokens).
// When the key is absent from all sources it falls back to an interactive
// terminal prompt so the PIN is never stored in shell history.
// Returns an error when the key is absent and stdin is not a terminal.
func resolvePin(cfg *cmdConfig, key, prompt string) (string, error) {
	return resolvePinWithFns(cfg, key, prompt, term.IsTerminal, term.ReadPassword)
}
