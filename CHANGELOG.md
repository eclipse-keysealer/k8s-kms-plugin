# Changelog

All notable changes to k8s-kms-plugin are documented in this file. For the full commit-level
history see [GitHub Releases](https://github.com/eclipse-keysealer/k8s-kms-plugin/releases).

## Unreleased

### Changed

- **Configuration resolution moved from [Viper](https://github.com/spf13/viper) to
  [koanf](https://github.com/knadh/koanf)**, keeping Cobra for the commands and flags. The user
  contract is unchanged: the same flags, the same `K8S_KMS_PLUGIN_*` environment variables, the
  same config file sections, resolved with the same priority — CLI flags > environment variables >
  configuration file > defaults. Configuration files keep mirroring the command hierarchy
  (`k8s-kms-plugin.serve.rotation.old-p11-pin`), as do the environment variables
  (`K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_PIN`). YAML, TOML and JSON are still accepted, and the
  config file is still discovered from `--config`, then `K8S_KMS_PLUGIN_CONFIG`, then
  `k8s-kms-plugin.conf.{yaml,yml,json,toml}` in `$HOME` or `$HOME/.config/k8s-kms-plugin/`.
- `viper-patch-sub.go` is gone, and with it the workaround it existed for: `viper.Sub("section")`
  dropped the flag/env/default priority chain, so `UnmarshalSubMergedE` had to merge a config
  subsection back into the global Viper config layer before unmarshalling it. koanf layers the
  providers explicitly — config file section, then environment, then flags — so a subsection is
  just another layer and the ordering is stated in one place. The new
  [`config.go`](cmd/k8s-kms-plugin/cmd/config.go) replaces it.
- The one workaround that survives is cobra's, not Viper's: `MarkFlagsOneRequired` and
  `MarkFlagsMutuallyExclusive` decide from whether a flag was typed on the command line, so a value
  arriving through an environment variable or the config file is still written back into the cobra
  flag set. It is now applied only to values a user actually provided, so a config file restating a
  default (`debug: false`) no longer marks that flag as set — which previously could collide with
  the flag it is mutually exclusive with.
- `--debug` now selects the debug level from its resolved *value* rather than from the fact that it
  was passed, so `--debug=false` no longer forces debug logging.
- The per-command flag structs and their validators were renamed accordingly: `ViperFlagsServe` →
  `ServeFlags`, `ViperFlagsRotation` → `RotationFlags`, `ViperFlagsRoot`/`ViperFlagsVersion`/
  `ViperFlagsDocs` likewise, and `sanitizeViperFlagsServe` / `sanitizeViperFlagsRotation` →
  `sanitizeServeFlags` / `sanitizeRotationFlags`. Their struct tags moved from `mapstructure` to
  `koanf`. These are internal names; no CLI, environment variable or config file key changed.
- Dependencies: `github.com/spf13/viper` and `github.com/mitchellh/go-homedir` (archived) are out —
  the home directory now comes from `os.UserHomeDir`. `github.com/knadh/koanf/v2` and its yaml,
  toml, json, env, posflag and confmap modules are in.

## v1.0.0 — first stable release: KMS v2, PKCS#11 v3.2 and ML-KEM

`k8s-kms-plugin` has been on `0.x` since its start, with no stability contract. v1.0.0 is its first
stable release: it moves from the deprecated Kubernetes KMS v1 API to KMS v2 (with key rotation),
replaces its PKCS#11 binding, and adds post-quantum ML-KEM support. It is now part of
[Eclipse KeySealer](https://projects.eclipse.org/projects/technology.keysealer), consuming
[crypto11](https://github.com/eclipse-keypont/crypto11), [gose](https://github.com/eclipse-keypont/gose)
and [pkcs11-go](https://github.com/eclipse-keypont/pkcs11-go) from the
[Eclipse Keypont](https://projects.eclipse.org/projects/technology.keypont) project.

### Breaking changes

- **Dropped Kubernetes KMS v1 support.** Only the [KMS v2 API](https://pkg.go.dev/k8s.io/kms/apis/v2)
  is served now, since KMS v1 is deprecated as of Kubernetes v1.28 and disabled by default since
  v1.29. `serve rotation` adds key-rotation operations on top of KMS v2.
- **PKCS#11 binding replaced**: `miekg/pkcs11` is out, [`eclipse-keypont/pkcs11-go`](https://pkg.go.dev/github.com/eclipse-keypont/pkcs11-go)
  is in (via `crypto11/v2`), bringing PKCS#11 v3.2 support.
- **`--algorithm` renamed to `--algorithm-family`** (and `--old-algorithm` to
  `--old-algorithm-family`, now explicitly required for rotation). `Algorithm` became a typed
  `AlgorithmFamily` string with `AlgAESGCM` / `AlgAESCBC` / `AlgRSAOAEP` / `AlgMLKEM` constants,
  validated at parse time via `pflag.Value` instead of an ad hoc `algFromString`.
- **gRPC transport is unix-socket only.** The TCP/TLS gRPC server option was removed, since
  Kubernetes KMS v2 only supports gRPC over a local unix socket.
- **PKCS#11 environment variables standardized** to `PKCS11_MODULE` / `PKCS11_PIN` / `PKCS11_TOKEN`.
- **Istio integration removed** (proxy/mesh-specific code, docs and tests) to keep the plugin
  focused on its core KMS v2 / PKCS#11 responsibility.
- Dependencies moved off the `ThalesGroup` fork paths: `github.com/ThalesGroup/crypto11` →
  `github.com/eclipse-keypont/crypto11/v2`, `github.com/ThalesGroup/gose` →
  `github.com/eclipse-keypont/gose`, both now consumed as published releases (no `replace`
  directives).
- Repository and Go module path moved from `github.com/ThalesGroup/k8s-kms-plugin` to
  `github.com/eclipse-keysealer/k8s-kms-plugin`.
- **Release artifacts are signed with Sigstore bundles instead of detached `.sig` / `.pem` files.**
  Each binary, package, SBOM and `checksums.txt` now ships a single `<artifact>-keyless.bundle.json`
  holding the signature, the Fulcio certificate and the Rekor inclusion proof together. Verification
  changes from `cosign verify-blob --certificate … --signature …` to
  `cosign verify-blob --bundle <artifact>-keyless.bundle.json …`, and requires **cosign v3 or later**.
  cosign v3 removed the `--output-signature` / `--output-certificate` flags that produced the old
  pair, so this is the only supported output format going forward.

### Added

- **Post-quantum ML-KEM support** (`--algorithm-family ml-kem`): ML-KEM-512/768/1024 hybrid
  encryption (CRYSTALS-Kyber / FIPS 203), with the KEM ciphertext carried in KMS v2 annotations
  instead of inside the JWE.
- **RSA-OAEP support**, including RSA-3072 and RSA-4096 key sizes.
- Interactive PKCS#11 PIN entry (prompted, instead of only via flag/env var).
- `create-dev-token`, a standalone CLI tool to provision a dev PKCS#11 token pre-populated with
  keys for every supported algorithm family (AES-GCM, AES-CBC+HMAC, RSA-OAEP, ML-KEM), with a
  `--socket` flag and its own `--version` output; built in CI alongside the main plugin.
- End-to-end `serve rotation` tests covering all 16 old/new algorithm-family combinations.
- A Cryptography Bill of Materials-style Notices generator (`go-licenses`-based `NOTICES.md`).
- CI workflows for build, lint, secret scanning (Gitleaks) and OpenSSF Scorecard; `make lint-fix`
  Makefile target.

### Fixed

- **RSA-OAEP JWEs are now portable** (via gose `v1.0.0-rc2`). RFC 7518 §4.3 defines `RSA-OAEP` as
  RSAES-OAEP with SHA-1 and `RSA-OAEP-256` as the SHA-256 variant; the plugin advertised
  `RSA-OAEP` while wrapping the CEK with SHA-256, so a conformant recipient derived SHA-1 and
  failed to unwrap. The protected header now reads `RSA-OAEP-256`. Objects encrypted by earlier
  versions remain readable — the plugin passes an explicit SHA-256 to `Decrypt` rather than
  deriving the digest from the header — so **no re-encryption of data at rest is required**.
- **Concurrent map access / race condition** in the P11 provider under concurrent encrypt/decrypt
  requests.
- **AES-CBC+HMAC key type bug**: `CKK_AES` does not allow `CKM_SHA256_HMAC` — the HMAC key must be
  `CKK_GENERIC_SECRET` with `CKA_SIGN=true`. Fixed in both the provider and the integration tests.
- Key-rotation label bug: the `kid` parameter was not threaded through `makeAeadKey`, so callers
  could not select between the active key label and the old key label during rotation.
- Hardened user input validation/sanitization on CLI flags, config file values and environment
  variables (`sanitizeViperFlagsServe` / `sanitizeViperFlagsRotation`, called from each command's
  `PersistentPreRunE`).

### Changed

- CLI flag resolution now goes through Viper with an explicit priority: CLI flags > environment
  variables > configuration file > defaults.
- Logging switched from `logrus` to the standard library `log/slog`, with a custom "trace" level
  for verbose diagnostics.
- Go toolchain updated progressively from 1.23.6 to 1.26.4, alongside each `gose`/`crypto11`
  dependency bump.
- Full `golangci-lint` cleanup across the codebase (errcheck, gosec, revive var-naming/copyloopvar,
  package-comment and stutter findings).
- Obsolete build tooling removed and the Makefile modernised (`prototool` dropped, deprecated Ko
  repository list removed).

### CI/CD & supply chain

- Release pipeline restructured; all third-party GitHub Actions updated, Trivy and Syft bumped.
- Blob signing migrated to the Sigstore bundle format (see Breaking changes): the `signs` blocks in
  `.goreleaser.yml` now pass `--bundle` to `cosign sign-blob`, which is required by cosign v3 and is
  what `sigstore/cosign-installer` now provides.
- Reference to the project's Eclipse Foundation donation added to project docs.

## Pre-1.0 (`ThalesGroup` era, v0.x)

Originally maintained at `github.com/ThalesGroup/k8s-kms-plugin`, serving the (now removed) KMS v1
API on `miekg/pkcs11`. Notable tagged milestones:

- **v0.5.0** (2020-07-18): early KMS v1 plugin.
- **v0.6.0** (2024-02-14) / **v0.6.0-alpha**, **v0.6.1-alpha** (2025-09-30): pre-KMS v2 iterations.
- **0.7.0** (2025-11-21): last release before the KMS v2 / PKCS#11 v3.2 / ML-KEM work in this file.
- Assorted `v0.7.0-test-*` / `v0.8.0-test-*` / `v0.9.0-test-ci-1` tags: CI/build-pipeline
  validation tags, not functional releases.

Full commit history for this era is available via `git log 0.7.0` or the
[GitHub Releases](https://github.com/eclipse-keysealer/k8s-kms-plugin/releases) page.
