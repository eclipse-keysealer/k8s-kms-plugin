# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`k8s-kms-plugin` is a gRPC service implementing the [Kubernetes KMS v2 API](https://pkg.go.dev/k8s.io/kms/apis/v2),
backed by a PKCS #11 TPM or HSM. It is part of [Eclipse KeySealer](https://projects.eclipse.org/projects/technology.keysealer)
and consumes `crypto11`, `gose` and `pkcs11-go` from [Eclipse Keypont](https://projects.eclipse.org/projects/technology.keypont).

Read `CHANGELOG.md` first when touching anything cryptographic — the v1.0.0 entry is the authoritative
record of the KMS v1 → v2 migration, the PKCS#11 binding swap, and every deliberate behavioural choice
(including bug fixes with data-at-rest compatibility implications).

### Repository URLs in the documentation

Every link out of `docs/`, and every badge and site link in `README.md`, uses an absolute
`eclipse-keysealer` URL on purpose: a fork that copies these files keeps pointing readers at this
repository rather than silently advertising the fork's own half-built copy.

The one value that is *not* absolute is `website/hugo.toml`'s `baseURL`. It is only a local-dev
default — the Docs workflow computes the real URL from the owner and repository actually running the
build and passes it with `--baseURL`, so the same config publishes correctly from here and from any
fork with nothing to remember. Leave it alone; override it locally with
`hugo --baseURL https://example.github.io/k8s-kms-plugin/` if you need to.

If you develop the site on a fork and want its badges to track your own Pages deployment, change
them in your branch but switch them back before opening a pull request here.

### Release artefact names in the documentation

Any command in the docs that downloads, installs or verifies a release artefact must use the **real
asset names from the latest release on the upstream repository** — currently
[`v1.0.0-rc5`](https://github.com/eclipse-keysealer/k8s-kms-plugin/releases/tag/v1.0.0-rc5). Read them
off the release rather than reconstructing them from `.goreleaser.yml`, and re-check when a newer tag
lands. The asset list is at `https://github.com/eclipse-keysealer/k8s-kms-plugin/releases/expanded_assets/<tag>`
(the release page itself lazy-loads its assets, so fetching that page returns none of them).

Reconstructing names is what goes wrong, because **each packaging format spells a pre-release
differently** and none of them matches the tag:

| Format | `v1.0.0-rc5` becomes | Asset |
|--------|----------------------|-------|
| binary / archive | `1.0.0-rc5` | `k8s-kms-plugin_linux_amd64_1.0.0-rc5`, `.tar.gz`, `.zip` |
| `apk` | `1.0.0_rc5` | `k8s-kms-plugin_1.0.0_rc5_x86_64.apk` |
| `archlinux` | `1.0.0rc5` | `k8s-kms-plugin-1.0.0rc5-1-x86_64.pkg.tar.zst` |
| `deb` / `rpm` | `1.0.0.rc5` | `k8s-kms-plugin_1.0.0.rc5_amd64.deb`, `k8s-kms-plugin-1.0.0.rc5-1.x86_64.rpm` |

Note there is **no `v` prefix** on any artefact — goreleaser's `.Version` strips it — and that the
`deb`/`rpm` `.` is a deliberate substitution for the conventional `~`, which GitHub rejects in an
asset name. Checksums are `k8s-kms-plugin_checksums.txt`, Sigstore bundles are
`<asset>-keyless.bundle.json`, and SLSA provenance is a single `multiple.intoto.jsonl`.
`docs/installation.md` documents the whole mapping; keep it in step.

## Commands

`CGO_ENABLED=1` is required everywhere — the PKCS#11 bindings are cgo. The Makefile sets it for you; set
it yourself if you invoke `go` directly.

```sh
make build              # dev build (native arch) -> dist/k8s-kms-plugin
make test               # unit tests: ./pkg/... ./cmd/... with -race
make lint               # golangci-lint run
make lint-fix           # auto-fix the mechanically-fixable findings
make vet                # same check as CI
make coverage           # -> build/coverage.html
make govulncheck        # reachability-aware vuln scan (same as CI)
make check-doc-links    # relative links and #anchors across the docs
make site-serve         # documentation site at localhost:1313/k8s-kms-plugin/
make site               # documentation site -> website/public/
make check-site         # verify the BUILT site: missing assets, doubled baseURL, dead anchors
make glossary           # regenerate docs/glossary.md from docs/termbase.yaml
make glossary-check     # fail if that regeneration would change anything (CI runs this)
```

CI (`.github/workflows/ci.yml`) runs exactly `go vet ./...`, `go build ./...`, `go test -count=1 ./...`.

### Running a single test

```sh
CGO_ENABLED=1 go test -race -run 'TestValidateHexKeyID' ./pkg/providers/
CGO_ENABLED=1 go test -race -run 'TestValidateHexKeyID/subtest_name' ./pkg/providers/
```

### Integration and e2e tests (need a PKCS#11 module)

```sh
PKCS11_MODULE=/usr/local/lib/softhsm/libsofthsm3.so make test-integration
PKCS11_MODULE=/usr/local/lib/softhsm/libsofthsm3.so make test-e2e   # also runs `make build`
```

Both suites bootstrap their own ephemeral SoftHSM token through the PKCS#11 API itself
(`C_InitToken`/`C_InitPIN` in each suite's `TestMain`) — no `softhsm2-util` needed. `PKCS11_PIN` defaults to `1234`.

> **Trap:** without `PKCS11_MODULE` both suites exit **immediately and successfully**. A green
> `go test ./...` does *not* mean the PKCS#11 paths ran. Always confirm the variable is set.

ML-KEM needs SoftHSMv3 ([`pqctoday-hsm`](https://github.com/pqctoday-org/pqctoday-hsm), see `docs/hsm-guides/softhsm-v3.md`);
AES and RSA paths also work on SoftHSMv2. The e2e suite additionally requires `grpcurl` on `$PATH` — a missing
`grpcurl` **fails** rather than skips.

`tools/create-dev-token/` provisions a *persistent* dev token with one key per algorithm family — handy for
driving `serve` by hand. Development only; it uses well-known PINs and fixed CKA_IDs.

### Fuzzing

`make test` already replays every fuzz target's seed corpus as an ordinary unit test. `make fuzz` additionally
runs the mutation engine (`FUZZTIME=60s` per target by default). A crashing input lands in
`<pkg>/testdata/fuzz/<target>/` — **commit it**, it then becomes a permanent regression seed.

### Regenerating tracked files

These write files that are committed, so re-run them when the underlying source changes:

- `make doc` — after adding or changing any CLI flag or command (regenerates `docs/cli-user-interface/`)
- `make glossary` — after editing `docs/termbase.yaml` (regenerates `docs/glossary.md`; `make
  glossary-check` is the CI guard)
- `make notices` — after changing dependencies (regenerates `NOTICES.md`)

`make doc` is **reproducible**, and CI's "is the CLI reference up to date" check depends on it
entirely: it regenerates and fails on any diff, so anything that varies by clock, machine or
environment turns into a red build with no CLI change behind it. A committed generated file can never
contain its own commit hash, so provenance is CI-only by design (below) — but three other leaks had
to be closed, all in `docs.go`, all render-only masks that leave behaviour untouched:

| Leak | What it did | Mask |
|------|-------------|------|
| `--output-dir` default is a timestamped temp dir | cobra renders defaults into the pages, so the clock landed in two files every run | `DefValue` overridden with a `$TMPDIR/...<timestamp>` placeholder |
| `--provenance` default is `GITHUB_ACTIONS == "true"` | the rendered default read `true` when regenerated in CI and `false` on a laptop, so each made the other look stale | `DefValue` overridden with `auto` |
| cobra's `###### Auto generated by spf13/cobra on <date>` footer | `time.Now()`, so the reference went stale on a *calendar boundary* | `rootCmd.DisableAutoGenTag = true` |

Cobra also mutates the command tree while generating — `GenMarkdownCustom` calls
`InitDefaultHelpFlag` and `InitDefaultHelpCmd` per command — so a second generation in the same
process saw flags and a `help` command the first did not. `initHelpFlags` registers `--help` across
the tree up front and the flag-table walk skips the `help` command, which is cobra's, not this CLI's.

Four tests in `docs_test.go` pin all of it: two runs are byte-identical, the output is identical with
and without `GITHUB_ACTIONS`, no page contains today's date, and every generated page has front
matter. Add to them rather than trusting a manual check — every one of these bugs was invisible on
the day it was introduced.

Build and CI provenance (`build_commit`, `ci_run_url`, …) goes into the generated front matter only
under `--provenance`, which `k8s-kms-plugin docs` enables automatically when `GITHUB_ACTIONS=true`.
The published documentation therefore records the exact workflow run that built it while the
committed tree stays free of volatile data.

### Documentation links

`make check-doc-links` (`scripts/check-doc-links.py`) verifies every relative Markdown link and
`#anchor` in `README.md`, `CHANGELOG.md` and `docs/`. Anchors rot silently, so run it after moving
or renaming anything under `docs/`.

Headings carry **no manual section numbers** — they were removed because a static site generator
derives ordering from the document tree, and the hand-written numbers had already drifted out of
sync with the anchors pointing at them. Do not reintroduce `## 1.`-style numbering; ordering for the
generated CLI pages comes from front-matter `weight`.

Links from `docs/` to files *outside* the docs tree (`scripts/`, `deployments/`, `tools/`, `Makefile`,
Go source, and `README.md` itself) are absolute `github.com/eclipse-keysealer/...` URLs on purpose: a
published site serves only `docs/`, so a relative `../` link would 404 there. Links *between*
documentation pages stay relative. `docs/README.md` states both rules.

`README.md` is a **front door only** (~100 lines): identity, badges, what the plugin is, the algorithm
families, Quick Start, a documentation map, contributing, licence. Don't grow it back; add or extend a
docs page and link it from the map.

The manual lives in `docs/`, as five top-level pages — `overview.md`, `installation.md`,
`cryptographic-schemes.md`, `development.md`, `supply-chain-security.md` — plus `glossary.md` and four
sections, each with a `README.md` index that is mounted as the section landing page:

| Section | Weight | Holds |
|---------|--------|-------|
| `hsm-guides/` | 50 | One page per PKCS #11 provider, plus the support matrix. New devices go here |
| `kubernetes-guides/` | 60 | `KinD` and `k3s`. Neither is presented as the default choice |
| `tools-and-scripts/` | 65 | Documentation for `tools/create-dev-token/`, `scripts/grpcurl/` and `scripts/k8s-kind/`; those directories keep a short README pointing here |
| `cli-user-interface/` | 90 | Hand-written CLI notes plus the generated `markdown/` and `txt/` trees |

There is no `usage.md`: it was dissolved into `cli-user-interface/` and the guides. A new subdirectory
needs its own `_index.md` mount in `website/hugo.toml`.

### Documentation site (Hugo + Hextra)

`website/` holds the site config; **the content stays in `docs/`** and is *mounted* by
`website/hugo.toml`, so `docs/` remains the single source of truth and keeps rendering on GitHub.
`.github/workflows/docs.yml` builds it on PRs and publishes to GitHub Pages from `master`.
`website/README.md` is the reference; the load-bearing details:

- Every docs page needs front matter (`title`, `weight`) and **no `# H1` in the body** — Hextra
  renders the title as the page heading, so a body H1 shows it twice. Adding one is caught by
  building the site, not by any test.
- `markup.goldmark.renderer.unsafe = true` is **required**: Goldmark silently discards raw HTML, and
  the docs use `<details>` for collapsible sections. Losing it drops those blocks with no error.
- Mount `files` patterns need `'! foo'` **with the space**, and exclusions must come **before** the
  catch-all `'**'` — Hugo returns on the first match, so a leading `'**'` disables every exclusion
  after it. Neither mistake warns.
- A `README.md` is not a section index to Hugo; each one is excluded from the bulk mount and
  re-mounted as `_index.md`. A new docs subdirectory with a README needs its own mount.
- The theme is a Hugo Module pinned in `website/go.mod`, deliberately separate from the plugin's
  `go.mod` so it never reaches `go mod tidy`, `NOTICES.md` or `govulncheck`.
- Mermaid and FlexSearch are fetched at build time and re-served with SRI hashes, at versions pinned
  in `hugo.toml` — Hextra's default is `mermaid@latest`. `website/README.md` documents the offline
  build.
- Hugo does **not** need the extended build (Hextra ships precompiled CSS).
- **Which version is this page?** A version chip sits beside the navbar title and a
  "Documentation build" line in the footer gives version, commit, build date and a link to the
  workflow run. Both read `site.Params.docs{Version,Commit,BuildDate,RunURL,RepoURL}`, which are
  passed at build time as `HUGO_PARAMS_DOCS*` — by `SITE_VERSION_ENV` in the Makefile and by the
  Build step in `docs.yml`. Nothing is committed, so nothing can go stale; with no parameters the
  footer prints "unversioned local build" and the chip disappears rather than showing a wrong
  version. The footer fills Hextra's `custom/footer.html` **hook**, but the chip needs
  `_partials/navbar-title.html`, a genuine **override** — Hextra ships an unused
  `custom/navbar-title.html` that nothing in v0.12.3 calls. That makes three overrides to re-check on
  a theme upgrade (see below).
- GitHub-style alerts (`> [!NOTE]`, `TIP`, `IMPORTANT`, `WARNING`, `CAUTION`) render in **both**
  places — natively on GitHub, through Hextra's blockquote hook on the site — so they are preferred
  over a blockquote opening with an emoji, and the emoji/`**Note**:` label comes off when converting.
  Nothing may follow the marker on its line: a custom title is Hugo-only and makes GitHub drop the
  alert entirely. Only those five types exist; anything else is a build warning plus a green box.
- The glossary is a Hugo **data** file, not Markdown: Hextra's `glossary` layout reads
  `site.Data.<lang>.termbase` and ignores the page body. `docs/termbase.yaml` is the source (mounted
  at `data/en/termbase.yaml`, excluded from the content mount) and `docs/glossary.md` is generated
  from it so GitHub shows the terms too. Quote every YAML value — an unquoted `PKCS #11` silently
  truncates at the `#`. Definitions must be Markdown-free: they go straight into `<dd>`. The
  `{{</* term */>}}` shortcode must never appear in `docs/` — GitHub renders it verbatim.
- Code fences carry Hextra attributes — `{filename="…",base_url="…",linenos=table,hl_lines=[…]}` —
  parsed by Hugo with no `markup.goldmark.parser.attribute` setting needed. GitHub keeps only the
  first word of the info string and silently drops the rest, so an attribute is a site-only
  affordance: whatever a highlight is meant to say must also be said in the prose.
  `website/README.md` has the conventions (`filename` only when the block *is* that file,
  `linenos=table` never `inline`, and no path duplicated between a comment and the attribute).

`make doc` follows `GITHUB_ACTIONS` for provenance, so CI's "is the CLI reference up to date" check
must pass `DOC_FLAGS=--provenance=false`; otherwise the commit hash it just stamped in guarantees a
diff.

## Architecture

### Where the plugin sits

The plugin occupies exactly one step of the KMS v2 envelope scheme and **never sees `Secret` data** — only the
32-byte DEK seed that `kube-apiserver` asks it to wrap with the KEK held on the TPM/HSM. `kube-apiserver`
derives the DEK and encrypts the object itself. `docs/cryptographic-schemes.md` is the detailed reference for
every algorithm family; read it before changing wire formats.

Transport is **unix socket only** — the TCP/TLS gRPC option was removed because KMS v2 only supports a local socket.

### Provider layer

`pkg/providers/provider.go` defines the one-method-plus-embedding `Provider` interface
(`k8skmsv2.KeyManagementServiceServer` + a `UnaryInterceptor`). `P11` in `p11.go` is the only implementation;
it must embed `k8skmsv2.UnimplementedKeyManagementServiceServer` (required since KMS v0.34.0 moved to upstream
protobuf-go).

Four algorithm families, selected by `--algorithm-family`: `aes-gcm`, `aes-cbc`, `rsa-oaep`, `ml-kem`. The
sentinel `jose.Alg` constants in `p11.go` deliberately use the same string values as the CLI flag slugs, so
`serve.go` casts directly with no mapping table. Key size / parameter set is **not** a flag — it is derived at
runtime from the HSM key (e.g. AES-GCM reads `CKA_VALUE_LEN`).

**ML-KEM is the structural exception.** The other three families produce a JWE. ML-KEM is a KEM, so it emits two
artifacts and puts them in the two fields KMS v2 already provides: the KEM ciphertext goes into
`EncryptResponse.Annotations` (key `kem-ciphertext.k8s-kms-plugin.keysealer.eclipse.org`) and the AEAD-wrapped
seed goes into `Ciphertext`. This keeps `Ciphertext` at ~60 bytes; a JWE compact serialization would not fit
under the 1 kB limit for ML-KEM-768/1024. `Encrypt` and `decryptWithContext` both branch to `p11_mlkem.go`
before the JWE path. Access the annotation only via `putEncapsulation`/`getEncapsulation`.

### Key rotation

`P11` carries two parallel sets of fields: the active ones (`ctx`, `encryptors`, `decryptors`, `kekCkaID`, …)
and `old*` counterparts used for **decryption only**. `Decrypt` routes on `req.KeyId`: matching the active
KEK ID means normal operation, matching `oldKekCkaID` means rotation, anything else is an error.
`decryptWithContext(req, isRotation)` then selects the whole bundle of context/decryptors/algorithm/labels.
Both KEKs can live on *different* HSMs (the `serve rotation` command takes a full second set of `--old-p11-*` flags).

`mu sync.RWMutex` guards `encryptors`, `decryptors` and `oldDecryptors` — these maps are lazily populated on
first use, so concurrent apiserver requests race without it (this was a real fixed bug; see CHANGELOG).

### Size and length limits

`pkg/providers/kmsv2_limits.go` centralizes every bound, with a naming convention that is load-bearing:
`maxKMSv2<Field>Size` = a limit KMS v2 imposes (bytes on the wire), `max<Attr>Size` = a PKCS#11 limit in bytes,
`max<Attr>HexLen` = a PKCS#11 limit in **hex characters** (twice the raw byte count). The hex/raw distinction is
the one that causes bugs: a `CKA_ID` is raw bytes on the token but travels as a hex string through the CLI and
every KMS v2 `KeyId` field. There is a compile-time assertion tying `maxCkaIDHexLen` to `maxKMSv2KeyIDSize`;
keep it intact. Note the annotations budget is *shared* across all annotations (keys included), not per-annotation.

### CLI: Cobra + koanf

`cmd/k8s-kms-plugin/cmd/` holds the root command plus `serve`, `serve rotation`, `docs`, `version`, and PIN entry.

Configuration priority is **CLI flags > env vars > config file > defaults**. Because koanf resolves the values,
flags are generally registered *without* `Flags().StringVar(&x, …)` — values are read from a per-command
`*Flags` struct (`ServeFlags`, `RotationFlags`, …) with `koanf` tags, not from package variables. The one
exception is `--config`, which has to be known before anything else can be resolved.

`config.go` is essential reading before touching flag plumbing. `resolveCmdConfigE` builds one koanf instance
per command by layering three providers in increasing priority: the config file subsection for the command
path, then the environment variables naming a flag that command declares, then `posflag` (which overrides only
flags the user actually typed, and otherwise fills in defaults). That layering *is* the priority chain — there
is no equivalent of the old `viper-patch-sub.go`, whose `UnmarshalSubMergedE` existed only because
`viper.Sub("section")` dropped the chain for a config subsection.

One workaround survives, because it is cobra's rather than the config library's: `MarkFlagsMutuallyExclusive` /
`MarkFlagsOneRequired` decide from pflag's `Changed` bit, which only the command line sets, so
`syncFlagsFromConfig` writes values that arrived from the environment or the config file back into the cobra
flag set. It skips values a user did not provide and values equal to what the flag already carries, so a config
file restating a default does not mark a flag as set.

A command resolves only the flags it *declares* (`cmd.LocalFlags()`), not the persistent flags it inherits, so
each flag has exactly one env var and one config key — the ones of the command it is declared on. `--log-level`
is a root flag: `K8S_KMS_PLUGIN_LOG_LEVEL` and `k8s-kms-plugin.log-level`, never the `serve` section.

Env var names derive from the **command path**: `serve --p11-pin` → `K8S_KMS_PLUGIN_SERVE_P11_PIN`,
`serve rotation --old-p11-pin` → `K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_PIN`. Config file sections mirror the
same path (`k8s-kms-plugin.serve`, `k8s-kms-plugin.serve.rotation`).

`cmdConfig.IsSet` distinguishes a key the user configured from one that only carries a flag default — `posflag`
seeds every unset key with its default, so key *existence* says nothing. `--p11-pin` depends on that
distinction: an explicitly configured empty PIN is a no-PIN token, an absent one means "prompt".

Each command validates all user input in `PersistentPreRunE` via `sanitizeServeFlags` /
`sanitizeRotationFlags` — that is the single choke point covering flags, env vars *and* config file values.
`--algorithm-family` is additionally validated at parse time through a `pflag.Value` implementation, so both
paths call the same `validateAlgorithmFamily`.

`--p11-key-id` (CKA_ID) and `--p11-key-label` (CKA_LABEL) are mutually exclusive and one is required; same for
the HMAC pair. `NewP11` resolves whichever was omitted by looking up the other on the token. See
`docs/cli-user-interface/cka-id-vs-cka-label.md`.

### Help output

`help_theme.go` owns the terminal help: an ANSI theme plus a copy of cobra's usage template. Two rules keep it
from leaking:

- **Style the rendered text, never the stored strings.** `Short`, `Long`, `Example` and flag usage are read
  verbatim by shell completion, by `docs` (which bypasses the usage template entirely) and by the generated
  flag table, so an escape code stored in one of them would reach all three. `TestFlagsBlock_StylingPreservesLayout`
  is the guard: stripping the escapes must reproduce pflag's output byte for byte.
- **Style after padding.** `rpad` and `FlagUsages` compute their columns from plain text, so colour goes on
  last, where zero-width escapes cannot shift a column.

`colorEnabled` honours `NO_COLOR` (presence, not value), `CLICOLOR_FORCE` and a non-terminal stdout;
`helpWidth` wraps flag usage to the terminal, capped at 110 columns, falling back to `COLUMNS`. The template
deliberately puts the subcommand list *before* the examples so `serve rotation` is visible on the first screen
of `serve --help`, and ends with one footer line about env vars and config keys — which is why individual
usage strings must not grow `Env var: …` suffixes back.

`completion.go` classifies every flag for the shell: `registerFixedCompletion` for closed value sets,
`registerNoFileCompletion` for opaque values (PINs, labels, hex IDs), `markFlagFilename` / `markFlagDirname`
for paths. Without a classification cobra offers file names, which is wrong for most flags here. The mark
helpers pick between the local and persistent flag set themselves — `Command.Flags()` holds only local flags at
registration time, so marking a persistent flag through it fails with "no such flag".

`silenceUsage(cmd)` at the top of a `RunE` stops cobra from answering a *runtime* failure with the whole usage
screen; everything cobra validates before `RunE` (flag parsing, required flags, flag groups) still prints it.
`rootCmd` sets `SilenceErrors` so `Execute` prints the error exactly once, on stderr.

Config file discovery does **not** include `/etc`: it is `--config`, then `K8S_KMS_PLUGIN_CONFIG`, then
`k8s-kms-plugin.conf.yaml` in `$HOME` or `$HOME/.config/k8s-kms-plugin/`. The packaged example therefore has to
be passed explicitly.

### Shipped configuration files

`.goreleaser.yml` installs four files from every apk/deb/rpm/archlinux package, so two files in `configs/` are
user-facing deliverables rather than samples:

| Source | Installed at |
|--------|--------------|
| `configs/config.example.yaml` | `/etc/k8s-kms-plugin/k8s-kms-plugin.config.example.yaml` |
| `configs/systemd/k8s-kms-plugin.service` | `/lib/systemd/system/k8s-kms-plugin.service` |
| `deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml` | `/etc/k8s-kms-plugin/kubernetes/manifest/…example.yaml` |

The two `configs/` files had rotted badly and were repaired; keep them honest, because nothing
else does:

- **An unknown config key is ignored silently.** This was true of Viper and is still true of koanf: a stale key
  does not error — it leaves the setting at its default. `algorithm:` (renamed to `algorithm-family:`) was quietly forcing every reader's KEK to `aes-gcm`.
  Every key in the example must be one the CLI actually accepts; verify by running
  `dist/k8s-kms-plugin --config configs/config.example.yaml serve` and confirming it reaches the PKCS#11
  library load rather than a validation error.
- **`systemd-analyze verify configs/systemd/k8s-kms-plugin.service`** is the check for the unit, and it earns its
  keep: it caught `StartLimitIntervalSec`/`StartLimitBurst` being silently ignored under `[Service]` (they
  belong in `[Unit]`). The unit deliberately does **not** set `PrivateDevices` or `PrivateTmp` — the first hides
  `/dev/tpmrm0`, the second a SoftHSM store staged under `/tmp` — and takes the PIN from an `EnvironmentFile`,
  never `ExecStart`, which `ps` exposes.

### README badges

All eleven badges come from **shields.io** with `style=flat-square` and a logo, in two rows: what the project is,
then whether it is healthy. GitHub's own `actions/workflows/*/badge.svg`, `pkg.go.dev`'s badge and
`api.scorecard.dev`'s badge each render at their own height and font and accept no `style`, so adding one back
breaks the row — use the shields.io equivalents (`github/actions/workflow/status`, a static `pkg.go.dev` badge,
the `ossf-scorecard` endpoint). Workflow badges pin `branch=master` except the tag-triggered `release.yml`.
A badge reading a *value* must read it from this repository: the licence badge used to point at an unrelated
`Ileriayo/markdown-badges`, and so reported someone else's licence.

### Logging

Standard-library `log/slog` (not logrus), with a custom `trace` level below debug in `pkg/logging`. Text output
goes through `tint`; `--log-format=json` swaps in `slog.NewJSONHandler`. `--log-level=quiet` installs
`slog.DiscardHandler`. Use `slog.Log(ctx, logging.LevelTrace, …)` for trace-level lines.

A PKCS#11 authentication error during `serve` startup makes the process **sleep indefinitely** rather than exit,
so a crash-looping container cannot burn through the token's PIN retry counter and erase it.

## Dependencies

`crypto11`, `gose` and `pkcs11-go` are consumed as **published modules** — `go.mod` has no `replace` directives.
To build against unreleased changes, point `go.mod` at a branch with `GOPROXY=direct go get -u <module>@<branch>`
(README §5.2 has the full cross-repo recipe). Restore published versions before opening a PR — branch
pseudo-versions must not reach `master`.
