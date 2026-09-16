---
title: "Installation"
weight: 20
---

This page covers getting the `k8s-kms-plugin` binary onto a machine and checking that what you got
is what the project published. Running it, and wiring a cluster to it, are covered elsewhere:

| Next step | Where |
|-----------|-------|
| Set up a PKCS #11 provider and start `serve` against it | [HSM & TPM guides](./hsm-guides/README.md) |
| Point a Kubernetes cluster at a running plugin | [`KinD`](./kubernetes-guides/kind-kubernetes.md) or [`k3s`](./kubernetes-guides/k3s-kubernetes.md) |
| Flags, environment variables and config file keys | [Usage & User Guides](./cli-user-interface/README.md) |

## Requirements

`k8s-kms-plugin` targets Kubernetes **v1.29 or newer** and implements the
[KMS v2 API](https://pkg.go.dev/k8s.io/kms/apis/v2). See the upstream
[KMS provider documentation](https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/).

> [!IMPORTANT]
> `k8s-kms-plugin` **does not support KMS v1**, which is deprecated as of Kubernetes v1.28 and
> disabled by default since v1.29.

You also need a supported PKCS #11 provider holding at least one AES, RSA or ML-KEM key — see the
[HSM & TPM guides](./hsm-guides/README.md), starting with
[SoftHSMv3](./hsm-guides/softhsm-v3.md) if you have no hardware to hand.

## Install `k8s-kms-plugin` From Official Packages

As of now, `k8s-kms-plugin`'s Github Action Build Recipe supports building `apk`, `deb`, `rpm` and `archlinux` for
Linux x86 platform. Check the different package artefacts from the [releases](https://github.com/eclipse-keysealer/k8s-kms-plugin/releases)
tab.

> [!NOTE]
> The packages are not available on official repos yet.
> And signature remains to be added in the CICD build recipe.
> Therefore, this doc only shows local installation of the package.

### What a package installs

Every format installs the same four things:

| Path | What it is |
|------|------------|
| `/usr/bin/k8s-kms-plugin` | The binary |
| `/etc/k8s-kms-plugin/k8s-kms-plugin.config.example.yaml` | Annotated example of every configuration key, mirroring [`configs/config.example.yaml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/configs/config.example.yaml). Not read automatically — pass it with `--config`, or copy it to `$HOME/.config/k8s-kms-plugin/k8s-kms-plugin.conf.yaml` |
| `/etc/k8s-kms-plugin/kubernetes/manifest/encryption-conf-kmsv2-unix-socket.example.yaml` | The `EncryptionConfiguration` for `kube-apiserver` — see the [Kubernetes guides](./kubernetes-guides/README.md) |
| `/lib/systemd/system/k8s-kms-plugin.service` | A unit file for running `serve` as a system service |

The unit will not start as installed: a token label, a key and a PKCS #11 library path have no
sensible defaults, so it ships with placeholders. Replace them with `systemctl edit
k8s-kms-plugin`, put the PIN in a root-only `EnvironmentFile` rather than on the command line where
`ps` would show it, then `systemctl enable --now k8s-kms-plugin`. The header of
[`configs/systemd/k8s-kms-plugin.service`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/configs/systemd/k8s-kms-plugin.service)
walks through it, including which sandboxing directives must stay off for an HSM device node to
remain visible.

### How a release names its files

Every command below uses the real asset names from
[`v1.0.0-rc5`](https://github.com/eclipse-keysealer/k8s-kms-plugin/releases/tag/v1.0.0-rc5), the
latest release. Substitute your own tag — but read the version column first, because **each packaging
format spells a pre-release differently**, and the difference is not cosmetic: it is what the file is
actually called.

| Format | `1.0.0-rc5` becomes | Example asset (`x86_64` / `amd64`) |
|--------|---------------------|------------------------------------|
| binary and archives | `1.0.0-rc5` | `k8s-kms-plugin_linux_amd64_1.0.0-rc5` plus `.tar.gz` / `.zip` |
| `apk` | `1.0.0_rc5` | `k8s-kms-plugin_1.0.0_rc5_x86_64.apk` |
| `archlinux` | `1.0.0rc5` | `k8s-kms-plugin-1.0.0rc5-1-x86_64.pkg.tar.zst` |
| `deb` | `1.0.0.rc5` | `k8s-kms-plugin_1.0.0.rc5_amd64.deb` |
| `rpm` | `1.0.0.rc5` | `k8s-kms-plugin-1.0.0.rc5-1.x86_64.rpm` |

> [!NOTE]
> `deb` and `rpm` conventionally write a pre-release with a tilde (`1.0.0~rc5`), which sorts it below
> the final release. GitHub does not allow `~` in an asset name and silently rewrites it, so
> [`.goreleaser.yml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/.goreleaser.yml)
> replaces it with `.` deliberately — otherwise the published filename would no longer match the name
> recorded in `k8s-kms-plugin_checksums.txt` and in the SLSA provenance. The version *inside* the
> package is still `1.0.0~rc5`.

`arm64`/`aarch64` and `riscv64` builds are published for every format except `archlinux`, which ships
`x86_64` and `aarch64` only.

### `apk` on Wolfi OS packages

For now, `k8s-kms-plugin` does not support installation on Alpine Linux. Indeed, for now we are not building the `k8s-kms-plugin` package with the musl libc. We only support the glibc.

But `k8s-kms-plugin` supports installation on Wolfi OS as it uses the glibc.

Until the packages are available on official repos and signed, you can install the package from the following command:

Example on Wolfi OS:

```bash
apk add --allow-untrusted ./k8s-kms-plugin_1.0.0_rc5_x86_64.apk
```

### `archlinux` packages

See https://wiki.archlinux.org/title/Pacman#Additional_commands

Command should look like this:

```bash
pacman -U ./k8s-kms-plugin-1.0.0rc5-1-x86_64.pkg.tar.zst
```

### `deb` debian packages

```bash
sudo dpkg -i ./k8s-kms-plugin_1.0.0.rc5_amd64.deb
```

### `rpm` RPM packages

```bash
dnf install ./k8s-kms-plugin-1.0.0.rc5-1.x86_64.rpm
```

### Snapshot builds are a different story

A snapshot build — produced from an untagged commit, and **not** something the releases page publishes
— is named after the commit (`k8s-kms-plugin_SNAPSHOT-3239cd9_amd64.deb`), and that is not a version
either `dpkg` or `pacman` accepts.

<details>
<summary><code>dpkg</code> rejects it: <em>version number does not start with digit</em></summary>

```bash
$ sudo dpkg -i ./k8s-kms-plugin_SNAPSHOT-3239cd9_amd64.deb
```
```
dpkg: error processing archive ./k8s-kms-plugin_SNAPSHOT-3239cd9_amd64.deb (--install):
 parsing file '/var/lib/dpkg/tmp.ci/control' near line 2 package 'k8s-kms-plugin':
 'Version' field value 'SNAPSHOT-3239cd9': version number does not start with digit
Errors were encountered while processing:
 ./k8s-kms-plugin_SNAPSHOT-3239cd9_amd64.deb
```

`--force-all` downgrades that error to a warning:

```bash
dpkg --force-all -i ./k8s-kms-plugin_SNAPSHOT-3239cd9_amd64.deb
```
```
dpkg: warning: parsing file '/var/lib/dpkg/tmp.ci/control' near line 2 package 'k8s-kms-plugin':
 'Version' field value 'SNAPSHOT-3239cd9': version number does not start with digit
Selecting previously unselected package k8s-kms-plugin.
(Reading database ... 6089 files and directories currently installed.)
Preparing to unpack .../k8s-kms-plugin_SNAPSHOT-3239cd9_amd64.deb ...
Unpacking k8s-kms-plugin (SNAPSHOT-3239cd9) ...
Setting up k8s-kms-plugin (SNAPSHOT-3239cd9) ...
```
</details>

<details>
<summary><code>pacman</code> rejects it: <em>package version contains invalid characters</em></summary>

```
error: invalid metadata for package k8s-kms-plugin-SNAPSHOT-3239cd9-1 (package version contains invalid characters)
error: './k8s-kms-plugin-SNAPSHOT-3239cd9-1-x86_64.pkg.tar.zst': invalid or corrupted package
```

There is no `--force` for this one. Use a tagged release.
</details>

### Binary

Move the `k8s-kms-plugin` binary to a relevant location under your `$PATH`, for example `/usr/local/bin/k8s-kms-plugin`.

## Verify what you downloaded

Every release artefact ships a Sigstore bundle, and both the binaries and the container image carry
SLSA3 provenance. Verifying is two commands — one for the artefact, one for its provenance.

Install [`cosign`](https://github.com/sigstore/cosign) **v3 or later** and
[`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier):

```bash
go install github.com/sigstore/cosign/v3/cmd/cosign@latest
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.7.1
```

Download the artefact together with its `-keyless.bundle.json`, then check the signature:

```bash
TAG=v1.0.0-rc5
VERSION=${TAG#v}                              # goreleaser strips the leading "v"
FILE=k8s-kms-plugin_linux_amd64_${VERSION}

cosign verify-blob \
  --bundle "${FILE}-keyless.bundle.json" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity "https://github.com/eclipse-keysealer/k8s-kms-plugin/.github/workflows/release.yml@refs/tags/${TAG}" \
  "${FILE}"
```

And the provenance:

```bash
slsa-verifier verify-artifact "${FILE}" \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/eclipse-keysealer/k8s-kms-plugin \
  --source-tag "${TAG}"
```

> [!CAUTION]
> Always pin the signing identity with `--certificate-identity` (or `--certificate-identity-regexp`)
> and the source with `--source-uri`. A signature verified without them only proves *somebody*
> signed the file — which is not the question you are asking.

**That is the short version.** For what a release actually produces, how keyless signing works, SBOM
and VEX attestations, verifying the container image and its provenance by digest, and the full
identity strings, see **[Supply Chain Security](./supply-chain-security.md)** — that page is the
reference for signing and provenance.

## Install `k8s-kms-plugin` with `go install`

If you already have a Go toolchain, `go install` fetches, builds and installs the binary in one command — no clone, no
`make`, no release artefact to download:

```bash
go install github.com/eclipse-keysealer/k8s-kms-plugin/cmd/k8s-kms-plugin@v1.0.0-rc3
```

The binary is installed into `$(go env GOBIN)`, or `$(go env GOPATH)/bin` when `GOBIN` is unset. Make sure that directory
is on your `$PATH`:

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
k8s-kms-plugin serve --help
```

Requirements are the same as for a `make` build: a Go toolchain matching the `go` directive of the tagged
[`go.mod`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/go.mod), and a working **`CGO`** setup (a C compiler and the glibc/musl headers of your target), because the
PKCS#11 bindings are cgo-based. The resulting binary is dynamically linked against your system libc:

```bash
$ ldd $(go env GOPATH)/bin/k8s-kms-plugin
        linux-vdso.so.1
        libresolv.so.2 => /usr/lib/libresolv.so.2
        libc.so.6 => /usr/lib/libc.so.6
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2
```

As with every other build method, do not install on musl libc if you intend to run the plugin on glibc (and vice versa).

### Always Pin an Explicit Version

> [!WARNING]
> **Do not use `@latest` for now.** Go's `@latest` deliberately skips pre-releases, and the newest non-pre-release tag
> of this repository is still `v0.6.0` (February 2024). So `@latest` silently installs a two-year-old build:

```bash
$ curl -s https://proxy.golang.org/github.com/eclipse-keysealer/k8s-kms-plugin/@latest
{"Version":"v0.6.0","Time":"2024-02-14T09:32:16Z", ...}
```

Until `v1.0.0` is tagged, always pin the exact version you want. Available versions can be listed with:

```bash
go list -m -versions github.com/eclipse-keysealer/k8s-kms-plugin
```

### Limitation: `version` Reports an Empty Snapshot

`go install` cannot pass the `LDFLAGS` that the [`Makefile`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/Makefile) uses to stamp build metadata into
[`pkg/version`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/pkg/version/version.go). A `go install`-ed binary therefore reports an empty snapshot version:

```bash
$ k8s-kms-plugin version
k8s-kms-plugin: (snapshot)
```

This is cosmetic — the plugin itself is fully functional. The real version is still recorded in the Go build info, so
use `go version -m` to identify a binary:

```bash
$ go version -m $(go env GOPATH)/bin/k8s-kms-plugin | head -3
/home/user/go/bin/k8s-kms-plugin: go1.27.1
        path    github.com/eclipse-keysealer/k8s-kms-plugin/cmd/k8s-kms-plugin
        mod     github.com/eclipse-keysealer/k8s-kms-plugin      v1.0.0-rc3
```

If you need `k8s-kms-plugin version` to report the real version, build with `make` instead (see
[Build `k8s-kms-plugin` locally from Source with `make`](#build-k8s-kms-plugin-locally-from-source-with-make)) or download an official release artefact.

> [!TIP]
> **`goenv` users**: if `go install` fails with `compile: version "goX.Y.Z" does not match go tool version "goX.Y.W"`,
> your `GOROOT` environment variable is pinned to a different Go version than the `go` binary found on your `$PATH`.
> Unset it (`env -u GOROOT go install ...`) and let the `go` command locate its own `GOROOT`.

## Build `k8s-kms-plugin` locally from Source with `make`

### Build Requirements

You should have `make`, `git` and `go` installed. Review the content of the [`Makefile`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/Makefile) file for more details.

The required Go version is the one declared in [`go.mod`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/go.mod) (currently **Go 1.27**). The CI workflows resolve it
with `go-version-file: go.mod`, so `go.mod` is the single source of truth — do not rely on the versions pinned in this
document.

[`NOTICES.md`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/NOTICES.md) lists all third-party dependency licenses and is auto-generated via `make notices` (requires [`go-licenses`](https://github.com/google/go-licenses)).

**`CGO`** is required to build the plugin (`CGO_ENABLED=1` is set by the `Makefile`): **make sure you are using the right
C Library** (glibc or musl) for your target environment. Do not build on musl libc if you intend to use the plugin on a
non-musl environment (glibc).

The build was tested with the following tool versions:

| Tool | Version tested                    | Check with       |
|------|-----------------------------------|------------------|
| Go   | `go1.27.1 linux/amd64`            | `go version`     |
| Make | `GNU Make 4.4.1`                  | `make --version` |
| Git  | `git version 2.55.0`              | `git version`    |
| GCC  | native `gcc` (for `CGO_ENABLED=1`) | `gcc --version`  |

Building for a **non-native architecture** additionally requires the matching cross-compiler toolchain. The `Makefile`
expects these compiler names:

| Target                | `CC` used                | Debian/Ubuntu packages                                       |
|-----------------------|--------------------------|--------------------------------------------------------------|
| `linux/amd64`         | `gcc` (native)           | `build-essential`                                            |
| `linux/arm64`         | `aarch64-linux-gnu-gcc`  | `gcc-aarch64-linux-gnu`, `g++-aarch64-linux-gnu`, `libc6-dev-arm64-cross`   |
| `linux/riscv64`       | `riscv64-linux-gnu-gcc`  | `gcc-riscv64-linux-gnu`, `g++-riscv64-linux-gnu`, `libc6-dev-riscv64-cross` |

This mirrors what the CI installs in [`.github/actions/setup-build-env/action.yml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/.github/actions/setup-build-env/action.yml).

### Local Development Build (native architecture)

Run

```bash
make build
```

You should get a `k8s-kms-plugin` binary in the **`dist/`** directory:

```bash
./dist/k8s-kms-plugin version
```

This target builds for the host architecture, does not strip the binary (no `-s -w`), and does not require any
cross-compiler. It is the target to use for day-to-day development.

### Release-style Cross-Architecture Builds

The per-architecture targets produce stripped (`-s -w`) binaries whose names embed the version, matching the naming used
by the release artefacts:

```bash
make build-linux-amd64      # -> dist/k8s-kms-plugin_<version>_linux_amd64
make build-linux-arm64      # -> dist/k8s-kms-plugin_<version>_linux_arm64
make build-linux-riscv64    # -> dist/k8s-kms-plugin_<version>_linux_riscv64
```

`<version>` comes from `git describe --tags --always --dirty`.

The default target builds all three architectures at once (it requires every cross-compiler listed in
[Build Requirements](#build-requirements)):

```bash
make            # equivalent to: make all
```

### Debug Builds

Each architecture has a `-debug` variant, built with `-gcflags="all=-N -l"` (inlining and optimisations disabled) and
without stripping, so the binary can be used with [`delve`](https://github.com/go-delve/delve):

```bash
make build-linux-amd64-debug
make build-linux-arm64-debug
make build-linux-riscv64-debug
```

The binary is written to `dist/k8s-kms-plugin_<version>_linux_<arch>`. Do not use these binaries in a production
environment. See [`delve` Remote Debug](./development.md#delve-remote-debug) for how to attach a debugger.

### Other Useful `make` Targets

| Target                 | Purpose                                                                                  |
|------------------------|-------------------------------------------------------------------------------------------|
| `make lint`            | Runs `golangci-lint` (v2 binary required)                                                 |
| `make lint-fix`        | Runs `golangci-lint run --fix` to auto-fix mechanically-fixable findings                   |
| `make vet`             | Runs `go vet ./...` — same check as the CI *Vet, build & test* job                          |
| `make govulncheck`     | Scans for known vulnerabilities (see [Vulnerability check 💣](./supply-chain-security.md#vulnerability-check-)) |
| `make test`            | Unit tests (`./pkg/...`, `./cmd/...`) with the race detector                               |
| `make test-integration`| Integration tests (`./test/integration/...`) — needs `PKCS11_MODULE`, see [Running the Tests](./development.md#running-the-tests) |
| `make test-e2e`        | Builds the binary, then runs the end-to-end tests (`./test/e2e/...`) — needs `PKCS11_MODULE` and `grpcurl`, see [Running the Tests](./development.md#running-the-tests) |
| `make coverage`        | Unit test coverage report in `build/coverage.html`                                          |
| `make doc`             | Regenerates the CLI documentation under `docs/cli-user-interface/`                          |
| `make notices`         | Regenerates [`NOTICES.md`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/NOTICES.md) (requires `go-licenses`)                           |
| `make image`           | Builds the binary, then packages it into a container image from the [`Containerfile`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/Containerfile) (see [Build the Container Image](#build-the-container-image)) |
| `make image-from-source` | Same image, but compiled inside the builder stage — no local Go toolchain needed          |
| `make get-ldflags`     | Prints the `LDFLAGS` used by the build — consumed by `goreleaser` (see [Build `k8s-kms-plugin` **locally** from Source with `goreleaser`](#build-k8s-kms-plugin-locally-from-source-with-goreleaser)) |
| `make release-local-test` / `make release` | Run `goreleaser` locally (see [Build `k8s-kms-plugin` **locally** from Source with `goreleaser`](#build-k8s-kms-plugin-locally-from-source-with-goreleaser))            |
| `make clean`           | Removes the `dist/` directory                                                              |

## Build `k8s-kms-plugin` **locally** from Source with `goreleaser`

This section allows you to locally test the [`goreleaser`](https://github.com/goreleaser/goreleaser) Github Action Build
Recipe. It generates the same artefacts that the one generated by the Github Action CICD pipeline, but locally.

These commands are executed in `bash`. If you use other shells like `fish`, you might need to adjust the environment
variables export.

```bash
export LDFLAGS=$(make get-ldflags)
export WORKSPACE=/pwd
export GITHUB_REPOSITORY_OWNER=localfakegithubowner
```

As of now, we choose to configure `.goreleaser.yml` so that `goreleaser` gets the content of `LDFLAGS` from an
environment variable. This allows us to use the same `LDFLAGS` for the `make` build procedure as well as the
`goreleaser` build, without having to set `LDFLAGS` twice (once in `.goreleaser.yml`, and once in `Makefile`.).

`goreleaser` will fail if you do not provide a value for `GITHUB_REPOSITORY_OWNER`. We suggest using a fake value.
During a real Github Action run, the value will be provided by the `GITHUB_REPOSITORY_OWNER` environment variable set
by GA.

`goreleaser` will fail if you do not provide a value for `WORKSPACE`. During a real Github Action run, the value will be
provided by GA.

Then you can either install and run `goreleaser` locally, or (preferably) you can use `podman` to run `goreleaser`
inside an interactive container. Below is the `podman` command to run `goreleaser` locally.

```bash
podman run -it --rm \
        -v $PWD:/pwd \
        --workdir /pwd \
        -e LDFLAGS=$LDFLAGS \
        -e WORKSPACE=$WORKSPACE \
        -e GITHUB_REPOSITORY_OWNER=$GITHUB_REPOSITORY_OWNER \
        --platform "linux/amd64" \
        ghcr.io/thalesgroup/goreleaser-glibc-image:golang-1.25.1-bookworm \
          release \
            --clean \
            --snapshot \
            --skip sign,publish,validate,ko,sbom
```

We use a custom [`ghcr.io/thalesgroup/goreleaser-glibc-image`](https://github.com/ThalesGroup/goreleaser-glibc-image/pkgs/container/goreleaser-glibc-image) image to build `k8s-kms-plugin`, because the default [`ghcr.io/goreleaser/goreleaser`](https://github.com/goreleaser/goreleaser/pkgs/container/goreleaser) container image does not use the standard `glibc` libraries,
but uses MUSL libc (found on Alpine Linux).
To run on standard linux (not musl), `k8s-kms-plugin` needs to use standard `glibc` libraries as CGO is enabled.

You can also check out [`ghcr.io/goreleaser/goreleaser-cross`](https://github.com/goreleaser/goreleaser-cross/pkgs/container/goreleaser-cross),
which supports standard `glibc`.

Or you can create your own custom image, based on the examples from https://github.com/ThalesGroup/goreleaser-glibc-image.

## Build the Container Image

The image published to `ghcr.io` on release is built by [`ko`](https://ko.build/) through
[`.goreleaser.yml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/.goreleaser.yml). The [`Containerfile`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/Containerfile) is the local and CI equivalent —
it is what the Trivy image scan builds ([In CI (GitHub Actions)](./supply-chain-security.md#in-ci-github-actions)).

It does **not** compile anything by default: the `Makefile` stays the single source of truth for the build flags,
and the `Containerfile` only packages the artifact it produces.

```bash
# builds dist/k8s-kms-plugin, then packages it
make image

# override the engine or the tag
make image CONTAINER_ENGINE=docker IMAGE=k8s-kms-plugin:dev
```

Equivalent manual invocation, e.g. to package a specific `goreleaser` artifact:

```bash
podman build -f Containerfile \
  --build-arg BINARY=dist/k8s-kms-plugin_linux_amd64_1.0.0-rc5 \
  -t k8s-kms-plugin:v1.0.0 .
```

If you have no local Go toolchain, or want a cross-compiled multi-arch image, use the opt-in from-source build,
which compiles inside the builder stage:

```bash
make image-from-source

# or, multi-arch (amd64 / arm64 / riscv64 cross-compiled, no emulation)
docker buildx build --platform linux/amd64,linux/arm64,linux/riscv64 \
  --build-arg BINARY_SOURCE=source -f Containerfile -t k8s-kms-plugin:dev .
```

Build context exclusions live in [`.containerignore`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/.containerignore), the single source of truth.
Podman and Buildah read it directly; `.dockerignore` is a **symlink** to it, since Docker and BuildKit only look for
that name. Both toolchains therefore apply the same rules from one file, with no second copy to keep in sync.

The image is based on `debian:trixie-slim` (Debian 13), runs as the non-root user `1234:1234`, and carries the
[OCI image annotations](https://github.com/opencontainers/image-spec/blob/main/annotations.md) (`source`,
`revision`, `version`, `licenses`, `base.name`, …).

It deliberately ships **no PKCS#11 library** — vendor clients (Thales Luna `Chrystoki`, DPoD, SoftHSM) are
proprietary and/or host-specific, so bind-mount them at runtime and point `--p11-lib` at the mount:

```bash
podman run --rm \
  -v /opt/luna:/opt/luna:ro \
  -e ChrystokiConfigurationPath=/opt/luna/config \
  -v /run/k8s-kms-plugin:/run/k8s-kms-plugin \
  k8s-kms-plugin:dev serve \
    --provider luna \
    --p11-lib /opt/luna/lib/libCryptoki2.so \
    --p11-label mypartition \
    --p11-key-label kms-kek \
    --socket /run/k8s-kms-plugin/k8s-kms-plugin.sock
```

The header of the [`Containerfile`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/Containerfile) documents the remaining build arguments and a SoftHSM example.
