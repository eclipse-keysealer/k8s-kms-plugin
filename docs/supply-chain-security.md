---
title: "Supply Chain Security"
weight: 80
---

## Vulnerability check 💣

### Locally, before pushing

Three complementary checks, all runnable from the `Makefile` and mirroring what CI runs:

```sh
make vet           # go vet ./...        — suspicious constructs the compiler accepts
make lint          # golangci-lint       — bundles staticcheck, gosec, and more (see .golangci.yml)
make govulncheck   # govulncheck ./...   — known CVEs in the dependency tree
```

`make lint-fix` applies the mechanically-fixable lint findings. `make govulncheck` requires the tool:

```sh
go install golang.org/x/vuln/cmd/govulncheck@latest
```

`govulncheck` is **reachability-aware**: it reports a vulnerable module only when your code actually calls the
affected symbol, so it is far quieter than a plain dependency-version scan.

```sh
$ make govulncheck
Scanning your code and 288 packages across 34 dependent modules for known vulnerabilities...

No vulnerabilities found.
```

A finding is reported with the affected symbol, the fixed version and a call trace:

```
Vulnerability #1: GO-2026-5856
    More info: https://pkg.go.dev/vuln/GO-2026-5856
      Found in: crypto/tls@go1.26.4
      Fixed in: crypto/tls@go1.26.5
```

Findings in `crypto/…`, `net/…` and other standard-library packages are fixed by **upgrading the Go toolchain**, not
by touching [`go.mod`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/go.mod) requirements — bump the Go version and re-run the scan.

### In CI (GitHub Actions)

Scanning does not depend on anyone remembering to run it locally — these workflows run on every pull request, on
every push to `master`, and on a weekly schedule so that **newly disclosed** CVEs are caught between commits.
Findings land in the repository's **Security** tab (SARIF), without blocking the build.

| Workflow                                                    | What it does                                                                              |
|-------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| [`security.yaml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/.github/workflows/security.yaml)        | `govulncheck` (Go vuln DB), **CodeQL** (Go `security-extended` queries), **Trivy** filesystem scan (Go modules & Containerfiles) and Trivy image scan of the image built by `make image` from the [`Containerfile`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/Containerfile) |
| [`lint.yml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/.github/workflows/lint.yml)                  | `golangci-lint` — the same static analysis as `make lint`                                  |
| [`ci.yml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/.github/workflows/ci.yml)                      | `go vet`, build and test                                                                   |
| [`scorecard.yml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/.github/workflows/scorecard.yml)        | [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/eclipse-keysealer/k8s-kms-plugin) — rates supply-chain posture (branch protection, token permissions, pinned dependencies, dangerous workflow patterns). The badge in the [project README](https://github.com/eclipse-keysealer/k8s-kms-plugin#k8s-kms-plugin-) reflects the latest run |
| [`dependabot.yml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/.github/dependabot.yml)                | Weekly update PRs for **Go modules**, **GitHub Actions** and **Docker base images**; security updates are raised as individual PRs |

Because Dependabot also bumps GitHub Actions, the SHA pins used throughout the workflows stay current — one of the
criteria Scorecard grades.

> [!NOTE]
> `govulncheck` covers the Go dependency tree only. The PKCS #11 library loaded at runtime
> (SoftHSM, vendor middleware, …) is outside its reach and must be kept up to date by whoever operates the HSM.

## Release Signing & Attestations 📝

Pushing a `v*` tag runs Github Action [`release.yml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/.github/workflows/release.yml), which builds, signs, attests and publishes
everything **without any human interaction**.

Signing is **keyless**: `cosign` obtains a short-lived certificate from Sigstore's Fulcio CA using the OIDC token
GitHub issues to the job (`id-token: write`), and records the signature in the Rekor transparency log. No key
material, no secrets, and — unlike earlier releases of this project — **no authentication links to click in the job
logs**.

What a release produces:

| Artifact                                                              | Signature / attestation                                                        |
|------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| Binaries (`linux/amd64`, `arm64`, `riscv64`)                           | `<artifact>-keyless.bundle.json` — Sigstore bundle (`cosign sign-blob`)          |
| Packages (`apk`, `deb`, `rpm`, `pkg.tar.zst`)                          | idem                                                                             |
| `checksums.txt`                                                        | idem                                                                             |
| SBOMs — SPDX & CycloneDX (`syft`) and a CycloneDX VEX (`trivy`)        | idem, plus in-toto attestations via [`actions/attest`](https://github.com/actions/attest) |
| Container image `ghcr.io/eclipse-keysealer/k8s-kms-plugin`             | `cosign sign` on the exact `image@digest`; signature stored in the registry and Rekor |
| SLSA3 provenance — binaries (`*.intoto.jsonl`) and image               | [`slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator) `v2.1.0` reusable workflows |

The pipeline then **verifies its own output** before finishing: the `verify-provenance` job re-downloads the
published assets and runs `slsa-verifier` against both the binaries and the image
([`verify-slsa`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/.github/actions/verify-slsa/action.yml)). A release that cannot be verified fails the workflow.

> [!IMPORTANT]
> The signing identity is the release workflow itself:
> `https://github.com/eclipse-keysealer/k8s-kms-plugin/.github/workflows/release.yml@refs/tags/<tag>`.
> Every verification command below pins that identity — this is what makes the signature meaningful, so never
> verify without `--certificate-identity` / `--certificate-identity-regexp`.

## Verifying the authenticity of an artifact 📝🔍

Install [`cosign`](https://github.com/sigstore/cosign) (v3 or later — `COSIGN_EXPERIMENTAL` is no longer needed):

```bash
go install github.com/sigstore/cosign/v3/cmd/cosign@latest
```

Download the artifact together with its `-keyless.bundle.json` file from the
[releases page](https://github.com/eclipse-keysealer/k8s-kms-plugin/releases), then:

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

Expected output: `Verified OK`.

The bundle is a single, self-contained file: it holds the signature, the Fulcio certificate and the Rekor
inclusion proof that earlier releases shipped as a separate `.sig` / `.pem` pair.

The same command verifies packages, SBOMs and `k8s-kms-plugin_checksums.txt` — each ships its own bundle.
Verifying the checksums file once and then checking hashes locally covers every artifact at once:

```bash
sha256sum --check --ignore-missing k8s-kms-plugin_checksums.txt
```

The SBOMs (`k8s-kms-plugin-<version>-source.tar.gz.spdx.json`, `.cdx.json` and `.vex.cdx.json`) additionally carry
GitHub in-toto attestations, verifiable with the `gh` CLI:

```bash
gh attestation verify "k8s-kms-plugin-${VERSION}-source.tar.gz.spdx.json" \
  --repo eclipse-keysealer/k8s-kms-plugin
```

## Verifying the container image and its SLSA provenance

Verify the image signature (replace the tag, or pin a digest with `@sha256:…`):

```bash
TAG=v1.0.0-rc5
IMAGE=ghcr.io/eclipse-keysealer/k8s-kms-plugin:${TAG}

cosign verify "${IMAGE}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity "https://github.com/eclipse-keysealer/k8s-kms-plugin/.github/workflows/release.yml@refs/tags/${TAG}" \
  | jq .
```

[SLSA3](https://slsa.dev) provenance answers a different question — *which workflow, from which source revision,
produced this artifact* — and is checked with
[`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier) rather than `cosign`:

```bash
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.7.1
```

For a downloaded binary, using the `multiple.intoto.jsonl` published alongside it:

```bash
slsa-verifier verify-artifact "${FILE}" \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/eclipse-keysealer/k8s-kms-plugin \
  --source-tag "${TAG}"
```

For the image — the `--builder-id` must match the generator used by the `image-provenance` job:

```bash
slsa-verifier verify-image "${IMAGE}" \
  --source-uri github.com/eclipse-keysealer/k8s-kms-plugin \
  --source-tag "${TAG}" \
  --builder-id "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"
```

These are the same commands CI runs in [`verify-slsa`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/.github/actions/verify-slsa/action.yml), so a release that
reaches the releases page has already passed them once.
