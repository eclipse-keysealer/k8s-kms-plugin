---
title: "Documentation"
---

This folder is the documentation index for [`k8s-kms-plugin`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/README.md). Start here when looking for a guide;
the main [`README.md`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/README.md) is a short front door that links back here.

> [!NOTE]
> **Rendering**: these pages are rendered both by GitHub and by the documentation site
> ([Hugo + Hextra](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/website)), which publishes `docs/` and nothing else. Four link
> conventions keep them working in both places:
>
> - **between documentation pages** — always **relative** to the `.md` file (`./installation.md`).
>   A render hook rewrites these to page URLs on the site.
> - **to repository files outside `docs/`** (`scripts/`, `deployments/`, `tools/`, `Makefile`, Go source) —
>   always **absolute** (`https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/…`), because a
>   relative `../` link would leave the published site and 404.
> - **to non-page files inside `docs/`** (`.puml`, `.txt`, and directory listings) — also **absolute**.
>   A page becomes a *directory* URL on the site, so a relative link to a plain file beside it
>   resolves one level too deep. Images are the exception: keep those relative, since Hugo's image
>   render hook resolves them.
> - **to a Go package on pkg.go.dev** — never pin a module version. `https://pkg.go.dev/k8s.io/kms/apis/v2`
>   follows the module; inserting an `@<version>` freezes the link at whatever release was current the
>   day it was written, and nothing updates it on a dependency bump. `make check-doc-links` fails on a
>   pinned URL, in Markdown and in Go doc comments alike.
>
> Headings carry **no manual section numbers**: a generator derives ordering and the table of contents from the
> document tree, and hand-written numbers drift out of sync with the anchors pointing at them. Run
> `make check-doc-links` after moving or renaming anything here, and `make site` (which runs
> `make check-site`) to confirm the published output still resolves.

- [Where to Find What](#where-to-find-what)
- [Getting started](#getting-started)
- [Concepts & architecture](#concepts--architecture)
- [Cryptographic reference](#cryptographic-reference)
- [HSM \& TPM guides](#hsm--tpm-guides)
- [Kubernetes integration guides](#kubernetes-integration-guides)
- [CLI reference](#cli-reference)
- [Development](#development)
- [Helper tools \& scripts](#helper-tools--scripts)
- [Diagrams \& images](#diagrams--images)

## Where to Find What

| I want to…                                                 | Go to |
|------------------------------------------------------------|-------|
| Get something running in a few minutes                     | [Quick start](#getting-started) below — SoftHSMv3, then `KinD` |
| Set up an HSM, a TPM or a software HSM                      | [HSM & TPM guides](./hsm-guides/README.md) |
| Know which algorithm families were tested on my device      | [HSM & TPM Supported Platforms](./hsm-guides/README.md#hsm--tpm-supported-platforms) |
| Make a Kubernetes cluster use the plugin                    | [Kubernetes integration guides](./kubernetes-guides/README.md) |
| Install a package, or build from source                     | [Installation](./installation.md) |
| Check a download is genuine                                 | [Verify what you downloaded](./installation.md#verify-what-you-downloaded) |
| Look up a command, a flag or its environment variable       | [CLI reference](./cli-user-interface/README.md) |
| Understand what actually happens to my Secrets              | [Concepts & Architecture](./overview.md), then [Cryptographic Schemes](./cryptographic-schemes.md) |
| Rotate a KEK                                                | [Key Rotation Support](./overview.md#key-rotation-support) for how it works; the [`k3s` guide](./kubernetes-guides/k3s-kubernetes.md) happens to be where a worked example is written up |
| Test the gRPC API without a cluster, or stage a `KinD` env  | [Helper tools & scripts](#helper-tools--scripts) below |
| Debug the plugin                                            | [Debug Environment](./development.md#debug-environment-) |
| Verify a release's signature or SLSA provenance             | [Supply Chain Security](./supply-chain-security.md) |
| Look up an acronym or a term                                | [Glossary](./glossary.md) |

## Getting started

**Quick start** — two steps, no hardware needed. Do them in order:

| Step | Guide | What you get |
|------|-------|--------------|
| 1 | [SoftHSMv3 (`pqctoday-hsm`)](./hsm-guides/softhsm-v3.md) | A software PKCS #11 provider with a key per algorithm family, and `k8s-kms-plugin serve` running against it — including ML-KEM |
| 2 | [`KinD`](./kubernetes-guides/kind-kubernetes.md) | A single-node Kubernetes cluster encrypting its Secrets through that plugin, deleted again in one command |

Then, as you need them:

| Page | What it covers |
|------|----------------|
| [Installation](./installation.md) | Getting a release binary or package, verifying it, `go install`, building from source, container images |
| [Glossary](./glossary.md) | Every acronym and term used here, from DEK and KEK to ML-KEM's encapsulation key |
| [`CHANGELOG.md`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/CHANGELOG.md) | Release history |

## Concepts & architecture

The plugin occupies exactly one step of the KMS v2 envelope scheme, and **never sees your `Secret`
data** — only the 32-byte DEK seed that `kube-apiserver` asks it to wrap with the KEK held on the
TPM or HSM. The apiserver derives the DEK and encrypts the object itself.

→ **[Concepts & Architecture](./overview.md)** for the terminology, that flow drawn out, the
deployment topologies (single node and HA across three servers), and how key rotation works.

## Cryptographic reference

Four algorithm families, chosen with `--algorithm-family`. Key size and parameter set are **not**
flags — they are read from the key on the token at runtime.

| Family | What wraps the DEK seed | Output |
|--------|-------------------------|--------|
| `aes-gcm` | AES-GCM, 128/192/256-bit | JWE |
| `aes-cbc` | AES-CBC with HMAC-SHA256 authentication | JWE |
| `rsa-oaep` | RSA-OAEP (SHA-256), 2048/3072/4096-bit | JWE |
| `ml-kem` | ML-KEM-512/768/1024 (FIPS 203) + AES-256-GCM | binary envelope **+ a `kem-ciphertext` annotation** |

ML-KEM is the structural exception: a KEM produces two artefacts where JWE has one slot, and the KEM
ciphertext alone exceeds the KMS v2 1 kB ciphertext limit at 768 and 1024. So the plugin splits them
across the two fields KMS v2 already provides.

→ **[Cryptographic Schemes](./cryptographic-schemes.md)** for what each family does to the data
byte by byte, which operations stay inside the HSM, and the ML-KEM envelope in full.

## HSM & TPM guides

Every provider is reached through the same PKCS #11 interface, so the plugin configuration differs
only in `--p11-lib`, the token label and which key you point at. One page each, in
**[`hsm-guides/`](./hsm-guides/README.md)**; new devices are added there.

Tested and documented so far:

| Device | Type | Form factor | Algorithm families verified | Guide |
|--------|------|-------------|-----------------------------|-------|
| SoftHSMv3 (`pqctoday-hsm`) | HSM | Software | AES-GCM, AES-CBC+HMAC, RSA-OAEP, **ML-KEM** | [Guide](./hsm-guides/softhsm-v3.md) |
| SoftHSMv2 | HSM | Software | none yet — no ML-KEM support | [Guide](./hsm-guides/softhsm-v2.md) |
| Software TPM Emulator (`swtpm`) | TPM | Software | none yet — no ML-KEM support | [Guide](./hsm-guides/software-tpm-emulator.md) |
| Thales eToken Fusion | HSM | Hardware USB | RSA-OAEP | [Guide](./hsm-guides/thales-etoken-fusion.md) |
| Yubico YubiHSM 2 | HSM | Hardware USB | RSA-OAEP | [Guide](./hsm-guides/yubico-yubihsm2.md) |
| Thales Luna HSM | HSM | Network, cloud | none yet — integration documented by Thales | [Guide](./hsm-guides/thales-luna-hsm.md) |

**SoftHSMv3 is the one to start with** — it is the only provider here that covers every algorithm
family, and it needs no hardware.

"Verified" means someone ran it and wrote it down. A blank is not a failure: the plugin reads the key
size and parameter set from the token at runtime, so untested combinations are simply untested. The
exact key sizes and ML-KEM parameter sets behind each entry are in
[HSM & TPM Supported Platforms](./hsm-guides/README.md#hsm--tpm-supported-platforms), which is the
authoritative matrix.

## Kubernetes integration guides

How to make a cluster's `kube-apiserver` encrypt Secrets through a running plugin. One page per
distribution, in **[`kubernetes-guides/`](./kubernetes-guides/README.md)**.

Tested and documented so far:

| Distribution | Tested with | Runs where | Also covers | Guide |
|--------------|-------------|------------|-------------|-------|
| `KinD` — **recommended for testing** | `kind v0.32.0` (Kubernetes v1.36.1) | Podman or Docker container | Two-hop socket mount, rootless Podman, troubleshooting table | [Guide](./kubernetes-guides/kind-kubernetes.md) |
| `k3s` | `v1.33.1+k3s1` | On the host | Key rotation with `serve rotation`, HA with three server nodes | [Guide](./kubernetes-guides/k3s-kubernetes.md) |

Both require Kubernetes **v1.29 or newer** — the plugin serves only KMS v2, and KMS v1 is disabled by
default from v1.29. Any distribution that supports KMS v2 and lets you pass
`--encryption-provider-config` to the apiserver should work; these two are the ones exercised.

Both use the reference [`EncryptionConfiguration`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml)
from [`deployments/k8s/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/deployments/k8s/).

## CLI reference

| Page | What it covers |
|------|----------------|
| [CLI documentation index](./cli-user-interface/markdown/README.md) | One page per command, generated from the Cobra definitions |
| [`k8s-kms-plugin serve`](./cli-user-interface/markdown/k8s-kms-plugin_serve.md) | The main command: serves the KMS v2 gRPC API |
| [`k8s-kms-plugin serve rotation`](./cli-user-interface/markdown/k8s-kms-plugin_serve_rotation.md) | Key rotation mode (active + old KEK) |
| [Flags ↔ environment variables](./cli-user-interface/markdown/cli-env-var-table.md) | Recap of every subcommand, flag and env var ([txt version](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/docs/cli-user-interface/txt/cli-env-var-table.txt)) |
| [`CKA_ID` vs `CKA_LABEL`](./cli-user-interface/cka-id-vs-cka-label.md) | How `--p11-key-id`/`--p11-key-label` (and their `--p11-hmac-*`/`--old-*` counterparts) are resolved — hand-written, not regenerated by `make doc` |

_Auto generated_ files carry a footer such as `###### Auto generated by spf13/cobra on 31-Jul-2025`. Do not edit them
by hand — regenerate with `make doc`. See
[CLI Auto Generated Documentation](./cli-user-interface/README.md#cli-auto-generated-documentation).

## Development

Three test suites: unit tests need nothing, while the integration and end-to-end suites need a
PKCS #11 module in `PKCS11_MODULE` — **without it they exit successfully without testing anything**,
so a green run is not proof the PKCS #11 paths ran.

→ **[Development & Debugging](./development.md)** for the repository layout, what each suite needs,
building against `crypto11`/`gose` development branches, and `delve`/`vscode` debugging.

→ **[Supply Chain Security](./supply-chain-security.md)** — the reference for signing and provenance:
vulnerability scanning locally and in CI, what a release produces (Sigstore bundles, SBOMs, VEX,
SLSA3 provenance for binaries and image), and the full verification commands. [Installation](./installation.md#verify-what-you-downloaded)
has the short version if you only want to check a download.

## Helper tools & scripts

Development and testing helpers that ship with the repository — none is part of the deployable.
Documented in **[`tools-and-scripts/`](./tools-and-scripts/README.md)**.

| Helper | What it does |
|--------|--------------|
| [`create-dev-token`](./tools-and-scripts/create-dev-token.md) | A persistent SoftHSM token with one key per algorithm family, ready for `serve` — no hardware needed |
| [`grpcurl` round-trip scripts](./tools-and-scripts/grpcurl-scripts.md) | Drive `Status`, `Encrypt` and `Decrypt` against a running plugin with no cluster involved, including a key-rotation round trip |
| [`KinD` staging script](./tools-and-scripts/k8s-kind-scripts.md) | Stages the directories, `EncryptionConfiguration` and `kind.config.yaml` a `KinD` cluster needs |

They compose into a fast loop: get a token, prove the plugin encrypts and decrypts, then bring a
cluster into it — each step independent of the next.

## Diagrams & images

- [`puml-diagrams/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/docs/puml-diagrams/) — PlantUML sources (`.puml`) and their rendered `.svg`
  (`overview.png`/`.svg` are exported from `overview.drawio` instead, not from PlantUML)
- [`images/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/docs/images/) — deployment scenarios, key rotation sequences, dependency graphs

Two diagram formats are used on purpose:

| Format | Used for | Lives in |
|---|---|---|
| **Mermaid** | short overview diagrams, written inline in the Markdown and rendered by GitHub — nothing to regenerate | the `.md` files themselves |
| **PlantUML** | the detailed KMS v2 sequences (legend, `alt` branches, per-family payloads) | `.puml` sources + committed `.svg` |

The KMS v2 sequence diagrams are embedded under
[Deployment Scenarios Examples](./overview.md#deployment-scenarios-examples); the envelope overview
is the Mermaid diagram in [Architecture](./overview.md#architecture) and in
[Cryptographic Schemes](./cryptographic-schemes.md#what-the-plugin-actually-encrypts).

**Regenerating the PlantUML `.svg`** after editing a `.puml` — the `.svg` files are committed, so they must be
refreshed in the same commit:

```bash
podman run --rm -v "$PWD/docs/puml-diagrams:/data:z" -w /data \
  docker.io/plantuml/plantuml:latest -tsvg 'kmsv2-*.puml'
```

> [!WARNING]
> PlantUML names its output after the `@startuml "<name>"` title, **not** after the source file, so rename the
> results back to the tracked `kmsv2-*.sqce-diag.svg` names (or use the VS Code PlantUML extension, which keeps the
> source file name). The class diagrams (`cbc-class.puml`, `gcm-class.puml`, `rsa-class.puml`,
> `ml-kem-class.puml`) use an unnamed `@startuml`, so PlantUML already names their output after the source
> file and no renaming is needed.
