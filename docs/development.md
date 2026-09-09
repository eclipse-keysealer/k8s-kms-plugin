---
title: "Development & Debugging"
weight: 70
---

## Development Environment 🔬

Repository layout:

| Path                                                      | Contents                                                                        |
|-----------------------------------------------------------|---------------------------------------------------------------------------------|
| [`cmd/k8s-kms-plugin/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/cmd/k8s-kms-plugin/)            | CLI entry point: Cobra commands and the Cobra ↔ koanf binding                    |
| [`pkg/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/pkg/)                                          | Plugin implementation: KMS v2 gRPC service and PKCS #11 providers                |
| [`tools/create-dev-token/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/tools/create-dev-token/)    | Standalone helper that bootstraps a SoftHSM development token                    |
| [`test/integration/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/test/integration/), [`test/e2e/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/test/e2e/) | Integration and end-to-end test suites                               |
| [`deployments/k8s/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/deployments/k8s/)                  | Reference `EncryptionConfiguration` and Kubernetes manifests                     |
| [`scripts/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/scripts/)                                  | Development helpers — see [`docs/`](./README.md#helper-tools--scripts)    |
| [`docs/`](./README.md)                               | Documentation, including the generated CLI reference                             |

The everyday loop uses the `make` targets documented in
[Build from Source](./installation.md#build-k8s-kms-plugin-locally-from-source-with-make) — mainly `make build`, `make test`
and `make lint-fix`; the full list is in [Other Useful `make` Targets](./installation.md#other-useful-make-targets).

Two of them regenerate tracked files, so re-run them when the relevant source changes:

- `make doc` — after adding or changing a CLI flag or command ([CLI Auto Generated Documentation](./cli-user-interface/README.md#cli-auto-generated-documentation))
- `make notices` — after changing dependencies, to refresh [`NOTICES.md`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/NOTICES.md)

### Running the Tests

| Suite                                          | Command                | Requirements                                                                 |
|------------------------------------------------|------------------------|-------------------------------------------------------------------------------|
| Unit ([`pkg/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/pkg/), [`cmd/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/cmd/))      | `make test`            | None — pure Go, race detector enabled                                         |
| Integration ([`test/integration/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/test/integration/)) | `make test-integration` | `PKCS11_MODULE`                                                    |
| End-to-end ([`test/e2e/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/test/e2e/))        | `make test-e2e`        | `PKCS11_MODULE`, [`grpcurl`](https://github.com/fullstorydev/grpcurl) in `$PATH`, and the built binary (`make test-e2e` builds it for you) |

**`PKCS11_MODULE`** points at a PKCS #11 shared library; both suites bootstrap their own ephemeral token from it.
`PKCS11_PIN` is optional (default `1234`). ML-KEM tests need SoftHSMv3 — see [`docs/softhsm-v3.md`](./hsm-guides/softhsm-v3.md);
the AES and RSA paths also work with SoftHSMv2.

> [!WARNING]
> Without `PKCS11_MODULE` both suites exit **immediately and successfully**, printing only a skip notice. A green
> run therefore does **not** mean the PKCS #11 paths were exercised — always check that the variable is set.

**`grpcurl`** is required by the end-to-end suite only: it drives the KMS v2 gRPC API over the plugin's unix socket,
using the [KMS v2 `api.proto`](https://pkg.go.dev/k8s.io/kms/apis/v2) as the service definition, resolved
automatically at the `k8s.io/kms` version `go.mod` selects (the same approach as the
[`scripts/grpcurl/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/scripts/grpcurl/) helper scripts, which additionally need `jq`). Unlike a missing
`PKCS11_MODULE`, a missing `grpcurl` makes the tests **fail** rather than skip.

```sh
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

Running the suites:

```sh
PKCS11_MODULE=/usr/local/lib/softhsm/libsofthsm3.so make test-integration
PKCS11_MODULE=/usr/local/lib/softhsm/libsofthsm3.so make test-e2e
```

### Build Against `crypto11` / `gose` Development Branches

`k8s-kms-plugin` consumes [`crypto11`](https://github.com/eclipse-keypont/crypto11) and
[`gose`](https://github.com/eclipse-keypont/gose) as **published modules** — [`go.mod`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/go.mod) has no `replace`
directives. To build against unreleased changes in those repositories, point the module requirements at a branch:

1. Push your changes to a dedicated branch in the `crypto11` repository (e.g. `my-dev-branch`).

2. In the `gose` repository, update *go.mod* to that `crypto11` branch and push:

```sh
# In the gose repo, on a dev branch
git switch -c my-dev-branch
GOPROXY=direct go get -u github.com/eclipse-keypont/crypto11/v2@my-dev-branch
go mod tidy
git add go.mod go.sum
git commit -S -s -m "dev: update gose with crypto11 dev changes"
git push
```

3. In the `k8s-kms-plugin` repository, point *go.mod* at both dev branches, then build:

```sh
git switch -c my-dev-branch
GOPROXY=direct go get -u github.com/eclipse-keypont/crypto11/v2@my-dev-branch
GOPROXY=direct go get -u github.com/eclipse-keypont/gose@my-dev-branch
go mod tidy
make build
```

> [!IMPORTANT]
> Restore the published module versions in `go.mod` / `go.sum` before opening a pull request — branch
> pseudo-versions must not reach `master`.

## Debug Environment 🐛

### `delve` Remote Debug

For a remote debug, build the plugin with debug mode :

```sh
go install github.com/go-delve/delve/cmd/dlv@latest
make build-linux-amd64-debug
```

It generates a binary `dist/k8s-kms-plugin_<version>_linux_amd64` that can be used with Delve for debug purpose
(see [Debug Builds](./installation.md#debug-builds) for the other architectures).
Do not use this binary in a production environment.

```sh
dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec ./dist/k8s-kms-plugin_<version>_linux_amd64
```

### `vscode` Debug

Install the [Go extension](https://marketplace.visualstudio.com/items?itemName=golang.Go) (`golang.go`); it installs
[`delve`](https://github.com/go-delve/delve) on demand (**Go: Install/Update Tools** → `dlv`).

`.vscode/` is git-ignored, so each developer keeps their own configurations. Create `.vscode/launch.json` with the
configurations you need — the three below cover the usual cases:

```jsonc {filename=".vscode/launch.json",linenos=table,hl_lines=[5,6,28,29,44,45]}
{
  "version": "0.2.0",
  "configurations": [
    {
      // 1. Build from source and debug in one step — no `make build` needed
      "name": "serve: SoftHSMv3 RSA-OAEP",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/cmd/k8s-kms-plugin",
      "cwd": "${workspaceFolder}",
      "console": "integratedTerminal",
      "args": [
        "serve",
        "--log-level", "trace",
        "--socket", "/run/user/1000/k8s-kms-plugin.sock",
        "--p11-lib", "/usr/local/lib/softhsm/libsofthsm3.so",
        "--p11-label", "k8s-kms-plugin-dev",
        "--p11-pin", "1234",
        "--p11-key-label", "dev-rsa-2048-oaep",
        "--algorithm-family", "rsa-oaep"
      ],
      "env": {
        "SOFTHSM2_CONF": "/tmp/k8s-kms-plugin-devtoken/softhsm2.conf"
      }
    },
    {
      // 2. Debug an already-built binary (see the Debug Builds section)
      "name": "serve: exec debug binary",
      "type": "go",
      "request": "launch",
      "mode": "exec",
      "program": "${workspaceFolder}/dist/k8s-kms-plugin",
      "cwd": "${workspaceFolder}",
      "console": "integratedTerminal",
      "args": ["serve", "--config", "configs/config.example.yaml"],
      "env": {
        "K8S_KMS_PLUGIN_LOG_LEVEL": "trace",
        "K8S_KMS_PLUGIN_SERVE_P11_LIB": "/usr/local/lib/softhsm/libsofthsm3.so",
        "K8S_KMS_PLUGIN_SERVE_SOCKET": "/run/user/1000/k8s-kms-plugin.sock"
      }
    },
    {
      // 3. Attach to the headless dlv started in the delve remote debug section
      "name": "attach to running dlv",
      "type": "go",
      "request": "attach",
      "mode": "remote",
      "host": "127.0.0.1",
      "port": 2345,
      "apiVersion": 2
    }
  ]
}
```

Then set breakpoints (e.g. in [`pkg/providers/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/pkg/)), pick the configuration in the **Run and Debug** view and
press `F5`.

A few traps specific to this project:

- **One `args` element per token.** `"--p11-lib /path/to/lib.so"` as a *single* string is passed to the process as one
  argument and Cobra will not parse it. Always split: `"--p11-lib", "/path/to/lib.so"`.
- **`"console": "integratedTerminal"`** is required if you omit `--p11-pin`: the PIN is then requested interactively
  with hidden input, and the Debug Console cannot provide it.
- **Flags, env vars or config file** — all three work, with the priority described in
  [User Input Priority: CLI > Env Vars > Config File > Default](./cli-user-interface/README.md#user-input-priority-cli--env-vars--config-file--default). The env var for a subcommand flag includes the
  subcommand: `--p11-pin` under `serve` is `K8S_KMS_PLUGIN_SERVE_P11_PIN`.
- **Breakpoints stop in Go code only.** The PKCS #11 library is C called through `CGO`; `delve` cannot step into it.
  To see what is sent to the token, use `--log-level trace` and the [`grpcurl` scripts](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/scripts/grpcurl/).
- **Debugging tests**: use the *debug test* code lens above any `Test…` function. The
  [integration](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/test/integration/) and [e2e](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/test/e2e/) suites need `PKCS11_MODULE` — supply it via
  `"go.testEnvVars"` in `.vscode/settings.json`, or point `"go.testEnvFile"` at a `.env` file:

```jsonc {filename=".vscode/settings.json"}
{
  "go.testEnvFile": "${workspaceFolder}/.env"
}
```
