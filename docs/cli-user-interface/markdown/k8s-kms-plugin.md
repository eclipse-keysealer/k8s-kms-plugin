---
title: "k8s-kms-plugin"
description: "Kubernetes KMS v2 plugin backed by a PKCS #11 TPM or HSM"
weight: 10
generator: "k8s-kms-plugin docs -f markdown"
---

## k8s-kms-plugin

Kubernetes KMS v2 plugin backed by a PKCS #11 TPM or HSM

### Synopsis

Connect a Kubernetes cluster to a PKCS #11 TPM or HSM through the Kubernetes KMS v2 API.

kube-apiserver asks the plugin to wrap and unwrap the data encryption key it uses to encrypt
etcd; the key encryption key (KEK) itself never leaves the token, and the plugin never sees a
Secret.

There are two ways to serve, and KEK rotation is one of them:

- "k8s-kms-plugin serve" serves one active KEK.
- "k8s-kms-plugin serve rotation" serves that same active KEK and additionally keeps one
  previous KEK for decryption, so a key rotation runs without downtime.

Reference:

- Project page: https://github.com/eclipse-keysealer/k8s-kms-plugin
- Documentation: https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/docs


```
k8s-kms-plugin [flags]
```

### Options

```
      --config string       Path to a YAML, TOML or JSON configuration file. Without it, k8s-kms-plugin.conf.{yaml,yml,json,toml} is looked up in $HOME and $HOME/.config/k8s-kms-plugin/; /etc is never searched.
      --debug               Shorthand for --log-level=debug. Mutually exclusive with --log-level.
  -h, --help                help for k8s-kms-plugin
      --log-format string   Log output format. One of: text (coloured, for a terminal), json (for a log collector). Logs always go to stderr. (default "text")
      --log-level string    Verbosity. One of: trace, debug, info, warn, error, quiet. "quiet" silences logging entirely. Mutually exclusive with --debug. (default "info")
```

### SEE ALSO

* [k8s-kms-plugin completion](k8s-kms-plugin_completion.md)	 - Generate the autocompletion script for the specified shell
* [k8s-kms-plugin docs](k8s-kms-plugin_docs.md)	 - Generate the CLI reference documentation
* [k8s-kms-plugin serve](k8s-kms-plugin_serve.md)	 - Serve the Kubernetes KMS v2 API over a unix socket
* [k8s-kms-plugin version](k8s-kms-plugin_version.md)	 - Print version, build and git metadata

