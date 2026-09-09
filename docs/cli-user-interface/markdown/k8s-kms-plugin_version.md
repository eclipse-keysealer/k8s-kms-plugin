---
title: "k8s-kms-plugin version"
description: "Print version, build and git metadata"
weight: 100
generator: "k8s-kms-plugin docs -f markdown"
---

## k8s-kms-plugin version

Print version, build and git metadata

### Synopsis

Print the version of k8s-kms-plugin together with the build and git repository metadata
it was compiled from: commit, build date, platform and Go toolchain.

Use -o json or -o yaml to consume it from a script; with no --output the version is printed as
a single human-readable line.

```
k8s-kms-plugin version [flags]
```

### Examples

```

  # Version and git details as a one-line JSON string, ready to pipe into jq.
  k8s-kms-plugin version -o json --pretty=false

  # The same, as indented YAML.
  k8s-kms-plugin version -o yaml

```

### Options

```
  -h, --help            help for version
  -o, --output string   Machine-readable output format. One of: yaml, json. Omit for a single human-readable line.
  -P, --pretty          Indent the JSON output. Set to false for a one-line string. (default true)
```

### Options inherited from parent commands

```
      --config string       Path to a YAML, TOML or JSON configuration file. Without it, k8s-kms-plugin.conf.{yaml,yml,json,toml} is looked up in $HOME and $HOME/.config/k8s-kms-plugin/; /etc is never searched.
      --debug               Shorthand for --log-level=debug. Mutually exclusive with --log-level.
      --log-format string   Log output format. One of: text (coloured, for a terminal), json (for a log collector). Logs always go to stderr. (default "text")
      --log-level string    Verbosity. One of: trace, debug, info, warn, error, quiet. "quiet" silences logging entirely. Mutually exclusive with --debug. (default "info")
```

### SEE ALSO

* [k8s-kms-plugin](k8s-kms-plugin.md)	 - Kubernetes KMS v2 plugin backed by a PKCS #11 TPM or HSM

