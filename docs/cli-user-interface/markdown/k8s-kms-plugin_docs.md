---
title: "k8s-kms-plugin docs"
description: "Generate the CLI reference documentation"
weight: 70
generator: "k8s-kms-plugin docs -f markdown"
---

## k8s-kms-plugin docs

Generate the CLI reference documentation

### Synopsis

Generate the CLI reference for every command and flag of k8s-kms-plugin.

The markdown tree and the flag/environment-variable table are committed to
docs/cli-user-interface/, so this command is what "make doc" runs after a flag is added,
renamed or reworded. Its default output is deterministic: two runs on the same source tree
produce byte-identical files.

```
k8s-kms-plugin docs [flags]
```

### Examples

```

  # Regenerate the committed markdown reference (what "make doc" does).
  k8s-kms-plugin docs --format markdown --output-dir docs/cli-user-interface/markdown/

  # Regenerate the committed flag/env-var table.
  k8s-kms-plugin docs --format cli-table-pretty --output-dir docs/cli-user-interface/txt/

  # Look at the flag table without writing anything you have to clean up afterwards.
  k8s-kms-plugin docs --format cli-table-pretty

```

### Options

```
  -f, --format string       Output format. One of: markdown (what the documentation site publishes), man, rst, yaml, cli-table-csv, cli-table-pretty, cli-table-html, all. (default "markdown")
  -h, --help                help for docs
  -o, --output-dir string   Directory the generated files are written to. Defaults to a fresh timestamped directory under $TMPDIR, so two ad hoc runs never overwrite each other. (default "$TMPDIR/k8s-kms-plugin-docs-<timestamp>")
      --provenance          Stamp the build and CI run that produced the pages into the front matter of the generated markdown. Defaults to true when GITHUB_ACTIONS=true, so the published site records its build while the committed tree stays free of volatile data. (default auto)
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

