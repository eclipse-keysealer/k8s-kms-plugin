---
title: "k8s-kms-plugin completion"
description: "Generate the autocompletion script for the specified shell"
weight: 20
generator: "k8s-kms-plugin docs -f markdown"
---

## k8s-kms-plugin completion

Generate the autocompletion script for the specified shell

### Synopsis

Generate the autocompletion script for k8s-kms-plugin for the specified shell.
See each sub-command's help for details on how to use the generated script.


### Options

```
  -h, --help   help for completion
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
* [k8s-kms-plugin completion bash](k8s-kms-plugin_completion_bash.md)	 - Generate the autocompletion script for bash
* [k8s-kms-plugin completion fish](k8s-kms-plugin_completion_fish.md)	 - Generate the autocompletion script for fish
* [k8s-kms-plugin completion powershell](k8s-kms-plugin_completion_powershell.md)	 - Generate the autocompletion script for powershell
* [k8s-kms-plugin completion zsh](k8s-kms-plugin_completion_zsh.md)	 - Generate the autocompletion script for zsh

