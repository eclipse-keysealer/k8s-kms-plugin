---
title: "k8s-kms-plugin completion powershell"
description: "Generate the autocompletion script for powershell"
weight: 50
generator: "k8s-kms-plugin docs -f markdown"
---

## k8s-kms-plugin completion powershell

Generate the autocompletion script for powershell

### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	k8s-kms-plugin completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


```
k8s-kms-plugin completion powershell [flags]
```

### Options

```
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --config string       Path to a YAML, TOML or JSON configuration file. Without it, k8s-kms-plugin.conf.{yaml,yml,json,toml} is looked up in $HOME and $HOME/.config/k8s-kms-plugin/; /etc is never searched.
      --debug               Shorthand for --log-level=debug. Mutually exclusive with --log-level.
      --log-format string   Log output format. One of: text (coloured, for a terminal), json (for a log collector). Logs always go to stderr. (default "text")
      --log-level string    Verbosity. One of: trace, debug, info, warn, error, quiet. "quiet" silences logging entirely. Mutually exclusive with --debug. (default "info")
```

### SEE ALSO

* [k8s-kms-plugin completion](k8s-kms-plugin_completion.md)	 - Generate the autocompletion script for the specified shell

