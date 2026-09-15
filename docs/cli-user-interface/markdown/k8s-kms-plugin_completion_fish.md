---
title: "k8s-kms-plugin completion fish"
description: "Generate the autocompletion script for fish"
weight: 40
generator: "k8s-kms-plugin docs -f markdown"
---

## k8s-kms-plugin completion fish

Generate the autocompletion script for fish

### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	k8s-kms-plugin completion fish | source

To load completions for every new session, execute once:

	k8s-kms-plugin completion fish > ~/.config/fish/completions/k8s-kms-plugin.fish

You will need to start a new shell for this setup to take effect.


```
k8s-kms-plugin completion fish [flags]
```

### Options

```
  -h, --help              help for fish
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

