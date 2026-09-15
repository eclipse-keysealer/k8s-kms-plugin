---
title: "k8s-kms-plugin completion zsh"
description: "Generate the autocompletion script for zsh"
weight: 60
generator: "k8s-kms-plugin docs -f markdown"
---

## k8s-kms-plugin completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(k8s-kms-plugin completion zsh)

To load completions for every new session, execute once:

#### Linux:

	k8s-kms-plugin completion zsh > "${fpath[1]}/_k8s-kms-plugin"

#### macOS:

	k8s-kms-plugin completion zsh > $(brew --prefix)/share/zsh/site-functions/_k8s-kms-plugin

You will need to start a new shell for this setup to take effect.


```
k8s-kms-plugin completion zsh [flags]
```

### Options

```
  -h, --help              help for zsh
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

