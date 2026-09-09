---
title: "k8s-kms-plugin serve"
description: "Serve the Kubernetes KMS v2 API over a unix socket"
weight: 80
generator: "k8s-kms-plugin docs -f markdown"
---

## k8s-kms-plugin serve

Serve the Kubernetes KMS v2 API over a unix socket

### Synopsis

Serve the Kubernetes KMS v2 API on a unix socket, wrapping and unwrapping the data
encryption key with a key encryption key (KEK) held on a PKCS #11 token.

This command serves one active KEK. To keep decrypting data written under a previous KEK while
a rotation is in progress, use "k8s-kms-plugin serve rotation" instead.

Identify the KEK with exactly one of --p11-key-id (CKA_ID) or --p11-key-label (CKA_LABEL); the
plugin looks up whichever you leave out. --p11-hmac-id / --p11-hmac-label follow the same rule
and are only used by --algorithm-family=aes-cbc, which authenticates the ciphertext separately.

The PIN is a secret: prefer K8S_KMS_PLUGIN_SERVE_P11_PIN, or omit it and be prompted, over
--p11-pin, which any user on the host can read out of the process arguments.

Reference:

- Kubernetes KMS provider guide: https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#configuring-the-kms-provider-kms-v2
- KMS v2 API: https://pkg.go.dev/k8s.io/kms/apis/v2
- CKA_ID vs CKA_LABEL: https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/docs/cli-user-interface/cka-id-vs-cka-label.md


```
k8s-kms-plugin serve [flags]
```

### Examples

```

  # Everything on the command line, PIN prompted interactively (input hidden).
  k8s-kms-plugin serve \
    --socket /run/user/1000/k8s-kms-plugin.sock \
    --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --p11-label mytoken \
    --p11-key-label rsa0 \
    --algorithm-family rsa-oaep

  # AES-CBC with HMAC authentication, both keys identified by CKA_ID.
  k8s-kms-plugin serve \
    --log-level trace \
    --socket /run/user/1000/k8s-kms-plugin.sock \
    --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --p11-label mytoken \
    --p11-key-id 64636138353931326363356537313264 \
    --p11-hmac-id 30663536623936326235663530363234 \
    --algorithm-family aes-cbc

  # Everything from a configuration file, PIN from the environment.
  export K8S_KMS_PLUGIN_SERVE_P11_PIN=mypin
  k8s-kms-plugin --config my-kms-plugin-config.yaml serve

  # Config file for the token, environment for the PIN, flags for what changes per host.
  export K8S_KMS_PLUGIN_SERVE_P11_PIN=mypin
  k8s-kms-plugin --log-format json --config my-kms-plugin-config.yaml serve \
    --socket /run/user/1000/k8s-kms-plugin.sock

```

### Options

```
      --algorithm-family algorithmFamily   Mechanism the KEK is used with. One of: aes-gcm, aes-cbc, rsa-oaep, ml-kem. Key size and ML-KEM parameter set are read from the key on the token, not configured here. (default aes-gcm)
      --auto-create                        Generate the KEK on the token when it is missing, instead of failing. Not supported for ml-kem: that key pair has to be provisioned on the HSM beforehand.
  -h, --help                               help for serve
      --p11-hmac-id string                 CKA_ID of the HMAC key authenticating the ciphertext, hex. aes-cbc only. Mutually exclusive with --p11-hmac-label.
      --p11-hmac-label string              CKA_LABEL of the HMAC key authenticating the ciphertext. aes-cbc only. Mutually exclusive with --p11-hmac-id. The key must also carry a CKA_ID on the token.
      --p11-key-id string                  CKA_ID of the KEK, hex. Mutually exclusive with --p11-key-label, one of the two required. This is the ID Kubernetes stores in etcd alongside the data.
      --p11-key-label string               CKA_LABEL of the KEK. Mutually exclusive with --p11-key-id, one of the two required. The key must also carry a CKA_ID on the token: that is what is stored in etcd.
      --p11-label string                   Token label (CKA_LABEL of the token, not of the key) identifying which token to open. Takes precedence over --p11-slot.
      --p11-lib string                     Path to the PKCS #11 library of the TPM or HSM, e.g. /usr/lib/softhsm/libsofthsm2.so.
      --p11-pin string                     PIN of the token. Omit it to be prompted with hidden input; pass an empty string for a token that takes no PIN. Prefer the environment variable: process arguments are world-readable.
      --p11-slot int                       Slot number to open. Only used when --p11-label is empty.
      --provider string                    PKCS #11 driver quirks to apply. One of: p11 (generic), softhsm, luna, dpod. luna and dpod take the GCM IV from the HSM. (default "p11")
      --socket string                      Unix socket the gRPC server listens on, e.g. /run/user/$(id -u)/k8s-kms-plugin.sock. Created with mode 0775 so a client under a shared gid can connect. (default "/tmp/run/hsm-plugin-server.sock")
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
* [k8s-kms-plugin serve rotation](k8s-kms-plugin_serve_rotation.md)	 - Serve KMS v2 and also decrypt data written under a previous KEK

