---
title: "k8s-kms-plugin serve rotation"
description: "Serve KMS v2 and also decrypt data written under a previous KEK"
weight: 90
generator: "k8s-kms-plugin docs -f markdown"
---

## k8s-kms-plugin serve rotation

Serve KMS v2 and also decrypt data written under a previous KEK

### Synopsis

Serve the Kubernetes KMS v2 API exactly as "k8s-kms-plugin serve" does, and additionally
decrypt data that was written under one previous KEK.

Every DecryptRequest is routed by the key_id Kubernetes stored with the data: the active KEK
decrypts its own data, the old KEK decrypts everything older. Encryption always uses the active
KEK, so this command does not re-encrypt anything by itself — kube-apiserver rewrites the
objects, and once it has rewritten them all the old KEK can be dropped.

The old KEK is described by a second, complete set of --old-* flags, so it may live on another
token or another HSM than the active one. The active KEK keeps the flags of the parent "serve"
command, including --socket: this command listens on that one socket.

Reference:

- Kubernetes KMS rotation notes: https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#developing-a-kms-plugin-gRPC-server-notes-kms-v2
- KMS v2 API: https://pkg.go.dev/k8s.io/kms/apis/v2
- CKA_ID vs CKA_LABEL: https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/docs/cli-user-interface/cka-id-vs-cka-label.md


```
k8s-kms-plugin serve rotation [flags]
```

### Examples

```

  # Active KEK on the command line, old KEK after the "rotation" subcommand.
  # Both PINs are prompted for, in that order, unless they come from the environment.
  k8s-kms-plugin serve \
    --socket /run/user/1000/k8s-kms-plugin.sock \
    --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --p11-label mytoken \
    --p11-key-label rsa0 \
    --algorithm-family rsa-oaep \
    rotation \
      --old-p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
      --old-p11-label mytoken \
      --old-p11-key-id 64636138353931326363356537313264 \
      --old-p11-hmac-id 30663536623936326235663530363234 \
      --old-algorithm-family aes-cbc

  # Both KEKs from a configuration file, both PINs from the environment.
  export K8S_KMS_PLUGIN_SERVE_P11_PIN=mypin
  export K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_PIN=myoldpin
  k8s-kms-plugin --config my-kms-plugin-config.yaml serve rotation

```

### Options

```
  -h, --help                                   help for rotation
      --old-algorithm-family algorithmFamily   Mechanism the old KEK was used with. One of: aes-gcm, aes-cbc, rsa-oaep, ml-kem. Required: data written under it cannot be read back with the wrong mechanism. (default aes-gcm)
      --old-p11-hmac-id string                 CKA_ID of the old HMAC key, as a hex string. aes-cbc only. Mutually exclusive with --old-p11-hmac-label.
      --old-p11-hmac-label string              CKA_LABEL of the old HMAC key. aes-cbc only. Mutually exclusive with --old-p11-hmac-id.
      --old-p11-key-id string                  CKA_ID of the old KEK, as a hex string. Mutually exclusive with --old-p11-key-label; exactly one of the two is required.
      --old-p11-key-label string               CKA_LABEL of the old KEK. Mutually exclusive with --old-p11-key-id; exactly one of the two is required. The key must also carry a CKA_ID on the token.
      --old-p11-label string                   Token label of the old KEK's token. Takes precedence over --old-p11-slot.
      --old-p11-lib string                     Path to the PKCS #11 library of the old KEK's TPM or HSM.
      --old-p11-pin string                     PIN of the old KEK's token. If omitted, prompted interactively with hidden input; pass an empty string explicitly for a token that takes no PIN.
      --old-p11-slot int                       Slot number of the old KEK's token. Only used when --old-p11-label is empty.
      --old-provider string                    PKCS #11 driver quirks to apply to the old KEK's token. One of: p11, softhsm, luna, dpod. (default "p11")
```

### Options inherited from parent commands

```
      --algorithm-family algorithmFamily   Mechanism the KEK is used with. One of: aes-gcm, aes-cbc, rsa-oaep, ml-kem. Key size and ML-KEM parameter set are read from the key on the token, not configured here. (default aes-gcm)
      --auto-create                        Generate the KEK on the token when it is missing, instead of failing. Not supported for ml-kem: that key pair has to be provisioned on the HSM beforehand.
      --config string                      Path to a YAML, TOML or JSON configuration file. Without it, k8s-kms-plugin.conf.{yaml,yml,json,toml} is looked up in $HOME and $HOME/.config/k8s-kms-plugin/; /etc is never searched.
      --debug                              Shorthand for --log-level=debug. Mutually exclusive with --log-level.
      --log-format string                  Log output format. One of: text (coloured, for a terminal), json (for a log collector). Logs always go to stderr. (default "text")
      --log-level string                   Verbosity. One of: trace, debug, info, warn, error, quiet. "quiet" silences logging entirely. Mutually exclusive with --debug. (default "info")
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

### SEE ALSO

* [k8s-kms-plugin serve](k8s-kms-plugin_serve.md)	 - Serve the Kubernetes KMS v2 API over a unix socket

