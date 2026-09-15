---
title: "SoftHSMv2"
weight: 20
---

> [!NOTE]
> **Legacy reference**: This guide is kept for backward compatibility. [`SoftHSMv3` (`pqctoday-hsm`)](./softhsm-v3.md) is now the recommended software HSM for development and integration testing — it supports all algorithm families including **ML-KEM**. SoftHSMv2 does **not** support ML-KEM.

This guide describes how to set up [`SoftHSMv2`](https://github.com/softhsm/SoftHSMv2) and make it
work with the `k8s-kms-plugin` in a **non production environment**.

You should read `SoftHSMv2` official documentation before reading this guide.

- [Install `SoftHSMv2`](#install-softhsmv2)
  - [Install the required packages:](#install-the-required-packages)
  - [Setup for rootless usage:](#setup-for-rootless-usage)
  - [Create an AES Key in SoftHSMv2](#create-an-aes-key-in-softhsmv2)
  - [Start the `k8s-kms-plugin serve`](#start-the-k8s-kms-plugin-serve)
  - [Configure a kubernetes cluster](#configure-a-kubernetes-cluster)
- [Using Env Vars](#using-env-vars)


## Install `SoftHSMv2`

### Install the required packages:

```sh
# debian
sudo apt install softhsm2 opensc
```

```bash
# redhat
sudo yum install epel-release softhsm opensc
```

### Setup for rootless usage:

Assuming you are using `bash` shell:

```sh
sudo cp /etc/softhsm/softhsm2.conf $HOME
sudo chown $USER: $HOME/softhsm2.conf
echo 'export SOFTHSM2_CONF=$HOME/softhsm2.conf' >> $HOME/.bashrc
source $HOME/.bashrc
sudo usermod -aG softhsm $USER
```

**Logout and login**.

### Create an AES Key in SoftHSMv2

Create a token:

```sh
softhsm2-util --init-token --slot 0 --label mylabel --so-pin mysopin --pin mypin
```

Find the PKCS#11 module path:

```sh
# for debian
export MODULE="/usr/lib/softhsm/libsofthsm2.so"
```

```sh
# for redhat
export MODULE="/usr/lib64/pkcs11/libsofthsm2.so"
```

Create an AES encryption key (KEK) **using an ID**.
The ID is mandatory to work with the K8S KMS v2 protocol :

```sh
# aes kek
pkcs11-tool --module $MODULE --token-label mylabel --pin mypin --keygen --key-type aes:16 --label aes01softhsm --id $(head -c 8 /dev/urandom | xxd -p)
```

List objects:

```bash
pkcs11-tool \
  --module $MODULE \
  --login --pin "mypin" \
  --token-label "mylabel" \
  --list-objects
```

```bash
Secret Key Object; AES length 16
warning: PKCS11 function C_GetAttributeValue(VALUE) failed: rv = CKR_ATTRIBUTE_SENSITIVE (0x11)

  label:      aes00softhsm
  ID:         d73f87d08873be56
  Usage:      encrypt, decrypt, verify, wrap, unwrap
  Access:     never extractable, local
```

### Start the `k8s-kms-plugin serve`

aes-gcm mode

```sh
SOCKET="/run/user/$(id -u $USER)/k8s-kms-plugin.sock"
k8s-kms-plugin \
  serve \
    --log-level=trace \
    --socket $SOCKET \
    --p11-lib $MODULE \
    --p11-label mylabel \
    --p11-pin mypin \
    --p11-key-label aes00softhsm \
    --algorithm-family aes-gcm
```

Alternatively, you can use `--p11-key-id` (PKCS #11 CKA_ID) instead of `--p11-key-label` (PKCS #11 CKA_LABEL).
See [`CKA_ID` vs `CKA_LABEL`](../cli-user-interface/cka-id-vs-cka-label.md) for how the two are resolved.

```sh
SOCKET="/run/user/$(id -u $USER)/k8s-kms-plugin.sock"

k8s-kms-plugin \
  serve \
    --log-level=trace \
    --socket $SOCKET \
    --p11-lib $MODULE \
    --p11-label mylabel \
    --p11-pin mypin \
    --p11-key-id d73f87d08873be56 \
    --algorithm-family aes-gcm
```

You can validate Encryption and Decryption are working by using [`grpcurl-roundtrip-test.sh`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/scripts/grpcurl/grpcurl-roundtrip-test.sh).

```bash
./grpcurl-roundtrip-test.sh 'hello world' /run/user/1000/k8s-kms-plugin.sock
```

```
./grpcurl-roundtrip-test.sh 'hello world' /run/user/1000/k8s-kms-plugin.sock
🔐 Input plaintext: hello world
🔐 Base64 encoded: aGVsbG8gd29ybGQ=
🧾 key_id from Status: d73f87d08873be56
🗄️  Ciphertext (base64): ZXlKaGJHY2lPaUprYVhJaUxDSnJhV1FpT2lKaFpYTXdNSE52Wm5Sb2MyMGlMQ0psYm1NaU9pSkJNalUyUjBOTkluMC4uSVZ6Y0RtSUpsTjF4dTVlQzJKVmFhZy5EZVg2MnRxMVlZaVN6QjgucFU3SG1zUTZUeGRvRXZvLXBFUlZ3UQ==
🔓 Decrypted text: hello world
✅ Round-trip encryption/decryption successful!
```

If `grpcurl-roundtrip-test.sh` works, it should work with a kubernetes server node.

### Configure a kubernetes cluster

Then review the content of file [`encryption-conf-kmsv2-unix-socket.yaml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml).
Make sure `resources.providers.kms.endpoint` points to the same unix socket file of the running `k8s-kms-plugin`.

Then point a cluster at it, following either
[Kubernetes integration guide](../kubernetes-guides/README.md):
[`KinD`](../kubernetes-guides/kind-kubernetes.md) installs nothing on the host and is deleted in one
command, while [`k3s`](../kubernetes-guides/k3s-kubernetes.md) runs on the host and is where key
rotation and HA are documented.

`k3s` takes the configuration directly on its install command — the highlighted line is the one that
wires `kube-apiserver` to the plugin:

```bash {hl_lines=[3]}
curl -sfL https://get.k3s.io | K3S_DEBUG=true INSTALL_K3S_VERSION=v1.33.1+k3s1 sh -s - \
  --write-kubeconfig-mode 660 \
  --kube-apiserver-arg=encryption-provider-config=$HOME/k8s-kms-plugin/deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml
```

`KinD` needs the socket mounted into the node container instead — see its guide.

## Using Env Vars

> [!NOTE]
> TODO: improve this section and harmonise the previous section to use environment variables

Have a look at this [table](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/docs/cli-user-interface/txt/cli-env-var-table.txt) which explains how to use environment variables with the `k8s-kms-plugin`.

```bash
export K8S_KMS_PLUGIN_SERVE_SOCKET="/run/user/$(id -u $USER)/k8s-kms-plugin.sock"
export K8S_KMS_PLUGIN_SERVE_P11_LIB="/usr/lib64/pkcs11/libsofthsm2.so"

k8s-kms-plugin \
  serve \
    --log-level=trace \
    --p11-label mylabel \
    --p11-pin mypin \
    --p11-key-label aes00softhsm \
    --algorithm-family aes-gcm
```
