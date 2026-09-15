---
title: "k3s"
weight: 20
---

This guide explains how to setup a `k3s` kubernetes cluster to use `k8s-kms-plugin serve` for
encryption operations.

The guide also explains the key rotation mechanism with `k8s-kms-plugin serve rotation` supported
by [KMS v2](https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/).

> [!CAUTION]
> **This guide is for testing purposes only. Do not use it in a production environment.**

> [!NOTE]
> Doc under construction

- [Kubernetes Requirements](#kubernetes-requirements)
- [Kubernetes KMS v2 Sequence Diagram](#kubernetes-kms-v2-sequence-diagram)
- [Single Node `k3s` Cluster](#single-node-k3s-cluster)
  - [Run `k8s-kms-plugin serve` (no key rotation)](#run-k8s-kms-plugin-serve-no-key-rotation)
  - [Restart `k3s`: Clear the DEK Cache](#restart-k3s-clear-the-dek-cache)
  - [Perform a Key Rotation Operation](#perform-a-key-rotation-operation)
- [k3s High Availability Embedded etcd](#k3s-high-availability-embedded-etcd)

## Kubernetes Requirements

`k8s-kms-plugin` is designed for kubernetes clusters that are using version v1.29 or higher and implements the[KMS v2 API](https://pkg.go.dev/k8s.io/kms/apis/v2).

> [!IMPORTANT]
> `k8s-kms-plugin` **does not support KMS v1** which is deprecated in Kubernetes v1.28 and disabled by default since Kubernetes v1.29.

This guide uses [`k3s`](https://k3s.io/) as a Kubernetes distribution, as `k3s` is easy to setup.
In general, we make sure to explicitely set `INSTALL_K3S_VERSION`.

## Kubernetes KMS v2 Sequence Diagram

![](../puml-diagrams/kmsv2-first-k8s-startup.sqce-diag.svg)

![](../puml-diagrams/kmsv2-decryptrequest.sqce-diag.svg)

![](../puml-diagrams/kmsv2-key-rotation.sqce-diag.svg)

## Single Node `k3s` Cluster

### Run `k8s-kms-plugin serve` (no key rotation)

> [!NOTE]
> This section does not detail how to deploy & run the `k8s-kms-plugin`. See the other
> documentation pages like [`SoftHSMv2`](../hsm-guides/softhsm-v2.md) or
> [`Yubico YubiHSM 2`](../hsm-guides/yubico-yubihsm2.md) to run the `k8s-kms-plugin`. 

Assuming you have configured a PKCS #11 TPM or HSM, you can start the
`k8s-kms-plugin serve` without the key rotation support for now:

```bash
k8s-kms-plugin \
  serve \
    --log-level=trace \
    --socket /run/user/1000/k8s-kms-plugin.sock \
    --p11-lib /usr/lib64/pkcs11/libtpm2_pkcs11.so \
    --p11-label mylabel \
    --p11-pin mypin \
    --p11-key-id abcd \
    --algorithm-family rsa-oaep
```

> [!NOTE]
> This example uses [`Software TPM Emulator`](https://github.com/stefanberger/swtpm).

Then review the content of file [`encryption-conf-kmsv2-unix-socket.yaml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml).
Make sure `resources.providers.kms.endpoint` points to the same unix socket file of the running `k8s-kms-plugin`.

Then install `k3s` inversion `v1.33.1+k3s1` with the following command — the highlighted line is the
one that wires `kube-apiserver` to the plugin:

```bash {hl_lines=[3]}
curl -sfL https://get.k3s.io | K3S_DEBUG=true INSTALL_K3S_VERSION=v1.33.1+k3s1 sh -s - \
  --write-kubeconfig-mode 660 \
  --kube-apiserver-arg=encryption-provider-config=$HOME/k8s-kms-plugin/deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml
```

During `k3s` first startup, the k8s API server sends a KMS v2 [`StatusRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#StatusRequest) and an [`EncryptRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#EncryptRequest) to the `k8s-kms-plugin` to encrypt the DEK. You should see those Requests in the `k8s-kms-plugin` logs (level ).

```
# k8s-kms-plugin serve --log-level=trace

TRAC[0031] UnaryInterceptor kms v2 StatusRequest         line="providers/p11.go:969"
TRAC[0031] p11 Status: entering method                   line="providers/p11.go:1001"
DEBU[0031] StatusResponse                                Healthz=ok KeyId=abcd Version=v2 line="providers/p11.go:1027"
TRAC[0031] UnaryInterceptor kms v2 EncryptRequest        line="providers/p11.go:973"
TRAC[0031] p11:Encrypt case RSA-OAEP                     line="providers/p11.go:899"
```

The k3s installation should go through without errors. Then perform commands like `kubectl get secrets -A` and
`kubectl get nodes` to see how your cluster is responding.

```bash
sudo sqlite3 /var/lib/rancher/k3s/server/db/state.db "SELECT hex(value) FROM kine WHERE name LIKE '%secrets%k3s-serving'" | xxd -r -p | hexdump -C | head -n 2
```
```hexdump
00000000  6b 38 73 3a 65 6e 63 3a  6b 6d 73 3a 76 32 3a 6b  |k8s:enc:kms:v2:k|
00000010  6d 73 2d 73 65 72 76 65  72 3a 0a b4 18 e7 4a 3e  |ms-server:....J>|
```

### Restart `k3s`: Clear the DEK Cache

Keep the `k8s-kms-plugin serve` running, then stop and restart `k3s`.

```bash
sudo systemctl stop k3s.service

sudo systemctl start k3s.service
```

You should see [`DecryptRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#DecryptRequest) in the `k8s-kms-plugin` logs.
This means `k3s` wants to decrypt the DEK Seed with the KEK.

You will also see `EncryptRequest` (with a fresh new DEK seed) and `StatusRequest` in the `k8s-kms-plugin` logs.
This is an assumption: the `EncryptRequest` is sent because kubernetes expects a key rotation after a reboot, or maybe
the DEK seed is renewed at each new restart.

### Perform a Key Rotation Operation

From the point of view of the `k8s-kms-plugin`, the key rotation operation is handled by [`k8s-kms-plugin serve rotation`](../cli-user-interface/markdown/k8s-kms-plugin_serve_rotation.md).

`k8s-kms-plugin serve rotation` allows the `k8s-kms-plugin` to access both an **active KEK key** (the new current key)
and an **old KEK key** (the key being rotated and replaced).

While in rotation mode, the `k8s-kms-plugin` will support [`DecryptRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#DecryptRequest)
for both the active and old KEK keys. But `k8s-kms-plugin` will only support
[`StatusRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#StatusRequest) and [`EncryptRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#EncryptRequest)
for the active KEK key. This prevent new kubernetes content from being encrypted with the old KEK key while allwoing
to decrypt the older kubernetes content which will be re-encrypted with the new active KEK key.

## k3s High Availability Embedded etcd

> HA means High Availability

The `k8s-kms-plugin` also supports kubernetes cluster in HA mode (at least 3 server nodes), as long as the KEK is the same for each kubernetes node in the HA cluster. Otherwise it will fail to work with the Raft consensus algorithm for the synchronization of the content of the etcd cluster.

![](../images/k8s-kms-plugin-TPM_3_master_nodes.svg)
![](../images/k8s-kms-plugin-USB_HSM_3_master_nodes.svg)
![](../images/k8s-kms-plugin-Net_HSM_3_master_nodes.svg)



A minimal [`k3s` HA cluster](https://docs.k3s.io/datastore/ha-embedded) is composed of 3 `k3s` server nodes like below:

| **`k3s` Server Node** | **IP Address** |
|-----------------------|----------------|
| k3sserver1            | 192.168.122.11 |
| k3sserver2            | 192.168.122.12 |
| k3sserver3            | 192.168.122.13 |

For the kms provider to work with an HA cluster, the following requirements must be met:

-  All 3 `k3s` Server Nodes must use the same KEK Key 🔑. Ohterwise, this messes with the RAFT etcd synchronizing among all the `k3s` Server Nodes.
- Each `k3s` Server Node runs its own instance of `k8s-kms-plugin serve` to serve the KMS v2 requests. And each `k8s-kms-plugin` must use the same KEK Key 🔑. Other than that, `k8s-kms-plugin serve` runs similar to when it is a single node cluster.

The first `k3s` server node initializes the HA cluster thanks to `--cluster-init`:

```bash {hl_lines=[2]}
curl -sfL https://get.k3s.io | K3S_TOKEN="servertoken" K3S_DEBUG=true INSTALL_K3S_VERSION=v1.33.1+k3s1 sh -s - \
  --cluster-init \
  --disable traefik \
  --write-kubeconfig-mode 660 \
  --kube-apiserver-arg=encryption-provider-config=/home/core/k8s-kms-plugin/deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml
```

Second and Third server node joins the existing cluster with the following command:

```bash {hl_lines=[2]}
curl -sfL https://get.k3s.io | K3S_TOKEN="servertoken" K3S_DEBUG=true INSTALL_K3S_VERSION=v1.33.1+k3s1 sh -s - \
  --server https://192.168.122.11:6443 \
  --write-kubeconfig-mode 660 \
  --kube-apiserver-arg=encryption-provider-config=/home/core/k8s-kms-plugin/deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml
```

Verify that the content of the `etcd` database is encrypted with [`etcdctl`](https://github.com/etcd-io/etcd/tree/main/etcdctl).

```bash
sudo etcdctl --endpoints=https://127.0.0.1:2379 \
    --cert=/var/lib/rancher/k3s/server/tls/etcd/server-client.crt \
    --key=/var/lib/rancher/k3s/server/tls/etcd/server-client.key \
    --cacert=/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt \
    get /registry/secrets/default/secretafterha | head -n 2
```

```
/registry/secrets/default/secretafterha
k8s:enc:kms:v2:kms-server:
```

Look for the `k8s:enc:kms:v2:kms-server:` prefix which means the data is encrypted inside the etcd database.

Now you can try to stop one node, or to stop one k8s-kms-plugin instance, and see how the HA cluster recovers.