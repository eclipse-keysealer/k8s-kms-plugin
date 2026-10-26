---
title: "Glossary"
weight: 95
layout: glossary
---

<!-- GENERATED FILE — DO NOT EDIT.
     Source: docs/termbase.yaml. Regenerate with `make glossary`.
     The published site renders this page from the same YAML through Hextra's glossary layout;
     the table below is what GitHub shows. -->

Terms used across this documentation. The source is
[`docs/termbase.yaml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/docs/termbase.yaml);
this page is generated from it by `make glossary`.

| Term | Definition |
|------|------------|
| **Additional Authenticated Data (AAD)** | Data covered by an AEAD authentication tag but not encrypted by it. The ml-kem family puts a version string and the KEM ciphertext there, which is what stops an attacker swapping the annotation. |
| **Advanced Encryption Standard (AES)** | The block cipher behind the aes-gcm and aes-cbc families, and the one used to seal the seed in the ml-kem hybrid. |
| **Algorithm family** | The wrapping scheme the plugin uses, chosen with --algorithm-family. One of aes-gcm, aes-cbc, rsa-oaep or ml-kem. Key size and parameter set are not configured, they are read from the key on the token. |
| **Annotations** | An opaque map of small values that KMS v2 stores next to a ciphertext and hands back on decryption. The ml-kem family uses it to carry the KEM ciphertext; the budget is shared across all annotations, keys included. |
| **Authenticated Encryption with Associated Data (AEAD)** | Encryption that also detects tampering, and can bind unencrypted context into that guarantee. AES-GCM is the AEAD used here. |
| **cgo** | The Go facility for calling C code. The PKCS #11 bindings need it, so CGO_ENABLED=1 is required for every build and test of this project. |
| **CKA_ID** | The PKCS #11 attribute holding a key identifier, raw bytes on the token but a hex string everywhere in this plugin. It is what KMS v2 reports as key_id and what etcd stores alongside every ciphertext. |
| **CKA_LABEL** | The PKCS #11 attribute holding a human-readable key name. Selecting a key by label still requires the key to carry a CKA_ID, because that is what gets recorded in etcd. |
| **Data Encryption Key (DEK)** | The symmetric key that actually encrypts a Kubernetes object. It is derived and cached inside kube-apiserver and never reaches the plugin. |
| **Decapsulation key (dk)** | In ML-KEM, the key used to recover the shared secret. The classical analogue is a private key, and it never leaves the HSM. |
| **DEK seed** | The 32 bytes of key material kube-apiserver sends in an EncryptRequest and from which it derives the DEK. It is the only plaintext this plugin ever handles. |
| **Encapsulation key (ek)** | In ML-KEM, the key used to encapsulate. The classical analogue is a public key. |
| **EncryptionConfiguration** | The Kubernetes API server configuration file that names which resources to encrypt and which provider to use. It carries the plugin socket path and is passed with --encryption-provider-config. |
| **Envelope encryption** | Encrypting data with a data key, then encrypting that data key with a second key held somewhere safer. Kubernetes KMS v2 is an envelope scheme, and this plugin performs only the second step. |
| **etcd** | The key-value store holding Kubernetes cluster state. It is what an attacker reads from a stolen disk or backup, and therefore what encryption at rest protects. |
| **FIPS 203** | The NIST standard defining ML-KEM. This project follows its vocabulary, so encapsulation key rather than public key. |
| **gRPC** | The RPC framework KMS v2 is defined in. This plugin serves it over a unix socket only, since that is all KMS v2 supports. |
| **grpcurl** | A command-line gRPC client. The scripts under scripts/grpcurl use it to exercise Status, Encrypt and Decrypt without a cluster. |
| **Hardware Security Module (HSM)** | A dedicated device that stores keys and performs cryptographic operations without ever exporting the private key material. |
| **Hash-based Message Authentication Code (HMAC)** | A keyed integrity tag. The aes-cbc family needs a separate HMAC key because CBC alone is not authenticated. |
| **High Availability (HA)** | A cluster with several control-plane nodes. Each node runs its own plugin instance, and all of them must use the same KEK. |
| **Initialisation vector (IV)** | The per-message random block a CBC-mode cipher starts from. Sixteen bytes for AES-CBC, and it is stored in the JWE. |
| **JSON Object Signing and Encryption (JOSE)** | The family of IETF standards for representing keys, signatures and encrypted data as JSON. The gose library implements it for this plugin. |
| **JSON Web Encryption (JWE)** | The JOSE format for encrypted content, defined in RFC 7516. The aes-gcm, aes-cbc and rsa-oaep families each emit one as their ciphertext; ml-kem does not. |
| **k3s** | A single-binary Kubernetes distribution that runs kube-apiserver as an ordinary host process, so it reaches the plugin socket directly. |
| **KEM ciphertext** | FIPS 203's c, the output of encapsulation, from 768 to 1568 bytes depending on parameter set. It travels in the kem-ciphertext annotation, never in EncryptResponse.ciphertext. |
| **Key Encapsulation Mechanism (KEM)** | A public-key primitive that generates a fresh shared secret and a ciphertext carrying it, rather than encrypting a chosen message. It takes no plaintext, which is why ml-kem has to be combined with an AEAD. |
| **Key Encryption Key (KEK)** | The long-lived key that wraps the DEK seed. It lives on the TPM or HSM, is selected with --p11-key-label or --p11-key-id, and never leaves the token. |
| **Key Management Service (KMS)** | In Kubernetes, the provider interface kube-apiserver uses to delegate wrapping of data encryption keys to an external process. This plugin implements its version 2. |
| **Key rotation** | Moving from one KEK to another without losing access to data already written. The serve rotation subcommand serves a new KEK while still decrypting under the previous one, routing each request by its key_id. |
| **KMAC** | The keyed hash function from NIST SP 800-185 used to derive the AES key from the ML-KEM shared secret. The parameter set name goes into its context string, so keys from different parameter sets cannot collide. |
| **KMS v2** | The second version of the Kubernetes KMS provider API, the only one this plugin implements. It is a gRPC service over a local unix socket with three RPCs, Status, Encrypt and Decrypt. |
| **kube-apiserver** | The Kubernetes control-plane component that talks to the plugin. It derives and caches DEKs, encrypts the objects itself, and asks the plugin only to wrap the DEK seed. |
| **Kubernetes (k8s)** | The container orchestrator whose API server calls this plugin to protect Secrets at rest. |
| **Kubernetes in Docker (KinD)** | A local Kubernetes distribution that runs each node as a container. The socket needs two bind-mount hops to reach kube-apiserver, which is why it takes more wiring than k3s. |
| **Mechanism** | In PKCS #11, the algorithm a key may be used with. It has to match the algorithm family the plugin is started with. |
| **Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)** | The post-quantum KEM standardised in FIPS 203, derived from CRYSTALS-Kyber. Available in three parameter sets, and the only family here that is not a JWE. |
| **Nonce** | A number used once. Every AES-GCM wrap takes a fresh one: 16 bytes in aes-gcm (generated by the HSM for luna and dpod, drawn from the HSM random generator otherwise), 12 bytes in ml-kem (HSM random generator) and in rsa-oaep (the operating system random generator, like the content encryption key). |
| **Optimal Asymmetric Encryption Padding (OAEP)** | The padding scheme that makes RSA encryption safe. This plugin uses it with SHA-256. |
| **Parameter set** | For ML-KEM, the size variant of the scheme: ML-KEM-512, ML-KEM-768 or ML-KEM-1024. It is read from the key on the token, never configured on the command line. |
| **PIN** | The secret that unlocks a PKCS #11 token. Enough failed attempts erase it, which is why the plugin sleeps indefinitely instead of exiting on an authentication error. |
| **Provenance** | A signed statement about how an artifact was built: which source, which builder, which workflow run. It is what lets you verify a binary came from this repository. |
| **Public-Key Cryptography Standards #11 (PKCS #11)** | The OASIS C API for talking to cryptographic tokens. Every key operation in this plugin goes through it, which is also why the build needs cgo. |
| **Secret** | The Kubernetes object type most often encrypted at rest. The plugin never sees its contents. |
| **Shared secret key (K)** | The 32 bytes both encapsulation and decapsulation produce. The plugin derives an AES key from it with KMAC rather than using it directly. |
| **Slot** | In PKCS #11, the numbered position a token sits in. Only needed when a label does not identify a single token. |
| **SoftHSM** | A software PKCS #11 token used for development and testing. Version 3 is required for ml-kem because it implements PKCS #11 v3.2; version 2 covers the AES and RSA families. |
| **Software Bill of Materials (SBOM)** | An inventory of everything that went into a build. A full nested SBOM is planned but not published yet. |
| **Supply-chain Levels for Software Artifacts (SLSA)** | A framework for describing how trustworthy a build is. Releases here ship SLSA provenance that can be checked with slsa-verifier. |
| **Token** | In PKCS #11, the object that holds keys, identified by its label. One HSM or TPM may present several. |
| **Trusted Platform Module (TPM)** | A cryptographic chip built into most machines. Exposed through a PKCS #11 module, it can hold the KEK without any extra hardware. |
