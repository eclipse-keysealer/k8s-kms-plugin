// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package providers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"

	"github.com/eclipse-keypont/crypto11/v2"
	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	k8skmsv2 "k8s.io/kms/apis/v2"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/logging"
)

const (
	// KemCiphertextAnnotationKey is the KMS v2 EncryptResponse.Annotations / DecryptRequest.Annotations
	// key under which the ML-KEM ciphertext travels — "(KEM) ciphertext" is the term FIPS 203
	// defines in its Terms and Definitions for the value ML-KEM.Encaps produces alongside the
	// shared secret key (Algorithm 20, output c). The apiserver round-trips annotations verbatim
	// from Encrypt to the matching Decrypt, so this is the channel that carries c across the two
	// RPCs. It must be a valid RFC 1123 DNS subdomain per the KMS v2 API contract. Access it only
	// via putEncapsulation / getEncapsulation so a future move to a dedicated EncryptResponse
	// field is a one-line change.
	KemCiphertextAnnotationKey = "kem-ciphertext.k8s-kms-plugin.keysealer.eclipse.org"

	// mlkemNonceSize is the AES-GCM nonce length used in the ML-KEM ciphertext binary layout:
	// nonce (mlkemNonceSize bytes) || AES-GCM-Seal-output (encrypted DEK seed || 16-byte tag).
	mlkemNonceSize = 12

	// mlkemAADContext domain-separates this envelope format inside the AES-GCM additional
	// authenticated data. Bump the version suffix on any change to the ML-KEM binary layout,
	// the KDF, or the set of fields mlkemAAD covers: an envelope sealed under one context
	// string cannot be opened under another, which turns a silent format mismatch into a
	// clean authentication failure.
	mlkemAADContext = "k8s-kms-plugin/ml-kem/v1"
)

// mlkemAAD returns the additional authenticated data bound into the ML-KEM envelope's AES-GCM
// tag. AAD is authenticated but not encrypted: AES-GCM covers it by the tag, so Open only
// succeeds when it is reproduced byte for byte.
//
// Binding the KEM ciphertext here makes "this envelope goes with this KEM ciphertext" a
// property of the format rather than a side effect. The two are already bound in practice —
// a substituted kemCt makes Decapsulate return a different shared secret (FIPS 203 uses
// implicit rejection rather than signalling failure), which derives a different key and fails
// the tag check — but that holds only because the KEM ciphertext happens to be the sole
// annotation feeding the KDF. Any future annotation that influences decryption would not be
// covered unless it is added here.
//
// kemCt is round-tripped verbatim by the apiserver, so both sides reproduce these bytes
// exactly. It is the last field, so no length prefix is needed to keep the encoding
// unambiguous; if another field is ever appended, length-prefix each one and bump
// mlkemAADContext.
func mlkemAAD(kemCt []byte) []byte {
	aad := make([]byte, 0, len(mlkemAADContext)+len(kemCt))
	aad = append(aad, mlkemAADContext...)
	return append(aad, kemCt...)
}

// formatMLKEMEnvelope lays out an ML-KEM ciphertext as nonce || sealed, where sealed is the
// AES-GCM output (encrypted DEK seed || 16-byte tag). It is the inverse of parseMLKEMEnvelope.
func formatMLKEMEnvelope(nonce, sealed []byte) []byte {
	envelope := make([]byte, 0, len(nonce)+len(sealed))
	envelope = append(envelope, nonce...)
	return append(envelope, sealed...)
}

// parseMLKEMEnvelope splits a DecryptRequest ciphertext into its nonce and AES-GCM portions.
//
// This is the first thing the ML-KEM path does with attacker-reachable bytes, before any key
// material has authenticated them, so it is kept free of HSM calls: it is pure, and therefore
// directly fuzzable (see FuzzParseMLKEMEnvelope).
//
// The returned slices alias envelope; callers must not modify them.
func parseMLKEMEnvelope(envelope []byte) (nonce, sealed []byte, err error) {
	if len(envelope) < mlkemNonceSize {
		return nil, nil, fmt.Errorf("ciphertext too short: got %d bytes, need at least %d", len(envelope), mlkemNonceSize)
	}
	return envelope[:mlkemNonceSize], envelope[mlkemNonceSize:], nil
}

// putEncapsulation places the ML-KEM encapsulation ciphertext into resp.Annotations.
func putEncapsulation(resp *k8skmsv2.EncryptResponse, ct []byte) {
	if resp.Annotations == nil {
		resp.Annotations = map[string][]byte{}
	}
	resp.Annotations[KemCiphertextAnnotationKey] = ct
}

// getEncapsulation retrieves the ML-KEM encapsulation ciphertext from req.Annotations.
// ok is false if the request carries no kem-ciphertext annotation, i.e. it was not produced by the
// ML-KEM path.
func getEncapsulation(req *k8skmsv2.DecryptRequest) (ct []byte, ok bool) {
	ct, ok = req.GetAnnotations()[KemCiphertextAnnotationKey]
	return ct, ok
}

// destroySharedSecret releases the transient shared-secret key object that Encapsulate or
// Decapsulate created on the token.
//
// Failing to destroy it is not worth failing the RPC over — the crypto has already
// succeeded and the seed is wrapped — but it must not pass silently either: the objects
// accumulate on the token for as long as the session lives, so the log line is how an
// operator finds out before the token fills up.
func destroySharedSecret(ss *crypto11.MLKEMSharedSecret, op, uid string) {
	if ss == nil {
		return
	}
	if err := ss.Delete(); err != nil {
		slog.Warn("failed to destroy ML-KEM shared-secret object on the token; objects will accumulate until the session closes",
			"op", op, "uid", uid, "error", err)
	}
}

// mlkemSharedSecretTemplate returns the PKCS#11 attribute template used when deriving an
// ML-KEM shared secret on the HSM: a transient (non-token) AES-256 session object with
// CKA_EXTRACTABLE=true, so Bytes() can retrieve the raw shared secret for
// crypto11.MLKEMDeriveKey.
func mlkemSharedSecretTemplate() crypto11.AttributeSet {
	a := crypto11.NewAttributeSet()
	_ = a.Set(crypto11.CkaClass, pkcs11.CKO_SECRET_KEY)
	_ = a.Set(crypto11.CkaKeyType, pkcs11.CKK_AES)
	_ = a.Set(crypto11.CkaValueLen, 32)
	_ = a.Set(crypto11.CkaToken, false)
	_ = a.Set(crypto11.CkaSensitive, false)
	_ = a.Set(crypto11.CkaExtractable, true)
	return a
}

// encryptMLKEM encrypts req.Plaintext (the DEK seed) for the ML-KEM algorithm family.
//
// Unlike the other algorithm families, the output is not a JWE: ML-KEM is a Key
// Encapsulation Mechanism, so it produces two artifacts — the KEM ciphertext (key
// establishment material, no payload) and the AEAD-wrapped seed (the actual encrypted
// data) — which are placed in the two fields the KMS v2 API already provides for them:
// the KEM ciphertext goes to EncryptResponse.Annotations (via putEncapsulation) and the
// AEAD-wrapped seed goes to EncryptResponse.Ciphertext. This keeps Ciphertext at ~60 bytes,
// well under the KMS v2 1 kB limit, where a JWE compact serialization would not fit for
// ML-KEM-768/1024. The HSM performs the KEM encapsulation; the shared secret is extracted
// and passed through crypto11.MLKEMDeriveKey's KMAC KDF to derive the AES key.
func (p *P11) encryptMLKEM(ctx context.Context, req *k8skmsv2.EncryptRequest) (*k8skmsv2.EncryptResponse, error) {
	var (
		kp    crypto11.MLKEMKeyPair
		kemCt []byte
		ss    *crypto11.MLKEMSharedSecret
	)
	ref, find := mlkemKeyPair(p.ctx, p.kekCkaID, p.GetKekCkaLabelByteA())
	err := withKey(p, ref, func() (crypto11.MLKEMKeyPair, error) {
		kp, err := find()
		if err != nil {
			slog.Error("encryptMLKEM: cannot find ML-KEM key pair", "uid", req.GetUid(), "label", p.kekCkaLabel, "keyId", p.GetKekKeyIDString(), "error", err)
			return nil, fmt.Errorf("encryptMLKEM: cannot find ML-KEM key pair (label=%s id=%x): %w", p.kekCkaLabel, p.kekCkaID, err)
		}
		return kp, nil
	}, func(k crypto11.MLKEMKeyPair) (err error) {
		if kemCt, ss, err = k.Encapsulate(mlkemSharedSecretTemplate()); err != nil {
			slog.Error("encryptMLKEM: encapsulation failed", "uid", req.GetUid(), "keyId", p.GetKekKeyIDString(), "error", err)
			return fmt.Errorf("encryptMLKEM: encapsulation failed: %w", err)
		}
		kp = k
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Encapsulate creates a key object on the token. It is a session object
	// (CKA_TOKEN=false in mlkemSharedSecretTemplate), so it would only be reclaimed when the
	// session closes — and this plugin holds its session for the lifetime of the process, so
	// one object would accumulate per Encrypt call until the token runs out of object slots.
	// Destroy it here: the raw secret has already been copied out by Bytes() below.
	defer destroySharedSecret(ss, "encryptMLKEM", req.GetUid())
	sharedSecret, err := ss.Bytes()
	if err != nil {
		slog.Error("encryptMLKEM: failed to extract shared secret", "uid", req.GetUid(), "keyId", p.GetKekKeyIDString(), "error", err)
		return nil, fmt.Errorf("encryptMLKEM: failed to extract shared secret: %w", err)
	}
	defer clear(sharedSecret)

	derivedKey, err := crypto11.MLKEMDeriveKey(kp.ParameterSet(), sharedSecret)
	if err != nil {
		slog.Error("encryptMLKEM: KDF failed", "uid", req.GetUid(), "keyId", p.GetKekKeyIDString(), "parameterSet", kp.ParameterSet(), "error", err)
		return nil, fmt.Errorf("encryptMLKEM: KDF failed: %w", err)
	}
	defer clear(derivedKey)

	rng, err := p.ctx.NewRandomReader()
	if err != nil {
		slog.Error("encryptMLKEM: cannot get HSM random reader", "uid", req.GetUid(), "error", err)
		return nil, fmt.Errorf("encryptMLKEM: cannot get HSM random reader: %w", err)
	}
	nonce := make([]byte, mlkemNonceSize)
	if _, err = io.ReadFull(rng, nonce); err != nil {
		slog.Error("encryptMLKEM: failed to generate nonce", "uid", req.GetUid(), "error", err)
		return nil, fmt.Errorf("encryptMLKEM: failed to generate nonce: %w", err)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		slog.Error("encryptMLKEM: failed to create AES cipher", "uid", req.GetUid(), "error", err)
		return nil, fmt.Errorf("encryptMLKEM: failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		slog.Error("encryptMLKEM: failed to create GCM", "uid", req.GetUid(), "error", err)
		return nil, fmt.Errorf("encryptMLKEM: failed to create GCM: %w", err)
	}
	// sealed = encrypted seed || 16-byte tag. The KEM ciphertext is bound in as AAD so the
	// annotation carrying it cannot be swapped without failing the tag check on Decrypt.
	sealed := aead.Seal(nil, nonce, req.GetPlaintext(), mlkemAAD(kemCt))

	envelope := formatMLKEMEnvelope(nonce, sealed)
	if err := validateEncryptResponseCiphertext(envelope); err != nil {
		slog.Error("encryptMLKEM: refusing to return a ciphertext the API server would reject",
			"uid", req.GetUid(), "ciphertextLen", len(envelope), "error", err)
		return nil, fmt.Errorf("encryptMLKEM: %w", err)
	}

	resp := &k8skmsv2.EncryptResponse{
		Ciphertext: envelope,
		KeyId:      p.GetKekKeyIDString(),
	}
	putEncapsulation(resp, kemCt)
	putAlgorithmFamily(resp, p.algorithmFamily)
	// The KEM ciphertext is the largest thing this plugin ever puts in annotations, so this is
	// the path where the shared budget could realistically be spent.
	if err := validateEncryptResponseAnnotations(resp.Annotations); err != nil {
		slog.Error("encryptMLKEM: refusing to return annotations the API server would reject",
			"uid", req.GetUid(), "annotationSizes", annotationSizes(resp.Annotations), "error", err)
		return nil, fmt.Errorf("encryptMLKEM: %w", err)
	}
	slog.Log(ctx, logging.LevelTrace, "encryptMLKEM: returning response", "ciphertextLen", len(resp.Ciphertext), "annotationSizes", annotationSizes(resp.Annotations))
	return resp, nil
}

// decryptMLKEMWithContext decrypts a binary envelope produced by encryptMLKEM using actualCtx.
// Supports both the active and rotation HSM contexts. The KEM ciphertext travels in
// req.Annotations (round-tripped verbatim by the apiserver from the matching Encrypt call);
// its absence means this object was not produced by the ML-KEM path.
func (p *P11) decryptMLKEMWithContext(req *k8skmsv2.DecryptRequest, actualCtx *crypto11.Context) ([]byte, error) {
	kemCt, ok := getEncapsulation(req)
	if !ok {
		slog.Error("decryptMLKEM: missing kem-ciphertext annotation on DecryptRequest", "uid", req.GetUid(), "keyId", req.GetKeyId(), "annotationKey", KemCiphertextAnnotationKey)
		return nil, fmt.Errorf("decryptMLKEM: missing %q annotation on DecryptRequest", KemCiphertextAnnotationKey)
	}

	reqKeyID, err := hex.DecodeString(req.GetKeyId())
	if err != nil {
		slog.Error("decryptMLKEM: invalid key_id hex", "uid", req.GetUid(), "keyId", req.GetKeyId(), "error", err)
		return nil, fmt.Errorf("decryptMLKEM: invalid key_id hex %q: %w", req.GetKeyId(), err)
	}
	var (
		kp crypto11.MLKEMKeyPair
		ss *crypto11.MLKEMSharedSecret
	)
	ref, find := mlkemKeyPair(actualCtx, reqKeyID, nil)
	err = withKey(p, ref, func() (crypto11.MLKEMKeyPair, error) {
		kp, err := find()
		if err != nil {
			slog.Error("decryptMLKEM: cannot resolve ML-KEM private key", "uid", req.GetUid(), "keyId", req.GetKeyId(), "error", err)
			return nil, fmt.Errorf("decryptMLKEM: cannot resolve ML-KEM private key (key_id=%s): %w", req.GetKeyId(), err)
		}
		return kp, nil
	}, func(k crypto11.MLKEMKeyPair) (err error) {
		if ss, err = k.Decapsulate(kemCt, mlkemSharedSecretTemplate()); err != nil {
			slog.Error("decryptMLKEM: decapsulation failed", "uid", req.GetUid(), "keyId", req.GetKeyId(), "error", err)
			return fmt.Errorf("decryptMLKEM: decapsulation failed: %w", err)
		}
		kp = k
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Same session object as in encryptMLKEM, released for the same reason.
	defer destroySharedSecret(ss, "decryptMLKEM", req.GetUid())
	sharedSecret, err := ss.Bytes()
	if err != nil {
		slog.Error("decryptMLKEM: failed to extract shared secret", "uid", req.GetUid(), "keyId", req.GetKeyId(), "error", err)
		return nil, fmt.Errorf("decryptMLKEM: failed to extract shared secret: %w", err)
	}
	defer clear(sharedSecret)

	derivedKey, err := crypto11.MLKEMDeriveKey(kp.ParameterSet(), sharedSecret)
	if err != nil {
		slog.Error("decryptMLKEM: KDF failed", "uid", req.GetUid(), "keyId", req.GetKeyId(), "parameterSet", kp.ParameterSet(), "error", err)
		return nil, fmt.Errorf("decryptMLKEM: KDF failed: %w", err)
	}
	defer clear(derivedKey)

	nonce, sealed, err := parseMLKEMEnvelope(req.GetCiphertext())
	if err != nil {
		slog.Error("decryptMLKEM: malformed envelope", "uid", req.GetUid(), "keyId", req.GetKeyId(), "gotBytes", len(req.GetCiphertext()), "minBytes", mlkemNonceSize, "error", err)
		return nil, fmt.Errorf("decryptMLKEM: %w", err)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		slog.Error("decryptMLKEM: failed to create AES cipher", "uid", req.GetUid(), "keyId", req.GetKeyId(), "error", err)
		return nil, fmt.Errorf("decryptMLKEM: failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		slog.Error("decryptMLKEM: failed to create GCM", "uid", req.GetUid(), "keyId", req.GetKeyId(), "error", err)
		return nil, fmt.Errorf("decryptMLKEM: failed to create GCM: %w", err)
	}
	// The AAD must match the one encryptMLKEM sealed under; a tampered or mismatched
	// kem-ciphertext annotation surfaces here as an authentication failure.
	plaintext, err := aead.Open(nil, nonce, sealed, mlkemAAD(kemCt))
	if err != nil {
		slog.Error("decryptMLKEM: authenticated decryption failed", "uid", req.GetUid(), "keyId", req.GetKeyId(), "error", err)
		return nil, fmt.Errorf("decryptMLKEM: authenticated decryption failed: %w", err)
	}
	return plaintext, nil
}
