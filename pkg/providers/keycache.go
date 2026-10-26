// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package providers

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/eclipse-keypont/crypto11/v2"
)

// The KEK (and, for aes-cbc, the HMAC key) a request needs is fixed for the life of the
// process: NewP11 pins the CKA_ID and CKA_LABEL, and Decrypt only accepts the active or the
// old KEK's ID. Resolving it is a C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal
// sequence plus attribute reads, more for a key pair, and on a network HSM each of those is a
// round trip. So a key is resolved on the first request that needs it and the crypto11 object
// is reused from then on; crypto11 key objects are safe for concurrent use.
//
// Only keys whose every use is an operation on the token are cached: if the key behind a
// cached handle is deleted or replaced, that operation fails and withKey resolves the key
// again. rsa-oaep encryption, which uses only the public key and only in software, keeps its
// lookup on every request.

// keyKind is the kind of crypto11 object a lookup returns.
type keyKind uint8

const (
	kindSecretKey keyKind = iota
	kindRSAKeyPair
	kindMLKEMKeyPair
)

// keyRef identifies a lookup exactly as it is made on the token: the context, the kind of
// object and the CKA_ID / CKA_LABEL arguments. A nil argument (not searched on) is kept apart
// from an empty one, because crypto11 searches on an empty value.
type keyRef struct {
	ctx      *crypto11.Context
	kind     keyKind
	id       string
	hasID    bool
	label    string
	hasLabel bool
}

func newKeyRef(ctx *crypto11.Context, kind keyKind, id, label []byte) keyRef {
	return keyRef{ctx: ctx, kind: kind, id: string(id), hasID: id != nil, label: string(label), hasLabel: label != nil}
}

// secretKey returns the cache entry and the token lookup for ctx.FindKey(id, label).
func secretKey(ctx *crypto11.Context, id, label []byte) (keyRef, func() (*crypto11.SecretKey, error)) {
	return newKeyRef(ctx, kindSecretKey, id, label), func() (*crypto11.SecretKey, error) { return ctx.FindKey(id, label) }
}

// rsaKeyPair returns the cache entry and the token lookup for ctx.FindRSAKeyPair(id, label).
func rsaKeyPair(ctx *crypto11.Context, id, label []byte) (keyRef, func() (crypto11.SignerDecrypter, error)) {
	return newKeyRef(ctx, kindRSAKeyPair, id, label), func() (crypto11.SignerDecrypter, error) { return ctx.FindRSAKeyPair(id, label) }
}

// mlkemKeyPair returns the cache entry and the token lookup for ctx.FindMLKEMKeyPair(id, label).
func mlkemKeyPair(ctx *crypto11.Context, id, label []byte) (keyRef, func() (crypto11.MLKEMKeyPair, error)) {
	return newKeyRef(ctx, kindMLKEMKeyPair, id, label), func() (crypto11.MLKEMKeyPair, error) { return ctx.FindMLKEMKeyPair(id, label) }
}

// cachedKey returns the key ref resolves to, calling find only when it is not cached yet.
// cached reports whether the key came from the cache rather than from find.
func cachedKey[K any](p *P11, ref keyRef, find func() (K, error)) (key K, cached bool, err error) {
	p.mu.RLock()
	v, ok := p.keys[ref]
	p.mu.RUnlock()
	if ok {
		if key, ok = v.(K); ok {
			return key, true, nil
		}
	}

	if key, err = find(); err != nil {
		return key, false, err
	}
	p.mu.Lock()
	if p.keys == nil {
		p.keys = make(map[keyRef]any)
	}
	p.keys[ref] = key
	p.mu.Unlock()
	return key, false, nil
}

// logLookup wraps find so that a failed lookup is logged with msg and args.
func logLookup[K any](find func() (K, error), msg string, args ...any) func() (K, error) {
	return func() (K, error) {
		key, err := find()
		if err != nil {
			slog.With(args...).Error(msg, "error", err)
		}
		return key, err
	}
}

// forgetKey drops ref from the cache, so that the next request resolves it on the token again.
func (p *P11) forgetKey(ref keyRef) {
	p.mu.Lock()
	delete(p.keys, ref)
	p.mu.Unlock()
}

// errKeyOperationPanicked wraps a panic raised while using a key. cipher.AEAD.Seal has no
// error return, so crypto11's GCM AEAD reports a token failure by panicking.
var errKeyOperationPanicked = errors.New("operation with HSM key panicked")

// withKey runs op with the key ref resolves to.
//
// If op fails, the key is dropped from the cache. If it had come from the cache, op is
// retried once with a key resolved afresh: a cached handle goes stale when the key is
// deleted and re-created under the same CKA_ID, or the token is re-initialised, and a lookup
// on every request used to absorb that. A failure with a freshly resolved key is returned
// as is.
func withKey[K any](p *P11, ref keyRef, find func() (K, error), op func(K) error) error {
	key, cached, err := cachedKey(p, ref, find)
	if err != nil {
		return err
	}
	if err = runKeyOp(key, op); err == nil {
		return nil
	}
	p.forgetKey(ref)
	if !cached {
		return err
	}

	slog.Debug("operation with a cached HSM key failed; resolving the key again and retrying once", "error", err)
	if key, _, err = cachedKey(p, ref, find); err != nil {
		return err
	}
	if err = runKeyOp(key, op); err != nil {
		p.forgetKey(ref)
	}
	return err
}

// runKeyOp calls op and turns a panic into an error.
func runKeyOp[K any](key K, op func(K) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = fmt.Errorf("%w: %w", errKeyOperationPanicked, e)
			} else {
				err = fmt.Errorf("%w: %v", errKeyOperationPanicked, r)
			}
		}
	}()
	return op(key)
}
