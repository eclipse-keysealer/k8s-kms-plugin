// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package providers

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKey stands in for a crypto11 key object; generation tells lookups apart.
type fakeKey struct{ generation int64 }

// fakeToken counts lookups and hands out a new key generation on each one.
type fakeToken struct {
	lookups atomic.Int64
	err     error
}

func (f *fakeToken) find() (*fakeKey, error) {
	n := f.lookups.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return &fakeKey{generation: n}, nil
}

func testRef(id string) keyRef {
	return newKeyRef(nil, kindSecretKey, []byte(id), nil)
}

func TestWithKey_ResolvesOnce(t *testing.T) {
	p := &P11{}
	tok := &fakeToken{}
	ref := testRef("01")

	for range 10 {
		require.NoError(t, withKey(p, ref, tok.find, func(k *fakeKey) error {
			assert.Equal(t, int64(1), k.generation)
			return nil
		}))
	}
	assert.Equal(t, int64(1), tok.lookups.Load(), "the key is looked up on the token once")
}

func TestWithKey_LookupErrorIsNotCached(t *testing.T) {
	p := &P11{}
	notFound := errors.New("key not found")
	tok := &fakeToken{err: notFound}
	ref := testRef("01")

	ran := false
	err := withKey(p, ref, tok.find, func(*fakeKey) error { ran = true; return nil })
	require.ErrorIs(t, err, notFound)
	assert.False(t, ran, "op does not run without a key")

	tok.err = nil
	require.NoError(t, withKey(p, ref, tok.find, func(*fakeKey) error { return nil }))
	assert.Equal(t, int64(2), tok.lookups.Load(), "a failed lookup is retried on the next request")
}

func TestWithKey_StaleCachedKeyIsResolvedAgainAndRetried(t *testing.T) {
	p := &P11{}
	tok := &fakeToken{}
	ref := testRef("01")
	require.NoError(t, withKey(p, ref, tok.find, func(*fakeKey) error { return nil }))

	// The cached generation-1 handle has gone stale: only a key from a new lookup works.
	stale := errors.New("CKR_KEY_HANDLE_INVALID")
	var seen []int64
	err := withKey(p, ref, tok.find, func(k *fakeKey) error {
		seen = append(seen, k.generation)
		if k.generation == 1 {
			return stale
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []int64{1, 2}, seen, "op is retried once, with a key resolved afresh")

	// The fresh key replaces the stale one in the cache.
	require.NoError(t, withKey(p, ref, tok.find, func(k *fakeKey) error {
		assert.Equal(t, int64(2), k.generation)
		return nil
	}))
	assert.Equal(t, int64(2), tok.lookups.Load())
}

func TestWithKey_FreshKeyFailureIsNotRetried(t *testing.T) {
	p := &P11{}
	tok := &fakeToken{}
	ref := testRef("01")
	bad := errors.New("authentication failed")

	calls := 0
	err := withKey(p, ref, tok.find, func(*fakeKey) error { calls++; return bad })
	require.ErrorIs(t, err, bad)
	assert.Equal(t, 1, calls, "a key that was just resolved is not resolved again for the same request")

	// The failure still drops the key, so the next request looks it up again.
	require.NoError(t, withKey(p, ref, tok.find, func(*fakeKey) error { return nil }))
	assert.Equal(t, int64(2), tok.lookups.Load())
}

func TestWithKey_RetryFailureIsReturned(t *testing.T) {
	p := &P11{}
	tok := &fakeToken{}
	ref := testRef("01")
	require.NoError(t, withKey(p, ref, tok.find, func(*fakeKey) error { return nil }))

	bad := errors.New("bad ciphertext")
	calls := 0
	err := withKey(p, ref, tok.find, func(*fakeKey) error { calls++; return bad })
	require.ErrorIs(t, err, bad)
	assert.Equal(t, 2, calls, "one retry, no more")

	p.mu.RLock()
	_, cached := p.keys[ref]
	p.mu.RUnlock()
	assert.False(t, cached, "a key that failed twice is not kept")
}

func TestWithKey_PanicBecomesError(t *testing.T) {
	tokenErr := errors.New("C_Encrypt: CKR_DEVICE_ERROR")
	for name, tc := range map[string]struct {
		value any
		cause error
	}{
		"error":  {value: tokenErr, cause: tokenErr},
		"string": {value: "boom"},
	} {
		t.Run(name, func(t *testing.T) {
			p := &P11{}
			tok := &fakeToken{}
			var err error
			require.NotPanics(t, func() {
				err = withKey(p, testRef("01"), tok.find, func(*fakeKey) error { panic(tc.value) })
			})
			require.ErrorIs(t, err, errKeyOperationPanicked)
			if tc.cause != nil {
				assert.ErrorIs(t, err, tc.cause)
			}
		})
	}
}

func TestKeyRef_DistinguishesLookups(t *testing.T) {
	refs := []keyRef{
		newKeyRef(nil, kindSecretKey, []byte{0x01}, nil),
		newKeyRef(nil, kindSecretKey, []byte{0x01}, []byte{}),
		newKeyRef(nil, kindSecretKey, []byte{0x01}, []byte("kek")),
		newKeyRef(nil, kindSecretKey, []byte{0x02}, nil),
		newKeyRef(nil, kindSecretKey, nil, []byte("kek")),
		newKeyRef(nil, kindSecretKey, []byte{}, []byte("kek")),
		newKeyRef(nil, kindRSAKeyPair, []byte{0x01}, nil),
		newKeyRef(nil, kindMLKEMKeyPair, []byte{0x01}, nil),
	}
	seen := map[keyRef]int{}
	for i, r := range refs {
		if j, dup := seen[r]; dup {
			t.Errorf("lookups %d and %d share a cache entry", j, i)
		}
		seen[r] = i
	}
	assert.Equal(t, newKeyRef(nil, kindSecretKey, []byte{0x01}, []byte("kek")),
		newKeyRef(nil, kindSecretKey, []byte{0x01}, []byte("kek")), "the same lookup maps to the same entry")
}

func TestWithKey_ConcurrentUse(t *testing.T) {
	p := &P11{}
	tok := &fakeToken{}
	refs := []keyRef{testRef("01"), testRef("02")}

	var wg sync.WaitGroup
	for i := range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ref := refs[i%len(refs)]
			_ = withKey(p, ref, tok.find, func(*fakeKey) error {
				if i%17 == 0 {
					return errors.New("transient")
				}
				return nil
			})
		}()
	}
	wg.Wait()
	assert.LessOrEqual(t, len(p.keys), len(refs))
}
