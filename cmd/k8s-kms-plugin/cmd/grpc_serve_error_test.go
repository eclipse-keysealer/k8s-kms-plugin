// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// permanentErrListener always fails Accept with a non-temporary error, like a listener
// whose socket has gone away.
type permanentErrListener struct {
	mu     sync.Mutex
	calls  int
	closed bool
}

func (l *permanentErrListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.calls++
	l.mu.Unlock()
	return nil, net.ErrClosed
}

func (l *permanentErrListener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return nil
}

func (l *permanentErrListener) Addr() net.Addr { return &net.UnixAddr{Name: "test", Net: "unix"} }

// grpcServe must return when the listener fails permanently, rather than looping back into
// Serve on the now-closed listener and spinning.
func TestGrpcServe_ReturnsOnPermanentListenerError(t *testing.T) {
	l := &permanentErrListener{}

	done := make(chan error, 1)
	go func() { done <- grpcServe(l, &stubProvider{}) }()

	select {
	case err := <-done:
		require.Error(t, err, "grpcServe should surface the listener error")
	case <-time.After(5 * time.Second):
		l.mu.Lock()
		calls := l.calls
		l.mu.Unlock()
		t.Fatalf("grpcServe did not return; it is spinning on a dead listener (%d Accept calls)", calls)
	}
}
