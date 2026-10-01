package radius

// Regression test for go-auth#53: TestTLSPacketExchangerContextCancel failed
// on main under -race with "expected context canceled, got EOF".
//
// context cancels a parent by closing the parent's Done channel BEFORE it
// propagates to the children. exchange derives its own context from the
// caller's, so a peer that reacts to the caller's cancellation and closes the
// connection could make Read fail while the derived context still read as
// live, and the caller was told EOF instead of context.Canceled.
//
// That losing order is reproduced deterministically here rather than left to
// the scheduler: context.WithCancel hands a parent that implements AfterFunc
// the child's cancel function, and withheldCancelCtx simply does not call it
// until the exchange has returned.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"

	radiuslib "layeh.com/radius"
)

// withheldCancelCtx is a cancellable context that defers propagating its
// cancelation to derived contexts until release is called.
type withheldCancelCtx struct {
	context.Context
	done chan struct{}

	mu      sync.Mutex
	err     error
	pending []func()
}

func newWithheldCancelCtx() *withheldCancelCtx {
	return &withheldCancelCtx{Context: context.Background(), done: make(chan struct{})}
}

func (c *withheldCancelCtx) Done() <-chan struct{} { return c.done }

func (c *withheldCancelCtx) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// AfterFunc makes context.WithCancel register the child's cancel here instead
// of propagating it itself.
func (c *withheldCancelCtx) AfterFunc(f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = append(c.pending, f)
	return func() bool { return false }
}

// cancel cancels this context without propagating to its children.
func (c *withheldCancelCtx) cancel() {
	c.mu.Lock()
	c.err = context.Canceled
	c.mu.Unlock()
	close(c.done)
}

// release propagates the withheld cancellation to the children.
func (c *withheldCancelCtx) release() {
	c.mu.Lock()
	pending := c.pending
	c.pending = nil
	c.mu.Unlock()
	for _, f := range pending {
		f()
	}
}

// closeOnCancelDialer is a peer that reads the request, then closes the
// connection as soon as the caller's context is canceled.
type closeOnCancelDialer struct {
	requestRead chan struct{}
}

func (d *closeOnCancelDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buf := make([]byte, radiuslib.MaxPacketLength)
		if _, err := server.Read(buf); err != nil {
			return
		}
		close(d.requestRead)
		<-ctx.Done()
	}()
	return client, nil
}

func TestTLSPacketExchangerReportsCancellationWhenPeerClosesFirst(t *testing.T) {
	skipUnderFIPSActivation(t)
	dialer := &closeOnCancelDialer{requestRead: make(chan struct{})}
	auth, err := NewAuthenticator(
		"127.0.0.1:2083",
		sealed(t, "shared"),
		WithTLSConfig(&tls.Config{}),
		WithTLSDialer(dialer),
	)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	ctx := newWithheldCancelCtx()
	t.Cleanup(ctx.release)
	go func() {
		<-dialer.requestRead
		ctx.cancel()
	}()

	err = auth.Authenticate(ctx, "user", sealed(t, "password"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Authenticate after cancellation = %v, want context.Canceled", err)
	}
}
