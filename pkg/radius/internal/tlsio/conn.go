package tlsio

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Conn provides an in-memory net.Conn implementation backed by channels.
//
// It is primarily used to bridge the Go crypto/tls client handshake with the
// packet-oriented EAP-TLS transport. Writes performed by the TLS stack are
// published to the outbound queue for the caller to frame into EAP responses,
// while inbound TLS handshake bytes are injected by the caller for reads.
type Conn struct {
	outbound chan []byte
	inbound  chan []byte

	mu       sync.Mutex
	inBuf    []byte
	closed   chan struct{}
	closeErr error
	once     sync.Once
}

// NewConn returns a fresh in-memory TLS transport connection.
func NewConn(buffer int) *Conn {
	if buffer <= 0 {
		buffer = 4
	}
	return &Conn{
		outbound: make(chan []byte, buffer),
		inbound:  make(chan []byte, buffer),
		closed:   make(chan struct{}),
	}
}

// Write publishes TLS records produced by the client handshake to the outbound queue.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	err := c.closeErr
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}

	buf := make([]byte, len(p))
	copy(buf, p)

	select {
	case c.outbound <- buf:
		return len(p), nil
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}

// Read delivers TLS records injected from the EAP transport to the TLS client.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		c.mu.Lock()
		if len(c.inBuf) > 0 {
			n := copy(p, c.inBuf)
			c.inBuf = c.inBuf[n:]
			c.mu.Unlock()
			return n, nil
		}
		err := c.closeErr
		c.mu.Unlock()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, err
		}

		select {
		case data, ok := <-c.inbound:
			if !ok {
				return 0, io.EOF
			}
			if len(data) == 0 {
				continue
			}
			c.mu.Lock()
			c.inBuf = append(c.inBuf, data...)
			c.mu.Unlock()
		case <-c.closed:
			return 0, io.EOF
		}
	}
}

// CloseWithError terminates the connection and causes subsequent Read/Write calls to fail with err.
func (c *Conn) CloseWithError(err error) error {
	c.mu.Lock()
	c.closeErr = err
	c.mu.Unlock()
	c.once.Do(func() {
		close(c.closed)
		close(c.outbound)
		close(c.inbound)
	})
	return nil
}

// Close closes the transport with io.EOF.
func (c *Conn) Close() error {
	return c.CloseWithError(io.EOF)
}

// Inject copies TLS payload bytes into the inbound queue for consumption by the TLS stack.
func (c *Conn) Inject(payload []byte) {
	if len(payload) == 0 {
		return
	}
	buf := make([]byte, len(payload))
	copy(buf, payload)

	select {
	case <-c.closed:
	case c.inbound <- buf:
	}
}

// NextOutbound waits for the next TLS record produced by the client handshake.
func (c *Conn) NextOutbound(ctx context.Context) ([]byte, error) {
	select {
	case data, ok := <-c.outbound:
		if !ok {
			return nil, io.EOF
		}
		if len(data) == 0 {
			return c.NextOutbound(ctx)
		}
		buf := make([]byte, len(data))
		copy(buf, data)
		return buf, nil
	case <-c.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// DrainOutbound retrieves all currently queued TLS records without blocking.
func (c *Conn) DrainOutbound() [][]byte {
	var bufs [][]byte
	for {
		select {
		case data, ok := <-c.outbound:
			if !ok {
				return bufs
			}
			if len(data) == 0 {
				continue
			}
			buf := make([]byte, len(data))
			copy(buf, data)
			bufs = append(bufs, buf)
		default:
			return bufs
		}
	}
}

func (c *Conn) LocalAddr() net.Addr  { return dummyAddr(0) }
func (c *Conn) RemoteAddr() net.Addr { return dummyAddr(0) }

func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr int

func (dummyAddr) Network() string { return "eaptls" }
func (dummyAddr) String() string  { return "eaptls" }
