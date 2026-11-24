package radius

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jeremyhahn/go-auth/pkg/radius/internal/tlsio"
	radiuslib "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	defaultEAPTLSFragmentSize = 1010
	maxEAPTLSFragmentSize     = 4096

	// maxEAPTLSRoundTrips bounds one EAP-TLS conversation against a peer sending content-free challenges.
	maxEAPTLSRoundTrips = 100
)

var (
	errEAPTLSTooManyRoundTrips = errors.New("radius: eap-tls exceeded the maximum number of round trips")

	// errEAPTLSDiscardPacket marks a response that failed Message-Authenticator
	// verification. It is not an authentication outcome — it means the packet
	// is treated as never having arrived (RFC 3579 §3.2).
	errEAPTLSDiscardPacket = errors.New("radius: discarded unauthenticated response")
)

// EAPTLSConfig configures EAP-TLS authentication.
type EAPTLSConfig struct {
	TLSConfig     *tls.Config
	Identity      string
	OuterIdentity string
	FragmentSize  int
}

func (cfg *EAPTLSConfig) fragmentSize() int {
	if cfg == nil || cfg.FragmentSize <= 0 {
		return defaultEAPTLSFragmentSize
	}
	size := cfg.FragmentSize
	if size > maxEAPTLSFragmentSize {
		size = maxEAPTLSFragmentSize
	}
	return size
}

func (cfg *EAPTLSConfig) identityFor(username string) (string, string) {
	identity := cfg.Identity
	if identity == "" {
		identity = username
	}
	outer := cfg.OuterIdentity
	if outer == "" {
		outer = identity
	}
	return identity, outer
}

func (a *Authenticator) authenticateEAPTLS(ctx context.Context, username string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cfg := a.eapTLS
	if cfg == nil {
		return errors.New("radius: EAP-TLS configuration not provided")
	}
	if cfg.TLSConfig == nil {
		return errors.New("radius: EAP-TLS requires TLS configuration")
	}

	identity, outer := cfg.identityFor(username)
	if identity == "" {
		return errors.New("radius: EAP-TLS identity must not be empty")
	}
	if outer == "" {
		return errors.New("radius: EAP-TLS outer identity must not be empty")
	}

	tlsCfg := cfg.TLSConfig.Clone()
	if tlsCfg == nil {
		return errors.New("radius: failed to clone TLS configuration")
	}

	session := &eapTLSSession{
		auth:         a,
		identity:     identity,
		outer:        outer,
		fragmentSize: cfg.fragmentSize(),
		transport:    tlsio.NewConn(8),
	}
	session.tlsConn = tls.Client(session.transport, tlsCfg)

	// The secret is readable only while run executes and the field is cleared on return. Residue R2: HMAC-MD5 pads live on the heap.
	return a.secret.WithBytes(func(sharedSecret []byte) error {
		session.secret = sharedSecret
		defer func() { session.secret = nil }()
		return session.run(ctx)
	})
}

type eapTLSSession struct {
	auth         *Authenticator
	secret       []byte
	identity     string
	outer        string
	fragmentSize int

	transport *tlsio.Conn
	tlsConn   *tls.Conn

	handshakeOnce bool
	handshakeDone bool
	handshakeErr  error

	// handshakeDoneCh closes when the handshake goroutine returns, after handshakeResult is written.
	handshakeDoneCh chan struct{}
	handshakeResult error

	nextMsg   *eapMessage
	stateAttr []byte

	incoming fragmentAccumulator

	pendingTLS [][]byte
	currentTLS []byte
	offset     int
}

func (s *eapTLSSession) run(ctx context.Context) error {
	s.nextMsg = &eapMessage{
		Code:       eapCodeResponse,
		Identifier: 0,
		Type:       eapTypeIdentity,
		Data:       []byte(s.identity),
	}

	for round := 0; ; round++ {
		if round >= maxEAPTLSRoundTrips {
			s.closeTransport(errEAPTLSTooManyRoundTrips)
			return errEAPTLSTooManyRoundTrips
		}
		if err := ctx.Err(); err != nil {
			s.closeTransport(err)
			return err
		}
		if s.nextMsg == nil {
			return errors.New("radius: EAP-TLS internal error: missing next message")
		}
		packet, err := s.buildAccessRequest(s.nextMsg)
		if err != nil {
			s.closeTransport(err)
			return err
		}

		resp, err := s.auth.client.exchange(ctx, packet, s.auth.address)
		if err != nil {
			s.closeTransport(err)
			return err
		}

		next, err := s.handleResponse(ctx, packet, resp)
		if err != nil {
			// A discarded packet leaves the session unchanged, so the request is retransmitted.
			if errors.Is(err, errEAPTLSDiscardPacket) {
				continue
			}
			s.closeTransport(err)
			return err
		}
		s.nextMsg = next
		// The only success path. handleAccept reaches it solely from an
		// Access-Accept whose Message-Authenticator verified, carrying
		// EAP-Success, with the TLS handshake completed without error.
		if s.nextMsg == nil {
			s.closeTransport(nil)
			return nil
		}
	}
}

func (s *eapTLSSession) buildAccessRequest(msg *eapMessage) (*radiuslib.Packet, error) {
	packet := radiuslib.New(radiuslib.CodeAccessRequest, s.secret)
	if s.outer != "" {
		if err := rfc2865.UserName_SetString(packet, s.outer); err != nil {
			return nil, fmt.Errorf("radius: set outer identity: %w", err)
		}
	}
	if len(s.stateAttr) > 0 {
		if err := rfc2865.State_Set(packet, s.stateAttr); err != nil {
			return nil, fmt.Errorf("radius: set state: %w", err)
		}
	}
	if err := setEAPMessageAttr(packet, msg); err != nil {
		return nil, err
	}
	if err := setMessageAuthenticator(packet, s.secret); err != nil {
		return nil, err
	}
	return packet, nil
}

func (s *eapTLSSession) handleResponse(ctx context.Context, req, resp *radiuslib.Packet) (*eapMessage, error) {
	if resp == nil {
		return nil, errors.New("radius: nil response packet")
	}
	if req == nil {
		return nil, errors.New("radius: nil request packet")
	}

	// RFC 3579 §3.2: verify the Message-Authenticator before reading any field and silently discard a mismatch; maxEAPTLSRoundTrips stops a peer that only sends bad packets.
	if err := verifyResponseMessageAuthenticator(resp, req.Authenticator, s.secret); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errEAPTLSDiscardPacket, resp.Code, err)
	}

	s.cacheState(resp)

	switch resp.Code {
	case radiuslib.CodeAccessChallenge:
		return s.handleChallenge(ctx, resp)
	case radiuslib.CodeAccessAccept:
		return s.handleAccept(ctx, resp)
	case radiuslib.CodeAccessReject:
		// Only a verified Access-Reject is the server's decision. An
		// unverifiable one was discarded above and never reaches this line,
		// so a forged denial cannot be laundered into an authoritative one.
		return nil, ErrRejected
	default:
		return nil, fmt.Errorf("radius: unexpected response code %s", resp.Code)
	}
}

func (s *eapTLSSession) cacheState(resp *radiuslib.Packet) {
	attr, ok := resp.Attributes.Lookup(rfc2865.State_Type)
	if !ok {
		s.stateAttr = nil
		return
	}
	s.stateAttr = append(s.stateAttr[:0], attr...)
}

func (s *eapTLSSession) handleChallenge(ctx context.Context, resp *radiuslib.Packet) (*eapMessage, error) {
	raw, err := getEAPMessageAttr(resp)
	if err != nil {
		return nil, err
	}
	msg, err := parseEAPMessage(raw)
	if err != nil {
		return nil, err
	}
	if msg.Code != eapCodeRequest {
		return nil, fmt.Errorf("radius: unexpected EAP code %d in challenge", msg.Code)
	}

	s.checkHandshakeResult()

	switch msg.Type {
	case eapTypeIdentity:
		return &eapMessage{
			Code:       eapCodeResponse,
			Identifier: msg.Identifier,
			Type:       eapTypeIdentity,
			Data:       []byte(s.identity),
		}, nil
	case eapTypeTLS:
		return s.handleTLSRequest(ctx, msg)
	default:
		return nil, fmt.Errorf("radius: unsupported EAP type %d", msg.Type)
	}
}

func (s *eapTLSSession) handleAccept(ctx context.Context, resp *radiuslib.Packet) (*eapMessage, error) {
	raw, err := getEAPMessageAttr(resp)
	if err != nil {
		return nil, err
	}
	msg, err := parseEAPMessage(raw)
	if err != nil {
		return nil, err
	}
	if msg.Code == eapCodeFailure {
		return nil, ErrRejected
	}
	if msg.Code != eapCodeSuccess {
		return nil, fmt.Errorf("radius: unexpected EAP code %d in Access-Accept", msg.Code)
	}

	// An Access-Accept only authorizes the identity the TLS handshake proved.
	// A server that sends one before the handshake finishes has authorized
	// nothing yet, so wait for the result rather than taking its word for it.
	if err := s.waitForHandshake(ctx); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *eapTLSSession) ensureHandshakeStarted() {
	if s.handshakeOnce {
		return
	}
	s.handshakeOnce = true
	s.handshakeDoneCh = make(chan struct{})
	go func() {
		err := s.tlsConn.Handshake()
		s.handshakeResult = err
		close(s.handshakeDoneCh)
	}()
}

func (s *eapTLSSession) handleTLSRequest(ctx context.Context, msg *eapMessage) (*eapMessage, error) {
	s.ensureHandshakeStarted()

	if msg.Flags&eapTLSFlagMoreFragments != 0 || msg.Flags&eapTLSFlagLengthIncluded != 0 || len(msg.Data) > 0 {
		complete, data, err := s.incoming.add(msg)
		if err != nil {
			return nil, fmt.Errorf("radius: EAP-TLS fragment error (id=%d flags=0x%02x len=%d): %w", msg.Identifier, msg.Flags, msg.TLSMessageLength, err)
		}
		if !complete {
			return s.emptyTLSAck(msg.Identifier), nil
		}
		if len(data) > 0 {
			s.transport.Inject(data)
		}
	}

	s.collectTLSOutbound(ctx)

	next := s.nextTLSFragment(msg.Identifier)
	if next != nil {
		return next, nil
	}

	// A finished handshake is not the end: RFC 5216 §2.1.1 sends an empty response and waits for the server's verified decision.
	if s.handshakeDoneCh != nil && !s.handshakeDone {
		if data, err := s.awaitOutbound(ctx); err == nil {
			s.pendingTLS = append(s.pendingTLS, data)
			s.pendingTLS = append(s.pendingTLS, s.transport.DrainOutbound()...)
			if frag := s.nextTLSFragment(msg.Identifier); frag != nil {
				return frag, nil
			}
		} else if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && err != io.EOF {
			return nil, err
		} else {
			s.pendingTLS = append(s.pendingTLS, s.transport.DrainOutbound()...)
			if frag := s.nextTLSFragment(msg.Identifier); frag != nil {
				return frag, nil
			}
		}
	}

	return s.emptyTLSAck(msg.Identifier), nil
}

func (s *eapTLSSession) emptyTLSAck(identifier uint8) *eapMessage {
	return &eapMessage{
		Code:       eapCodeResponse,
		Identifier: identifier,
		Type:       eapTypeTLS,
	}
}

// awaitOutbound returns the next TLS record, or nil when the handshake goroutine finished, or an error at the deadline.
func (s *eapTLSSession) awaitOutbound(ctx context.Context) ([]byte, error) {
	waitCtx := ctx
	if waitCtx == nil {
		waitCtx = context.Background()
	}
	var cancel context.CancelFunc
	if _, ok := waitCtx.Deadline(); !ok {
		waitCtx, cancel = context.WithTimeout(waitCtx, 2*time.Second)
		defer cancel()
	}

	// Stop waiting as soon as the handshake ends, whichever way it ends.
	if s.handshakeDoneCh != nil {
		linked, stop := context.WithCancel(waitCtx)
		defer stop()
		go func() {
			select {
			case <-s.handshakeDoneCh:
				stop()
			case <-linked.Done():
			}
		}()
		waitCtx = linked
	}

	data, err := s.transport.NextOutbound(waitCtx)
	if err != nil {
		s.checkHandshakeResult()
		return nil, err
	}
	return data, nil
}

func (s *eapTLSSession) collectTLSOutbound(ctx context.Context) {
	buffers := s.transport.DrainOutbound()
	if len(buffers) == 0 {
		// A record already being fragmented is the reply to this challenge.
		if len(s.currentTLS) > 0 || len(s.pendingTLS) > 0 {
			return
		}

		// After the handshake goroutine returns there is nothing more to wait for.
		s.checkHandshakeResult()
		if s.handshakeDone {
			return
		}

		if data, err := s.awaitOutbound(ctx); err == nil {
			buffers = append(buffers, data)
			buffers = append(buffers, s.transport.DrainOutbound()...)
		} else if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) && err != io.EOF {
			s.handshakeErr = err
			s.handshakeDone = true
		} else {
			// The wait may have ended because the handshake finished; take
			// anything it wrote on its way out.
			buffers = append(buffers, s.transport.DrainOutbound()...)
		}
	}
	if len(buffers) == 0 {
		return
	}
	s.pendingTLS = append(s.pendingTLS, buffers...)
}

func (s *eapTLSSession) nextTLSFragment(identifier uint8) *eapMessage {
	if len(s.currentTLS) == 0 {
		if len(s.pendingTLS) == 0 {
			s.checkHandshakeResult()
			return nil
		}
		s.currentTLS = s.pendingTLS[0]
		s.pendingTLS = s.pendingTLS[1:]
		s.offset = 0
	}

	total := len(s.currentTLS)
	if total == 0 {
		s.currentTLS = nil
		return nil
	}

	remaining := total - s.offset
	chunk := remaining
	if chunk > s.fragmentSize {
		chunk = s.fragmentSize
	}

	flags := uint8(0)
	if s.offset == 0 {
		flags |= eapTLSFlagLengthIncluded
	}
	if s.offset+chunk < total {
		flags |= eapTLSFlagMoreFragments
	}

	fragment := s.currentTLS[s.offset : s.offset+chunk]
	msg := &eapMessage{
		Code:       eapCodeResponse,
		Identifier: identifier,
		Type:       eapTypeTLS,
		Flags:      flags,
		Data:       append([]byte(nil), fragment...),
	}
	if flags&eapTLSFlagLengthIncluded != 0 {
		msg.TLSMessageLength = total
	}

	s.offset += chunk
	if s.offset >= total {
		s.currentTLS = nil
		s.offset = 0
	}

	return msg
}

func (s *eapTLSSession) waitForHandshake(ctx context.Context) error {
	if s.handshakeDone {
		return s.handshakeErr
	}
	if s.handshakeDoneCh == nil {
		return errors.New("radius: EAP-TLS handshake never started")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-s.handshakeDoneCh:
		s.handshakeDone = true
		s.handshakeErr = s.handshakeResult
		return s.handshakeErr
	case <-ctx.Done():
		// Never report success for a handshake whose result is unknown.
		return ctx.Err()
	}
}

func (s *eapTLSSession) checkHandshakeResult() {
	if s.handshakeDone || s.handshakeDoneCh == nil {
		return
	}
	select {
	case <-s.handshakeDoneCh:
		s.handshakeErr = s.handshakeResult
		s.handshakeDone = true
	default:
	}
}

func (s *eapTLSSession) closeTransport(err error) {
	if err == nil {
		s.transport.Close()
		return
	}
	_ = s.transport.CloseWithError(err)
}

type fragmentAccumulator struct {
	buffer   []byte
	expected int
}

func (a *fragmentAccumulator) add(msg *eapMessage) (bool, []byte, error) {
	data := msg.Data
	if msg.Flags&eapTLSFlagLengthIncluded != 0 {
		if msg.TLSMessageLength < 0 {
			return false, nil, errors.New("radius: invalid EAP-TLS length")
		}
		a.expected = msg.TLSMessageLength
		if a.expected == 0 {
			a.expected = len(data)
		}
	}
	a.buffer = append(a.buffer, data...)

	if msg.Flags&eapTLSFlagMoreFragments != 0 {
		return false, nil, nil
	}

	if a.expected != 0 && len(a.buffer) < a.expected {
		return false, nil, fmt.Errorf("radius: incomplete EAP-TLS fragment (have %d, want %d)", len(a.buffer), a.expected)
	}

	payload := append([]byte(nil), a.buffer...)
	a.buffer = a.buffer[:0]
	a.expected = 0
	return true, payload, nil
}
