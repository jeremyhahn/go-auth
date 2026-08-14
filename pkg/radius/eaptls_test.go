package radius

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	radiuslib "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestAuthenticateEAPTLSSuccess(t *testing.T) {
	secret := []byte("sharedsecret")

	serverCfg, clientCfg := mustLoadTLSConfigs(t)

	srv := newFakeEAPTLSServer(t, secret, serverCfg, decisionAccept)
	t.Cleanup(srv.Close)

	auth := mustEAPTLSAuthenticator(t, secret, srv, clientCfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := auth.Authenticate(ctx, "user@example", ""); err != nil {
		t.Fatalf("unexpected authenticate error: %v", err)
	}

	srv.assertHandshakeComplete()
}

// TestAuthenticateEAPTLSRequiresAccessAccept is the regression test for the
// authorization gap fixed alongside it: the client used to report success as
// soon as its own TLS handshake completed with nothing left to send, which
// authenticated the user without the RADIUS server ever having made — or
// been asked for — an authorization decision. A server that completes the
// handshake and then withholds its verdict must authenticate nobody.
//
// The conversation is bounded by maxEAPTLSRoundTrips rather than by a clock,
// so this test carries no timing assumption.
func TestAuthenticateEAPTLSRequiresAccessAccept(t *testing.T) {
	secret := []byte("sharedsecret")
	serverCfg, clientCfg := mustLoadTLSConfigs(t)

	srv := newFakeEAPTLSServer(t, secret, serverCfg, decisionWithhold)
	t.Cleanup(srv.Close)

	auth := mustEAPTLSAuthenticator(t, secret, srv, clientCfg)

	err := auth.Authenticate(context.Background(), "user@example", "")
	if !errors.Is(err, errEAPTLSTooManyRoundTrips) {
		t.Fatalf("expected the conversation to run out of round trips, got %v", err)
	}

	// The handshake itself succeeded; that is precisely why it must not be
	// mistaken for authorization.
	srv.assertHandshakeComplete()
}

// TestAuthenticateEAPTLSRejectsBadFinalPacket covers the other half: the
// server answers, but with something that is not an authorization. None of
// these may authenticate, and a completed TLS handshake does not rescue any
// of them.
func TestAuthenticateEAPTLSRejectsBadFinalPacket(t *testing.T) {
	tests := []struct {
		name     string
		decision finalDecision
		wantErr  error // nil means "any error, but never success"
	}{
		{name: "Access-Reject", decision: decisionReject, wantErr: ErrRejected},
		{name: "Access-Accept carrying EAP-Failure", decision: decisionAcceptEAPFailure, wantErr: ErrRejected},
		{name: "Access-Accept carrying neither Success nor Failure", decision: decisionAcceptWrongEAPCode},
		{name: "Access-Accept authenticated with the wrong secret", decision: decisionForgedAccept},
		{name: "Access-Reject authenticated with the wrong secret", decision: decisionForgedReject},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := []byte("sharedsecret")
			serverCfg, clientCfg := mustLoadTLSConfigs(t)

			srv := newFakeEAPTLSServer(t, secret, serverCfg, tt.decision)
			t.Cleanup(srv.Close)

			auth := mustEAPTLSAuthenticator(t, secret, srv, clientCfg)

			err := auth.Authenticate(context.Background(), "user@example", "")
			if err == nil {
				t.Fatal("authentication succeeded without an authorizing Access-Accept")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

// TestAuthenticateEAPTLSDiscardsForgedReject pins the specific hazard in an
// unverified Access-Reject: it must not reach the caller as ErrRejected.
// ErrRejected is the server's authoritative denial, and an off-path peer that
// cannot compute the Message-Authenticator must not be able to produce one.
// RFC 3579 §3.2 has the packet discarded, so the conversation carries on and
// ends on the round-trip bound instead.
func TestAuthenticateEAPTLSDiscardsForgedReject(t *testing.T) {
	secret := []byte("sharedsecret")
	serverCfg, clientCfg := mustLoadTLSConfigs(t)

	srv := newFakeEAPTLSServer(t, secret, serverCfg, decisionForgedReject)
	t.Cleanup(srv.Close)

	auth := mustEAPTLSAuthenticator(t, secret, srv, clientCfg)

	err := auth.Authenticate(context.Background(), "user@example", "")
	if errors.Is(err, ErrRejected) {
		t.Fatal("a forged Access-Reject was surfaced as the server's rejection")
	}
	if !errors.Is(err, errEAPTLSTooManyRoundTrips) {
		t.Fatalf("expected the forged rejects to be discarded until the round-trip bound, got %v", err)
	}
}

// TestAuthenticateEAPTLSDiscardsForgedChallenge covers the same rule on the
// challenge path. Verification happens before any field is read, so a forged
// challenge cannot plant the State attribute either.
func TestAuthenticateEAPTLSDiscardsForgedChallenge(t *testing.T) {
	secret := []byte("sharedsecret")
	serverCfg, clientCfg := mustLoadTLSConfigs(t)

	srv := newFakeEAPTLSServer(t, secret, serverCfg, decisionAccept)
	srv.forgeChallenges = true
	t.Cleanup(srv.Close)

	auth := mustEAPTLSAuthenticator(t, secret, srv, clientCfg)

	err := auth.Authenticate(context.Background(), "user@example", "")
	if err == nil {
		t.Fatal("authentication succeeded on a conversation of unauthenticated challenges")
	}
	if !errors.Is(err, errEAPTLSTooManyRoundTrips) {
		t.Fatalf("expected the forged challenges to be discarded until the round-trip bound, got %v", err)
	}
}

func mustEAPTLSAuthenticator(t *testing.T, secret []byte, srv *fakeEAPTLSServer, clientCfg *tls.Config) *Authenticator {
	t.Helper()
	auth, err := NewAuthenticator(
		"127.0.0.1:1812",
		string(secret),
		WithPacketExchanger(srv),
		WithEAPTLS(&EAPTLSConfig{TLSConfig: clientCfg}),
	)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}
	return auth
}

func TestAuthenticateEAPTLSMissingTLSConfig(t *testing.T) {
	auth, err := NewAuthenticator(
		"127.0.0.1:1812",
		"secret",
		WithPacketExchanger(&fakeExchanger{}),
		WithEAPTLS(&EAPTLSConfig{}),
	)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "user", "")
	if err == nil || err.Error() != "radius: EAP-TLS requires TLS configuration" {
		t.Fatalf("expected TLS config error, got %v", err)
	}
}

func mustLoadTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	base := filepath.Join("testdata", "certs")

	serverCert, err := tls.LoadX509KeyPair(filepath.Join(base, "server.pem"), filepath.Join(base, "server.key"))
	if err != nil {
		t.Fatalf("load server key pair: %v", err)
	}
	clientCert, err := tls.LoadX509KeyPair(filepath.Join(base, "client.pem"), filepath.Join(base, "client.key"))
	if err != nil {
		t.Fatalf("load client key pair: %v", err)
	}

	caBytes, err := os.ReadFile(filepath.Join(base, "ca.pem"))
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		t.Fatalf("failed to parse CA certificate")
	}

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
		// EAP-TLS carries the handshake and nothing else: a real server
		// answers a completed handshake with Access-Accept rather than
		// tunneling whatever the TLS stack writes afterwards. Suppressing
		// session tickets keeps the harness to that, so the last round is
		// decided by the handshake result alone.
		SessionTicketsDisabled: true,
	}

	clientCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
		ServerName:   "127.0.0.1",
		MinVersion:   tls.VersionTLS12,
	}

	return serverCfg, clientCfg
}

type fakeEAPTLSServer struct {
	t      *testing.T
	secret []byte
	state  []byte

	serverConn *tls.Conn
	pipe       net.Conn

	// serverOut carries every byte the TLS server writes. A dedicated pump
	// goroutine drains the pipe into it so the server's handshake never
	// blocks on a write nobody is reading. Reading the pipe on demand under
	// a short deadline instead — which is what this harness used to do —
	// makes progress depend on the server's crypto finishing inside a fixed
	// wall-clock window; on a loaded CI runner it does not, the server stays
	// blocked mid-write forever, and the conversation degenerates into an
	// endless exchange of content-free EAP-TLS acknowledgements.
	serverOut chan []byte

	closed    chan struct{}
	closeOnce sync.Once

	handshakeDone chan struct{}
	handshakeErr  error

	clientFragments fragmentAccumulator

	pendingServer [][]byte
	currentServer []byte
	serverOffset  int
	sentStart     bool

	nextIdentifier   uint8
	expectedResponse uint8
	stateSeen        bool

	decision finalDecision

	// forgeChallenges signs every Access-Challenge with the wrong secret,
	// standing in for an off-path peer injecting challenges into the
	// conversation.
	forgeChallenges bool

	// The last answer sent, replayed when the client retransmits — the RADIUS
	// server's duplicate-detection cache.
	lastHandledIdentifier uint8
	lastResponse          *radiuslib.Packet
	haveLastResponse      bool

	// reqAuthenticator is the Authenticator of the request being answered.
	// RFC 2869 §5.14 defines a response's Message-Authenticator over it rather
	// than over the response's own Authenticator, so every reply this server
	// signs must use it. Deriving the fake from the RFC rather than from the
	// client is the point: signing responses the way the client used to verify
	// them made the unit suite agree with itself while every conforming server
	// was rejected on the wire.
	reqAuthenticator [16]byte

	// lastSignSecret is the key lastResponse was signed under, so a replay can
	// be re-signed for the retransmission it answers.
	lastSignSecret []byte
}

// signResponse applies the Message-Authenticator a conforming RADIUS server
// would, over the Authenticator of the request being answered.
func (s *fakeEAPTLSServer) signResponse(pkt *radiuslib.Packet, secret []byte) {
	s.t.Helper()
	s.lastSignSecret = secret
	if err := setResponseMessageAuthenticator(pkt, s.reqAuthenticator, secret); err != nil {
		s.t.Fatalf("sign response: %v", err)
	}
}

// challengeSecret is the key the server's Access-Challenges are authenticated
// under.
func (s *fakeEAPTLSServer) challengeSecret() []byte {
	if s.forgeChallenges {
		return wrongSecret
	}
	return s.secret
}

// finalDecision is what the fake server does once its TLS handshake has
// completed. A completed handshake is not an authorization, so every one of
// these except decisionAccept must leave the client reporting failure.
type finalDecision int

const (
	// decisionAccept is the only outcome that authenticates: Access-Accept
	// carrying EAP-Success, with a Message-Authenticator over the real secret.
	decisionAccept finalDecision = iota
	// decisionWithhold never decides, answering forever with empty
	// Access-Challenges. This is the case the removed short-circuit turned
	// into a success.
	decisionWithhold
	// decisionReject is a plain Access-Reject.
	decisionReject
	// decisionAcceptEAPFailure is an Access-Accept whose EAP payload says
	// Failure — the RADIUS code and the EAP code disagreeing.
	decisionAcceptEAPFailure
	// decisionAcceptWrongEAPCode is an Access-Accept carrying neither
	// EAP-Success nor EAP-Failure.
	decisionAcceptWrongEAPCode
	// decisionForgedAccept is an Access-Accept authenticated with the wrong
	// secret: an off-path peer that cannot compute the real HMAC.
	decisionForgedAccept
	// decisionForgedReject is an Access-Reject authenticated with the wrong
	// secret. It must never surface as ErrRejected, which would turn an
	// injected packet into the server's authoritative denial.
	decisionForgedReject
)

// wrongSecret is what an off-path peer signs with: anything that is not the
// shared secret.
var wrongSecret = []byte("not-the-shared-secret")

func newFakeEAPTLSServer(t *testing.T, secret []byte, serverCfg *tls.Config, decision finalDecision) *fakeEAPTLSServer {
	t.Helper()
	clientPipe, serverPipe := net.Pipe()

	s := &fakeEAPTLSServer{
		t:              t,
		secret:         append([]byte(nil), secret...),
		state:          []byte("state-token"),
		pipe:           clientPipe,
		serverConn:     tls.Server(serverPipe, serverCfg),
		serverOut:      make(chan []byte, 32),
		closed:         make(chan struct{}),
		handshakeDone:  make(chan struct{}),
		nextIdentifier: 1,
		decision:       decision,
	}

	go s.pump()
	go s.runHandshake()

	return s
}

// runHandshake deliberately leaves the connection open: closing it here would
// emit a close_notify alert that the harness would then forward as one more
// EAP-TLS fragment, racing the handshake result it is supposed to report.
// Close tears the connection down instead.
func (s *fakeEAPTLSServer) runHandshake() {
	s.handshakeErr = s.serverConn.Handshake()
	close(s.handshakeDone)
}

// pump moves everything the TLS server writes off the pipe as soon as it is
// produced, so the server side is never blocked on an unread write.
func (s *fakeEAPTLSServer) pump() {
	defer close(s.serverOut)
	buf := make([]byte, 4096)
	for {
		n, err := s.pipe.Read(buf)
		if n > 0 {
			record := make([]byte, n)
			copy(record, buf[:n])
			select {
			case s.serverOut <- record:
			case <-s.closed:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *fakeEAPTLSServer) Close() {
	s.closeOnce.Do(func() { close(s.closed) })
	s.pipe.Close()
	s.serverConn.Close()
	<-s.handshakeDone
}

func (s *fakeEAPTLSServer) exchange(ctx context.Context, packet *radiuslib.Packet, addr string) (*radiuslib.Packet, error) {
	s.t.Helper()
	if err := verifyMessageAuthenticator(packet, s.secret); err != nil {
		s.t.Fatalf("verify request authenticator: %v", err)
	}
	s.reqAuthenticator = packet.Authenticator

	if !s.stateSeen {
		attr, ok := packet.Attributes.Lookup(rfc2865.State_Type)
		if ok {
			if !equalBytes(attr, s.state) {
				s.t.Fatalf("unexpected state attribute: %q", attr)
			}
			s.stateSeen = true
		}
	} else {
		attr, ok := packet.Attributes.Lookup(rfc2865.State_Type)
		if !ok || !equalBytes(attr, s.state) {
			s.t.Fatalf("missing or mismatched state attribute")
		}
	}

	raw, err := getEAPMessageAttr(packet)
	if err != nil {
		s.t.Fatalf("get EAP message: %v", err)
	}
	msg, err := parseEAPMessage(raw)
	if err != nil {
		s.t.Fatalf("parse EAP message: %v", err)
	}
	if msg.Code != eapCodeResponse {
		s.t.Fatalf("expected EAP response, got code %d", msg.Code)
	}

	// A client that discarded our last answer retransmits the same EAP
	// response. A real RADIUS server replies from its cache rather than
	// re-running the conversation, and this harness has to as well: replaying
	// the request would feed the same bytes to a TLS handshake that has
	// already returned, blocking on a pipe nobody reads any more.
	if s.haveLastResponse && msg.Identifier == s.lastHandledIdentifier {
		// A retransmission carries a fresh Request Authenticator, so the
		// cached reply is re-signed for it rather than replayed verbatim.
		s.signResponse(s.lastResponse, s.lastSignSecret)
		return s.lastResponse, nil
	}

	resp, err := s.respond(msg)
	if resp != nil {
		s.lastHandledIdentifier = msg.Identifier
		s.lastResponse = resp
		s.haveLastResponse = true
	}
	return resp, err
}

// respond produces the server's answer to a client EAP response it has not
// already seen.
func (s *fakeEAPTLSServer) respond(msg *eapMessage) (*radiuslib.Packet, error) {
	s.verifyIdentifier(msg.Identifier)

	if s.expectedResponse == 0 {
		if msg.Type == eapTypeIdentity {
			return s.challengeStart(), nil
		}
		if msg.Type != eapTypeTLS {
			s.t.Fatalf("unexpected initial EAP type %d", msg.Type)
		}
	}

	if msg.Type != eapTypeTLS {
		s.t.Fatalf("expected EAP-TLS response, got type %d", msg.Type)
	}

	// A pure ACK has no payload and no flags: the client is waiting on the
	// server. Block for the next record when the queue is empty rather than
	// replying with another empty challenge and leaving both sides waiting
	// for each other.
	if len(msg.Data) == 0 && msg.Flags == 0 {
		s.captureServerData(len(s.pendingServer) == 0 && len(s.currentServer) == 0)
		if pkt := s.emitServerFragment(); pkt != nil {
			return pkt, nil
		}
		if s.handshakeComplete() {
			if pkt := s.finalPacket(); pkt != nil {
				return pkt, nil
			}
		}
		return s.challengeNext(), nil
	}

	complete, data, err := s.clientFragments.add(msg)
	if err != nil {
		s.t.Fatalf("add client fragment: %v", err)
	}
	if !complete {
		return s.challengeNext(), nil
	}

	if len(data) > 0 {
		s.writeToServer(data)
	}

	// A complete client flight has just been delivered, so the server either
	// answers it or finishes the handshake. Waiting for one of those two
	// events keeps the conversation in lock step without guessing how long
	// the server's crypto takes.
	s.captureServerData(true)

	if pkt := s.emitServerFragment(); pkt != nil {
		return pkt, nil
	}
	if s.handshakeComplete() {
		if pkt := s.finalPacket(); pkt != nil {
			return pkt, nil
		}
	}
	return s.challengeNext(), nil
}

func (s *fakeEAPTLSServer) verifyIdentifier(id uint8) {
	if s.expectedResponse != 0 && id != s.expectedResponse {
		s.t.Fatalf("unexpected identifier: got %d want %d", id, s.expectedResponse)
	}
}

func (s *fakeEAPTLSServer) challengeStart() *radiuslib.Packet {
	pkt := radiuslib.New(radiuslib.CodeAccessChallenge, s.secret)
	if err := rfc2865.State_Set(pkt, s.state); err != nil {
		s.t.Fatalf("set state: %v", err)
	}
	identifier := s.nextIdentifier
	s.expectedResponse = identifier
	s.nextIdentifier++
	msg := &eapMessage{Code: eapCodeRequest, Identifier: identifier, Type: eapTypeTLS, Flags: eapTLSFlagStart}
	if err := setEAPMessageAttr(pkt, msg); err != nil {
		s.t.Fatalf("set challenge attr: %v", err)
	}
	s.signResponse(pkt, s.challengeSecret())
	return pkt
}

func (s *fakeEAPTLSServer) challengeNext() *radiuslib.Packet {
	pkt := radiuslib.New(radiuslib.CodeAccessChallenge, s.secret)
	if err := rfc2865.State_Set(pkt, s.state); err != nil {
		s.t.Fatalf("set state: %v", err)
	}
	identifier := s.nextIdentifier
	s.expectedResponse = identifier
	s.nextIdentifier++
	msg := &eapMessage{Code: eapCodeRequest, Identifier: identifier, Type: eapTypeTLS}
	if err := setEAPMessageAttr(pkt, msg); err != nil {
		s.t.Fatalf("set ack attr: %v", err)
	}
	s.signResponse(pkt, s.challengeSecret())
	return pkt
}

func (s *fakeEAPTLSServer) emitServerFragment() *radiuslib.Packet {
	payload, flags, total, ok := s.nextServerFragment()
	if !ok {
		return nil
	}
	pkt := radiuslib.New(radiuslib.CodeAccessChallenge, s.secret)
	if err := rfc2865.State_Set(pkt, s.state); err != nil {
		s.t.Fatalf("set state: %v", err)
	}
	identifier := s.nextIdentifier
	s.expectedResponse = identifier
	s.nextIdentifier++
	msg := &eapMessage{
		Code:             eapCodeRequest,
		Identifier:       identifier,
		Type:             eapTypeTLS,
		Flags:            flags,
		TLSMessageLength: total,
		Data:             payload,
	}
	if flags&eapTLSFlagLengthIncluded == 0 {
		msg.TLSMessageLength = 0
	}
	if err := setEAPMessageAttr(pkt, msg); err != nil {
		s.t.Fatalf("set server fragment attr: %v", err)
	}
	s.signResponse(pkt, s.challengeSecret())
	return pkt
}

func (s *fakeEAPTLSServer) nextServerFragment() ([]byte, uint8, int, bool) {
	if len(s.currentServer) == 0 {
		if len(s.pendingServer) == 0 {
			return nil, 0, 0, false
		}
		s.currentServer = s.pendingServer[0]
		s.pendingServer = s.pendingServer[1:]
		s.serverOffset = 0
	}

	total := len(s.currentServer)
	if total == 0 {
		s.currentServer = nil
		s.serverOffset = 0
		return nil, 0, 0, false
	}

	remaining := total - s.serverOffset
	chunk := remaining
	if chunk > defaultEAPTLSFragmentSize {
		chunk = defaultEAPTLSFragmentSize
	}

	flags := uint8(0)
	if !s.sentStart {
		flags |= eapTLSFlagStart
		s.sentStart = true
	}
	if s.serverOffset == 0 {
		flags |= eapTLSFlagLengthIncluded
	}
	if s.serverOffset+chunk < total {
		flags |= eapTLSFlagMoreFragments
	}

	fragment := make([]byte, chunk)
	copy(fragment, s.currentServer[s.serverOffset:s.serverOffset+chunk])
	startOffset := s.serverOffset
	s.serverOffset += chunk
	if s.serverOffset >= total {
		s.currentServer = nil
		s.serverOffset = 0
	}

	totalLen := total
	if startOffset != 0 {
		totalLen = 0
	}
	return fragment, flags, totalLen, true
}

// finalPacket is the server's answer once its TLS handshake has completed.
// A nil return means the server has not decided, which leaves the client
// holding an empty challenge and nothing to conclude from.
func (s *fakeEAPTLSServer) finalPacket() *radiuslib.Packet {
	switch s.decision {
	case decisionWithhold:
		return nil
	case decisionReject:
		return s.decisionPacket(radiuslib.CodeAccessReject, eapCodeFailure, s.secret)
	case decisionAcceptEAPFailure:
		return s.decisionPacket(radiuslib.CodeAccessAccept, eapCodeFailure, s.secret)
	case decisionAcceptWrongEAPCode:
		return s.decisionPacket(radiuslib.CodeAccessAccept, eapCodeRequest, s.secret)
	case decisionForgedAccept:
		return s.decisionPacket(radiuslib.CodeAccessAccept, eapCodeSuccess, wrongSecret)
	case decisionForgedReject:
		return s.decisionPacket(radiuslib.CodeAccessReject, eapCodeFailure, wrongSecret)
	default:
		return s.decisionPacket(radiuslib.CodeAccessAccept, eapCodeSuccess, s.secret)
	}
}

// decisionPacket builds the terminating packet. macSecret is the key the
// Message-Authenticator is computed under, so a test can present one an
// off-path peer could have produced.
func (s *fakeEAPTLSServer) decisionPacket(code radiuslib.Code, eapCode uint8, macSecret []byte) *radiuslib.Packet {
	pkt := radiuslib.New(code, s.secret)
	msg := &eapMessage{Code: eapCode, Identifier: s.nextIdentifier}
	if eapCode == eapCodeRequest {
		// Request and Response carry a type; Success and Failure do not.
		msg.Type = eapTypeIdentity
	}
	if err := setEAPMessageAttr(pkt, msg); err != nil {
		s.t.Fatalf("set decision attr: %v", err)
	}
	s.signResponse(pkt, macSecret)
	return pkt
}

func (s *fakeEAPTLSServer) writeToServer(payload []byte) {
	s.t.Helper()
	remaining := payload
	for len(remaining) > 0 {
		n, err := s.pipe.Write(remaining)
		if err != nil {
			s.t.Fatalf("write to tls server: %v", err)
		}
		remaining = remaining[n:]
	}
}

// captureServerData queues the TLS records the server has produced. When
// waitForFlight is set the server is known to owe an answer, so the call
// blocks until it produces one or the handshake goroutine returns; otherwise
// it takes only what is already queued.
func (s *fakeEAPTLSServer) captureServerData(waitForFlight bool) {
	if waitForFlight {
		select {
		case record, ok := <-s.serverOut:
			if !ok {
				return
			}
			s.pendingServer = append(s.pendingServer, record)
		case <-s.handshakeDone:
		}
	}
	for {
		select {
		case record, ok := <-s.serverOut:
			if !ok {
				return
			}
			s.pendingServer = append(s.pendingServer, record)
		default:
			return
		}
	}
}

func (s *fakeEAPTLSServer) assertHandshakeComplete() {
	s.t.Helper()
	select {
	case <-s.handshakeDone:
		if s.handshakeErr != nil {
			s.t.Fatalf("server handshake error: %v", s.handshakeErr)
		}
	default:
		s.t.Fatalf("handshake not completed")
	}
}

func (s *fakeEAPTLSServer) handshakeComplete() bool {
	select {
	case <-s.handshakeDone:
		if s.handshakeErr != nil {
			s.t.Fatalf("server handshake failed: %v", s.handshakeErr)
		}
		return true
	default:
		return false
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
