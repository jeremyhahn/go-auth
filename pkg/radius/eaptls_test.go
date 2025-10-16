package radius

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	radiuslib "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestAuthenticateEAPTLSSuccess(t *testing.T) {
	secret := []byte("sharedsecret")

	serverCfg, clientCfg := mustLoadTLSConfigs(t)

	srv := newFakeEAPTLSServer(t, secret, serverCfg)
	t.Cleanup(srv.Close)

	auth, err := NewAuthenticator(
		"127.0.0.1:1812",
		string(secret),
		WithPacketExchanger(srv),
		WithEAPTLS(&EAPTLSConfig{TLSConfig: clientCfg}),
	)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := auth.Authenticate(ctx, "user@example", ""); err != nil {
		t.Fatalf("unexpected authenticate error: %v", err)
	}

	srv.assertHandshakeComplete()
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
}

func newFakeEAPTLSServer(t *testing.T, secret []byte, serverCfg *tls.Config) *fakeEAPTLSServer {
	t.Helper()
	clientPipe, serverPipe := net.Pipe()

	s := &fakeEAPTLSServer{
		t:              t,
		secret:         append([]byte(nil), secret...),
		state:          []byte("state-token"),
		pipe:           clientPipe,
		serverConn:     tls.Server(serverPipe, serverCfg),
		handshakeDone:  make(chan struct{}),
		nextIdentifier: 1,
	}

	go s.runHandshake()

	return s
}

func (s *fakeEAPTLSServer) runHandshake() {
	err := s.serverConn.Handshake()
	s.handshakeErr = err
	s.serverConn.Close()
	close(s.handshakeDone)
}

func (s *fakeEAPTLSServer) Close() {
	s.pipe.Close()
	s.serverConn.Close()
	if s.handshakeDone != nil {
		<-s.handshakeDone
	}
}

func (s *fakeEAPTLSServer) exchange(ctx context.Context, packet *radiuslib.Packet, addr string) (*radiuslib.Packet, error) {
	s.t.Helper()
	if err := verifyMessageAuthenticator(packet, s.secret); err != nil {
		s.t.Fatalf("verify request authenticator: %v", err)
	}

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

	// A pure ACK has no payload and no flags.
	if len(msg.Data) == 0 && msg.Flags == 0 {
		if pkt := s.emitServerFragment(); pkt != nil {
			return pkt, nil
		}
		if s.handshakeComplete() {
			return s.accessAccept(), nil
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

	s.captureServerData()

	if pkt := s.emitServerFragment(); pkt != nil {
		return pkt, nil
	}
	if s.handshakeComplete() {
		return s.accessAccept(), nil
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
	if err := setMessageAuthenticator(pkt, s.secret); err != nil {
		s.t.Fatalf("set challenge authenticator: %v", err)
	}
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
	if err := setMessageAuthenticator(pkt, s.secret); err != nil {
		s.t.Fatalf("set ack authenticator: %v", err)
	}
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
	if err := setMessageAuthenticator(pkt, s.secret); err != nil {
		s.t.Fatalf("set server fragment authenticator: %v", err)
	}
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

func (s *fakeEAPTLSServer) accessAccept() *radiuslib.Packet {
	pkt := radiuslib.New(radiuslib.CodeAccessAccept, s.secret)
	msg := &eapMessage{Code: eapCodeSuccess, Identifier: s.nextIdentifier}
	if err := setEAPMessageAttr(pkt, msg); err != nil {
		s.t.Fatalf("set success attr: %v", err)
	}
	if err := setMessageAuthenticator(pkt, s.secret); err != nil {
		s.t.Fatalf("set success authenticator: %v", err)
	}
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

func (s *fakeEAPTLSServer) captureServerData() {
	buf := make([]byte, 4096)
	for {
		s.pipe.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		n, err := s.pipe.Read(buf)
		if n > 0 {
			copyBuf := make([]byte, n)
			copy(copyBuf, buf[:n])
			s.pendingServer = append(s.pendingServer, copyBuf)
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			if errors.Is(err, io.EOF) {
				break
			}
			s.t.Fatalf("read from tls server: %v", err)
		}
	}
	s.pipe.SetReadDeadline(time.Time{})
}

func (s *fakeEAPTLSServer) assertHandshakeComplete() {
	s.t.Helper()
	if s.handshakeDone == nil {
		if s.handshakeErr != nil {
			s.t.Fatalf("server handshake error: %v", s.handshakeErr)
		}
		return
	}
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
	if s.handshakeDone == nil {
		return s.handshakeErr == nil
	}
	select {
	case <-s.handshakeDone:
		if s.handshakeErr != nil {
			s.t.Fatalf("server handshake failed: %v", s.handshakeErr)
		}
		s.handshakeDone = nil
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
