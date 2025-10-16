package radius

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	radiuslib "layeh.com/radius"
)

type fakeExchanger struct {
	resp      *radiuslib.Packet
	err       error
	lastAddr  string
	lastReq   *radiuslib.Packet
	callCount int
}

func (f *fakeExchanger) exchange(ctx context.Context, packet *radiuslib.Packet, addr string) (*radiuslib.Packet, error) {
	_ = ctx
	f.callCount++
	f.lastAddr = addr
	f.lastReq = packet
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func TestNewAuthenticatorValidatesInputs(t *testing.T) {
	_, err := NewAuthenticator("", "secret")
	if err == nil {
		t.Fatalf("expected error for empty address")
	}

	_, err = NewAuthenticator("127.0.0.1:1812", "")
	if err == nil {
		t.Fatalf("expected error for empty secret")
	}
}

func TestNewAuthenticatorUsesDefaultClient(t *testing.T) {
	auth, err := NewAuthenticator("127.0.0.1:1812", "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth.client == nil {
		t.Fatalf("expected default client to be set")
	}
}

func TestNewAuthenticatorAppliesClientOptions(t *testing.T) {
	retry := 250 * time.Millisecond
	dialTimeout := 42 * time.Second
	auth, err := NewAuthenticator(
		"127.0.0.1:1812",
		"secret",
		WithNetwork("tcp"),
		WithRetry(retry),
		WithMaxPacketErrors(7),
		WithInsecureSkipVerify(true),
		WithDialTimeout(dialTimeout),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rc, ok := auth.client.(radiusClient)
	if !ok {
		t.Fatalf("expected radiusClient, got %T", auth.client)
	}
	if rc.client.Net != "tcp" {
		t.Fatalf("expected network tcp, got %q", rc.client.Net)
	}
	if rc.client.Retry != retry {
		t.Fatalf("expected retry %v, got %v", retry, rc.client.Retry)
	}
	if rc.client.MaxPacketErrors != 7 {
		t.Fatalf("expected max packet errors 7, got %d", rc.client.MaxPacketErrors)
	}
	if !rc.client.InsecureSkipVerify {
		t.Fatalf("expected insecure skip verify true")
	}
	if rc.client.Dialer.Timeout != dialTimeout {
		t.Fatalf("expected dial timeout %v, got %v", dialTimeout, rc.client.Dialer.Timeout)
	}
}

func TestRadiusClientExchange(t *testing.T) {
	secret := []byte("shared")
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("failed to set deadline: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, radiuslib.MaxPacketLength)
		n, addr, err := listener.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := radiuslib.Parse(buf[:n], secret)
		if err != nil {
			return
		}
		resp := req.Response(radiuslib.CodeAccessAccept)
		raw, err := resp.Encode()
		if err != nil {
			return
		}
		_, _ = listener.WriteTo(raw, addr)
	}()

	client := radiusClient{client: &radiuslib.Client{}}
	packet := radiuslib.New(radiuslib.CodeAccessRequest, secret)
	resp, err := client.exchange(context.Background(), packet, listener.LocalAddr().String())
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if resp.Code != radiuslib.CodeAccessAccept {
		t.Fatalf("expected Access-Accept, got %v", resp.Code)
	}
	<-done
}

func TestAuthenticateSuccess(t *testing.T) {
	response := radiuslib.New(radiuslib.CodeAccessAccept, []byte("secret"))
	ex := &fakeExchanger{resp: response}
	auth, err := NewAuthenticator("127.0.0.1:1812", "secret", WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "jane", "password"); err != nil {
		t.Fatalf("unexpected authenticate error: %v", err)
	}
	if ex.callCount != 1 {
		t.Fatalf("expected exchange to be called once, got %d", ex.callCount)
	}
	if ex.lastAddr != "127.0.0.1:1812" {
		t.Fatalf("unexpected address: %q", ex.lastAddr)
	}
}

func TestAuthenticateRejectsEmptyCredentials(t *testing.T) {
	auth, err := NewAuthenticator("127.0.0.1:1812", "secret", WithPacketExchanger(&fakeExchanger{}))
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	cases := []struct {
		name     string
		user     string
		password string
	}{
		{name: "empty username", password: "pw"},
		{name: "empty password", user: "jane"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := auth.Authenticate(context.Background(), tc.user, tc.password)
			if err == nil {
				t.Fatalf("expected error for invalid inputs")
			}
		})
	}
}

func TestAuthenticatePropagatesExchangeError(t *testing.T) {
	ex := &fakeExchanger{err: errors.New("boom")}
	auth, err := NewAuthenticator("127.0.0.1:1812", "secret", WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "jane", "password")
	if !errors.Is(err, ex.err) {
		t.Fatalf("expected exchange error, got %v", err)
	}
}

func TestAuthenticateRejectResponse(t *testing.T) {
	response := radiuslib.New(radiuslib.CodeAccessReject, []byte("secret"))
	ex := &fakeExchanger{resp: response}
	auth, err := NewAuthenticator("127.0.0.1:1812", "secret", WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "jane", "password")
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("expected ErrRejected, got %v", err)
	}
}

func TestAuthenticateUnexpectedCode(t *testing.T) {
	response := radiuslib.New(radiuslib.CodeAccountingResponse, []byte("secret"))
	ex := &fakeExchanger{resp: response}
	auth, err := NewAuthenticator("127.0.0.1:1812", "secret", WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "jane", "password")
	if err == nil {
		t.Fatalf("expected error for unexpected response code")
	}
}

func TestAuthenticateHonorsContextCancellation(t *testing.T) {
	ex := &fakeExchanger{}
	auth, err := NewAuthenticator("127.0.0.1:1812", "secret", WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = auth.Authenticate(ctx, "jane", "password")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if ex.callCount != 0 {
		t.Fatalf("expected exchange not to be invoked when context canceled")
	}
}

func TestAuthenticateAllowsNilContext(t *testing.T) {
	response := radiuslib.New(radiuslib.CodeAccessAccept, []byte("secret"))
	ex := &fakeExchanger{resp: response}
	auth, err := NewAuthenticator("127.0.0.1:1812", "secret", WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	if err := auth.Authenticate(nil, "jane", "password"); err != nil {
		t.Fatalf("unexpected authenticate error: %v", err)
	}
}

func TestNewAuthenticatorWithTLSConfigRequiresConfig(t *testing.T) {
	_, err := NewAuthenticator("127.0.0.1:1812", "secret", WithTLSConfig(nil))
	if err == nil {
		t.Fatalf("expected error when TLS config is nil")
	}
}

func TestNewAuthenticatorWithTLSAndCustomExchanger(t *testing.T) {
	response := radiuslib.New(radiuslib.CodeAccessAccept, []byte("secret"))
	ex := &fakeExchanger{resp: response}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	auth, err := NewAuthenticator("127.0.0.1:1812", "secret", WithTLSConfig(tlsConfig), WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "jane", "password"); err != nil {
		t.Fatalf("unexpected authenticate error: %v", err)
	}
	if ex.callCount != 1 {
		t.Fatalf("expected exchange to be called once, got %d", ex.callCount)
	}
}

func TestNewTLSPacketExchangerUsesDefaultDialer(t *testing.T) {
	cfg := &authConfig{
		tlsConfig:          &tls.Config{ServerName: "example"},
		retry:              10 * time.Millisecond,
		maxPacketErrors:    3,
		insecureSkipVerify: true,
		dialTimeout:        5 * time.Second,
	}

	exchanger, err := newTLSPacketExchanger(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating TLS exchanger: %v", err)
	}
	if _, ok := exchanger.dialer.(*tls.Dialer); !ok {
		t.Fatalf("expected *tls.Dialer, got %T", exchanger.dialer)
	}
}

func TestTLSPacketExchangerSuccess(t *testing.T) {
	secret := "shared"
	dialer := &fakeTLSDialer{secret: []byte(secret), responseCode: radiuslib.CodeAccessAccept}
	auth, err := NewAuthenticator(
		"127.0.0.1:2083",
		secret,
		WithTLSConfig(&tls.Config{}),
		WithTLSDialer(dialer),
	)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "user", "password"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestTLSPacketExchangerReject(t *testing.T) {
	secret := "shared"
	dialer := &fakeTLSDialer{secret: []byte(secret), responseCode: radiuslib.CodeAccessReject}
	auth, err := NewAuthenticator(
		"127.0.0.1:2083",
		secret,
		WithTLSConfig(&tls.Config{}),
		WithTLSDialer(dialer),
	)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "user", "password")
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("expected ErrRejected, got %v", err)
	}
}

func TestTLSPacketExchangerNonAuthenticResponse(t *testing.T) {
	secret := "shared"
	dialer := &fakeTLSDialer{secret: []byte(secret), responseCode: radiuslib.CodeAccessAccept, tamper: true}
	auth, err := NewAuthenticator(
		"127.0.0.1:2083",
		secret,
		WithTLSConfig(&tls.Config{}),
		WithTLSDialer(dialer),
		WithMaxPacketErrors(1),
	)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "user", "password")
	var nonAuthErr *radiuslib.NonAuthenticResponseError
	if !errors.As(err, &nonAuthErr) {
		t.Fatalf("expected NonAuthenticResponseError, got %v", err)
	}
}

func TestTLSPacketExchangerParseError(t *testing.T) {
	secret := "shared"
	dialer := &fakeTLSDialer{secret: []byte(secret), responseCode: radiuslib.CodeAccessAccept, malformed: true}
	auth, err := NewAuthenticator(
		"127.0.0.1:2083",
		secret,
		WithTLSConfig(&tls.Config{}),
		WithTLSDialer(dialer),
		WithMaxPacketErrors(1),
	)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "user", "password")
	if err == nil {
		t.Fatalf("expected parse error")
	}
}

func TestTLSPacketExchangerDialError(t *testing.T) {
	secret := "shared"
	dialer := &fakeTLSDialer{secret: []byte(secret), dialErr: errors.New("dial failure")}
	auth, err := NewAuthenticator(
		"127.0.0.1:2083",
		secret,
		WithTLSConfig(&tls.Config{}),
		WithTLSDialer(dialer),
	)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "user", "password")
	if !errors.Is(err, dialer.dialErr) {
		t.Fatalf("expected dial error, got %v", err)
	}
}

func TestTLSPacketExchangerReadError(t *testing.T) {
	secret := "shared"
	dialer := &fakeTLSDialer{secret: []byte(secret), closeWithoutResponse: true}
	auth, err := NewAuthenticator(
		"127.0.0.1:2083",
		secret,
		WithTLSConfig(&tls.Config{}),
		WithTLSDialer(dialer),
	)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "user", "password")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestTLSPacketExchangerContextCancel(t *testing.T) {
	secret := "shared"
	dialer := &fakeTLSDialer{secret: []byte(secret), responseDelay: 200 * time.Millisecond}
	auth, err := NewAuthenticator(
		"127.0.0.1:2083",
		secret,
		WithTLSConfig(&tls.Config{}),
		WithTLSDialer(dialer),
	)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)
	err = auth.Authenticate(ctx, "user", "password")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func TestTLSPacketExchangerRetry(t *testing.T) {
	secret := "shared"
	dialer := &fakeTLSDialer{secret: []byte(secret), responseCode: radiuslib.CodeAccessAccept, responseDelay: 30 * time.Millisecond}
	auth, err := NewAuthenticator(
		"127.0.0.1:2083",
		secret,
		WithTLSConfig(&tls.Config{}),
		WithTLSDialer(dialer),
		WithRetry(5*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "user", "password"); err != nil {
		t.Fatalf("expected success with retry, got %v", err)
	}
}

type fakeTLSDialer struct {
	secret               []byte
	responseCode         radiuslib.Code
	tamper               bool
	dialErr              error
	closeWithoutResponse bool
	responseDelay        time.Duration
	malformed            bool
}

func (d *fakeTLSDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	client, server := net.Pipe()

	go func() {
		defer server.Close()
		buf := make([]byte, radiuslib.MaxPacketLength)
		n, err := server.Read(buf)
		if err != nil {
			return
		}
		if d.closeWithoutResponse {
			return
		}
		if d.responseDelay > 0 {
			select {
			case <-time.After(d.responseDelay):
			case <-ctx.Done():
				return
			}
		}
		req, err := radiuslib.Parse(buf[:n], d.secret)
		if err != nil {
			return
		}
		resp := req.Response(d.responseCode)
		raw, err := resp.Encode()
		if err != nil {
			return
		}
		if d.tamper && len(raw) > 0 {
			raw[0] ^= 0xff
		}
		if d.malformed {
			_, _ = server.Write([]byte("bad"))
			return
		}
		_, _ = server.Write(raw)
	}()

	return client, nil
}
