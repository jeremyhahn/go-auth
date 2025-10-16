package tacacs

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	tacplus "github.com/nwaples/tacplus"
)

const testSecret = "sharedsecret"

type simpleHandler struct {
	creds map[string]string
	delay time.Duration
}

func (h simpleHandler) HandleAuthenStart(ctx context.Context, start *tacplus.AuthenStart, session *tacplus.ServerSession) *tacplus.AuthenReply {
	if h.delay > 0 {
		select {
		case <-time.After(h.delay):
		case <-ctx.Done():
			return &tacplus.AuthenReply{Status: tacplus.AuthenStatusError, ServerMsg: ctx.Err().Error()}
		}
	}

	user := start.User
	for user == "" {
		cont, err := session.GetUser(ctx, "Username:")
		if err != nil || cont == nil {
			return &tacplus.AuthenReply{Status: tacplus.AuthenStatusError, ServerMsg: "user prompt failed"}
		}
		if cont.Abort {
			return nil
		}
		user = cont.Message
	}

	password := ""
	for password == "" {
		cont, err := session.GetPass(ctx, "Password:")
		if err != nil || cont == nil {
			return &tacplus.AuthenReply{Status: tacplus.AuthenStatusError, ServerMsg: "password prompt failed"}
		}
		if cont.Abort {
			return nil
		}
		password = cont.Message
	}

	expected, ok := h.creds[user]
	if !ok || expected != password {
		return &tacplus.AuthenReply{Status: tacplus.AuthenStatusFail}
	}
	return &tacplus.AuthenReply{Status: tacplus.AuthenStatusPass}
}

func (h simpleHandler) HandleAuthorRequest(ctx context.Context, req *tacplus.AuthorRequest, session *tacplus.ServerSession) *tacplus.AuthorResponse {
	return &tacplus.AuthorResponse{Status: tacplus.AuthorStatusPassAdd}
}

func (h simpleHandler) HandleAcctRequest(ctx context.Context, req *tacplus.AcctRequest, session *tacplus.ServerSession) *tacplus.AcctReply {
	return &tacplus.AcctReply{Status: tacplus.AcctStatusSuccess}
}

type tokenHandler struct{}

func (tokenHandler) HandleAuthenStart(ctx context.Context, start *tacplus.AuthenStart, session *tacplus.ServerSession) *tacplus.AuthenReply {
	user := start.User
	for user == "" {
		cont, err := session.GetUser(ctx, "Username:")
		if err != nil || cont == nil || cont.Abort {
			return &tacplus.AuthenReply{Status: tacplus.AuthenStatusError, ServerMsg: "user prompt failed"}
		}
		user = cont.Message
	}

	pass := ""
	for pass == "" {
		cont, err := session.GetPass(ctx, "Password:")
		if err != nil || cont == nil || cont.Abort {
			return &tacplus.AuthenReply{Status: tacplus.AuthenStatusError, ServerMsg: "password prompt failed"}
		}
		pass = cont.Message
	}

	cont, err := session.GetData(ctx, "Token:", false)
	if err != nil || cont == nil || cont.Abort {
		return &tacplus.AuthenReply{Status: tacplus.AuthenStatusError, ServerMsg: "token prompt failed"}
	}
	token := cont.Message

	if user == "user" && pass == "token" && token == "token" {
		return &tacplus.AuthenReply{Status: tacplus.AuthenStatusPass}
	}
	return &tacplus.AuthenReply{Status: tacplus.AuthenStatusFail}
}

func (tokenHandler) HandleAuthorRequest(context.Context, *tacplus.AuthorRequest, *tacplus.ServerSession) *tacplus.AuthorResponse {
	return &tacplus.AuthorResponse{Status: tacplus.AuthorStatusPassAdd}
}

func (tokenHandler) HandleAcctRequest(context.Context, *tacplus.AcctRequest, *tacplus.ServerSession) *tacplus.AcctReply {
	return &tacplus.AcctReply{Status: tacplus.AcctStatusSuccess}
}

func startTestServer(t *testing.T, handler tacplus.RequestHandler) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	connHandler := &tacplus.ServerConnHandler{
		Handler: handler,
		ConnConfig: tacplus.ConnConfig{
			Secret: []byte(testSecret),
		},
	}

	srv := &tacplus.Server{
		ServeConn: func(conn net.Conn) {
			defer conn.Close()
			connHandler.Serve(conn)
		},
	}

	go func() {
		_ = srv.Serve(ln)
	}()

	cleanup := func() {
		_ = ln.Close()
	}

	return ln.Addr().String(), cleanup
}

func TestAuthenticateSuccess(t *testing.T) {
	addr, cleanup := startTestServer(t, simpleHandler{creds: map[string]string{"user": "pass"}})
	defer cleanup()

	auth, err := NewAuthenticator(addr, testSecret)
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "user", "pass"); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestAuthenticateInvalidCredentials(t *testing.T) {
	addr, cleanup := startTestServer(t, simpleHandler{creds: map[string]string{"user": "pass"}})
	defer cleanup()

	auth, err := NewAuthenticator(addr, testSecret)
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	err = auth.Authenticate(context.Background(), "user", "wrong")
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("expected ErrAuthenticationFailed, got %v", err)
	}
}

func TestAuthenticateServerError(t *testing.T) {
	addr, cleanup := startTestServer(t, requestHandlerFunc(func(ctx context.Context, start *tacplus.AuthenStart, session *tacplus.ServerSession) *tacplus.AuthenReply {
		return &tacplus.AuthenReply{Status: tacplus.AuthenStatusError, ServerMsg: "boom"}
	}))
	defer cleanup()

	auth, err := NewAuthenticator(addr, testSecret)
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	err = auth.Authenticate(context.Background(), "user", "pass")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected server error, got %v", err)
	}
}

func TestAuthenticateContextDeadline(t *testing.T) {
	addr, cleanup := startTestServer(t, simpleHandler{creds: map[string]string{"user": "pass"}, delay: 200 * time.Millisecond})
	defer cleanup()

	auth, err := NewAuthenticator(addr, testSecret, WithTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()

	if err := auth.Authenticate(ctx, "user", "pass"); err == nil {
		t.Fatalf("expected timeout error")
	}
}

func TestAuthenticateInputValidation(t *testing.T) {
	auth, err := NewAuthenticator("127.0.0.1:49", testSecret)
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "", "pass"); err == nil {
		t.Fatalf("expected error for empty username")
	}

	if err := auth.Authenticate(context.Background(), "user", ""); err == nil {
		t.Fatalf("expected error for empty password")
	}
}

func TestAuthenticateWithAdditionalData(t *testing.T) {
	addr, cleanup := startTestServer(t, tokenHandler{})
	defer cleanup()

	auth, err := NewAuthenticator(addr, testSecret)
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "user", "token"); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

type requestHandlerFunc func(context.Context, *tacplus.AuthenStart, *tacplus.ServerSession) *tacplus.AuthenReply

func (f requestHandlerFunc) HandleAuthenStart(ctx context.Context, start *tacplus.AuthenStart, session *tacplus.ServerSession) *tacplus.AuthenReply {
	return f(ctx, start, session)
}

func (requestHandlerFunc) HandleAuthorRequest(ctx context.Context, req *tacplus.AuthorRequest, session *tacplus.ServerSession) *tacplus.AuthorResponse {
	return &tacplus.AuthorResponse{Status: tacplus.AuthorStatusPassAdd}
}

func (requestHandlerFunc) HandleAcctRequest(ctx context.Context, req *tacplus.AcctRequest, session *tacplus.ServerSession) *tacplus.AcctReply {
	return &tacplus.AcctReply{Status: tacplus.AcctStatusSuccess}
}

type captureHandler struct {
	priv uint8
}

func (c *captureHandler) HandleAuthenStart(ctx context.Context, start *tacplus.AuthenStart, session *tacplus.ServerSession) *tacplus.AuthenReply {
	c.priv = start.PrivLvl
	return &tacplus.AuthenReply{Status: tacplus.AuthenStatusFail}
}

func (*captureHandler) HandleAuthorRequest(context.Context, *tacplus.AuthorRequest, *tacplus.ServerSession) *tacplus.AuthorResponse {
	return &tacplus.AuthorResponse{Status: tacplus.AuthorStatusFail}
}

func (*captureHandler) HandleAcctRequest(context.Context, *tacplus.AcctRequest, *tacplus.ServerSession) *tacplus.AcctReply {
	return &tacplus.AcctReply{Status: tacplus.AcctStatusError}
}

func TestAuthenticatorOptions(t *testing.T) {
	handler := &captureHandler{}
	addr, cleanup := startTestServer(t, handler)
	defer cleanup()

	dialCount := 0
	auth, err := NewAuthenticator(addr, testSecret, WithPrivLevel(15), WithDialContext(func(ctx context.Context, network, address string) (net.Conn, error) {
		dialCount++
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	err = auth.Authenticate(context.Background(), "user", "pass")
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("expected ErrAuthenticationFailed, got %v", err)
	}
	if handler.priv != 15 {
		t.Fatalf("expected privilege level 15, got %d", handler.priv)
	}
	if dialCount == 0 {
		t.Fatalf("expected custom dialer to be invoked")
	}
}

func TestHandleReplyNilSession(t *testing.T) {
	auth, err := NewAuthenticator("127.0.0.1:0", testSecret)
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	err = auth.handleReply(context.Background(), nil, &tacplus.AuthenReply{Status: tacplus.AuthenStatusGetPass}, "user", "pass")
	if err == nil {
		t.Fatalf("expected error when session is nil")
	}
}

func TestHandleReplyUnknownStatus(t *testing.T) {
	auth, err := NewAuthenticator("127.0.0.1:0", testSecret)
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	err = auth.handleReply(context.Background(), nil, &tacplus.AuthenReply{Status: 0xff}, "user", "pass")
	if err == nil {
		t.Fatalf("expected error for unsupported status")
	}
}

func TestHandleReplyRestartNilSession(t *testing.T) {
	auth, err := NewAuthenticator("127.0.0.1:0", testSecret)
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	err = auth.handleReply(context.Background(), nil, &tacplus.AuthenReply{Status: tacplus.AuthenStatusRestart}, "user", "pass")
	if err == nil {
		t.Fatalf("expected error when restart requested without session")
	}
}

func TestHandleReplyErrorWithoutMessage(t *testing.T) {
	auth, err := NewAuthenticator("127.0.0.1:0", testSecret)
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	err = auth.handleReply(context.Background(), nil, &tacplus.AuthenReply{Status: tacplus.AuthenStatusError}, "user", "pass")
	if err == nil {
		t.Fatalf("expected authentication error without message")
	}
}
