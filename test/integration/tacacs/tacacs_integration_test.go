//go:build integration

package tacacs_test

import (
	"context"
	"net"
	"testing"
	"time"

	tacacslib "github.com/jhahn/go-auth/pkg/tacacs"
	tacplus "github.com/nwaples/tacplus"
)

const tacacsSecret = "sharedsecret"

func startIntegrationServer(t *testing.T) (addr string, cleanup func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	handler := &tacplus.ServerConnHandler{
		Handler: testHandler{},
		ConnConfig: tacplus.ConnConfig{
			Secret: []byte(tacacsSecret),
		},
	}

	srv := &tacplus.Server{
		ServeConn: func(conn net.Conn) {
			defer conn.Close()
			handler.Serve(conn)
		},
	}

	go func() {
		_ = srv.Serve(ln)
	}()

	cleanup = func() {
		_ = ln.Close()
	}

	return ln.Addr().String(), cleanup
}

type testHandler struct{}

func (testHandler) HandleAuthenStart(ctx context.Context, start *tacplus.AuthenStart, session *tacplus.ServerSession) *tacplus.AuthenReply {
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

	if user == "tacacsuser" && pass == "tacacspass" {
		return &tacplus.AuthenReply{Status: tacplus.AuthenStatusPass}
	}
	if user == "delayed" {
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return &tacplus.AuthenReply{Status: tacplus.AuthenStatusError, ServerMsg: ctx.Err().Error()}
		}
		return &tacplus.AuthenReply{Status: tacplus.AuthenStatusPass}
	}
	return &tacplus.AuthenReply{Status: tacplus.AuthenStatusFail}
}

func (testHandler) HandleAuthorRequest(context.Context, *tacplus.AuthorRequest, *tacplus.ServerSession) *tacplus.AuthorResponse {
	return &tacplus.AuthorResponse{Status: tacplus.AuthorStatusPassAdd}
}

func (testHandler) HandleAcctRequest(context.Context, *tacplus.AcctRequest, *tacplus.ServerSession) *tacplus.AcctReply {
	return &tacplus.AcctReply{Status: tacplus.AcctStatusSuccess}
}

func TestAuthenticateSuccess(t *testing.T) {
	addr, cleanup := startIntegrationServer(t)
	defer cleanup()

	auth, err := tacacslib.NewAuthenticator(addr, tacacsSecret, tacacslib.WithTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := auth.Authenticate(ctx, "tacacsuser", "tacacspass"); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestAuthenticateRejectsWrongPassword(t *testing.T) {
	addr, cleanup := startIntegrationServer(t)
	defer cleanup()

	auth, err := tacacslib.NewAuthenticator(addr, tacacsSecret)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "tacacsuser", "wrongpass"); err == nil {
		t.Fatal("expected failure for wrong password")
	}
}

func TestAuthenticateRejectsUnknownUser(t *testing.T) {
	addr, cleanup := startIntegrationServer(t)
	defer cleanup()

	auth, err := tacacslib.NewAuthenticator(addr, tacacsSecret)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "ghost", "whatever"); err == nil {
		t.Fatal("expected failure for unknown user")
	}
}
