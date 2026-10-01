package ldapauth

import (
	"context"
	"errors"
	"runtime"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// waitForPendingClose returns once a Close is blocked on the lifecycle lock,
// or once Close has returned (the defect this guards against). A pending
// writer makes TryRLock fail, so this is a synchronization point, not a
// timing guess.
func waitForPendingClose(a *Authenticator, closeReturned <-chan struct{}) {
	for a.lifecycle.TryRLock() {
		a.lifecycle.RUnlock()
		select {
		case <-closeReturned:
			return
		default:
		}
		runtime.Gosched()
	}
}

// closeDuringCall drives the lifecycle contract: Close waits for an in-flight
// call, the call completes with the credential intact, and Close then
// destroys it and refuses further use. call starts an authentication;
// entered is closed once it is blocked mid-exchange, and closing release lets
// it continue.
func closeDuringCall(t *testing.T, auth *Authenticator, credential *enclave.MemoryEnclave, call func() error, entered, release chan struct{}) {
	t.Helper()
	callErr := make(chan error, 1)
	go func() { callErr <- call() }()
	<-entered

	closeDone := make(chan error, 1)
	closeReturned := make(chan struct{})
	go func() {
		closeDone <- auth.Close()
		close(closeReturned)
	}()
	waitForPendingClose(auth, closeReturned)

	select {
	case <-closeReturned:
		close(release)
		t.Fatal("Close returned while an authentication was in flight")
	default:
	}
	if !credential.IsAlive() {
		t.Fatal("the credential was destroyed under an in-flight authentication")
	}

	close(release)
	if err := <-callErr; err != nil {
		t.Fatalf("in-flight authentication failed: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if credential.IsAlive() {
		t.Fatal("Close left the credential alive")
	}
	if err := call(); !errors.Is(err, ErrClosed) {
		t.Fatalf("call after Close = %v, want ErrClosed", err)
	}
}

// TestCloseWaitsForInFlightAuthenticate blocks an Authenticate in its dial —
// before the service bind has borrowed the password — and closes underneath
// it. The service bind must still find the password alive.
func TestCloseWaitsForInFlightAuthenticate(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	first := true
	conn := &fakeConn{}
	service := pw(t, "service-password")
	auth, err := NewAuthenticator("ldap://example.com:389",
		WithUserDNTemplate("cn=%s,dc=example,dc=com"),
		WithServiceAccount("cn=admin,dc=example,dc=com", service),
		WithDialContext(func(context.Context) (ldapConn, error) {
			if first {
				first = false
				close(entered)
				<-release
			}
			return conn, nil
		}))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	password := pw(t, "pass")
	closeDuringCall(t, auth, service, func() error {
		return auth.Authenticate(context.Background(), "user", password)
	}, entered, release)

	if len(conn.binds) != 2 || conn.binds[0].password != "service-password" {
		t.Fatalf("binds = %+v, want the service bind with the real password, then the user bind", conn.binds)
	}
}
