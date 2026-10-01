package radius

import (
	"context"
	"errors"
	"runtime"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	radiuslib "layeh.com/radius"
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

// blockingExchanger parks the first exchange until released.
type blockingExchanger struct {
	entered, release chan struct{}
	first            bool
}

func (b *blockingExchanger) exchange(_ context.Context, packet *radiuslib.Packet, _ string) (*radiuslib.Packet, error) {
	if !b.first {
		b.first = true
		close(b.entered)
		<-b.release
	}
	return packet.Response(radiuslib.CodeAccessAccept), nil
}

func TestCloseWaitsForInFlightAuthenticate(t *testing.T) {
	skipUnderFIPSActivation(t)
	ex := &blockingExchanger{entered: make(chan struct{}), release: make(chan struct{})}
	secret := sealed(t, "shared-secret")
	auth, err := NewAuthenticator("127.0.0.1:1812", secret, WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	password := sealed(t, "password")
	closeDuringCall(t, auth, secret, func() error {
		return auth.Authenticate(context.Background(), "jane", password)
	}, ex.entered, ex.release)
}
