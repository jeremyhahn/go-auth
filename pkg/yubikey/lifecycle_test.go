package yubikey

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// splitBorrowValidator borrows the API key, blocks — as HTTPValidator does
// between signing the request and verifying the response — and borrows it
// again afterwards.
type splitBorrowValidator struct {
	entered chan struct{}
	release chan struct{}
}

func (v *splitBorrowValidator) Validate(_ context.Context, _ string, apiKey, _ *enclave.MemoryEnclave) error {
	if err := apiKey.WithBytes(func([]byte) error { return nil }); err != nil {
		return err
	}
	close(v.entered)
	<-v.release
	return apiKey.WithBytes(func([]byte) error { return nil })
}

// closeDuringCall drives the lifecycle contract: Close waits for an in-flight
// call, the call completes with the credential intact, and Close then
// destroys it and refuses further use.
func closeDuringCall(t *testing.T, auth *Authenticator, key *enclave.MemoryEnclave, entered, release chan struct{}) {
	t.Helper()
	callErr := make(chan error, 1)
	go func() {
		callErr <- auth.Authenticate(context.Background(), sealed(t, "ccccccbchvth"))
	}()
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
		t.Fatal("Close returned while a validation was in flight")
	default:
	}
	if !key.IsAlive() {
		t.Fatal("the API key was destroyed under an in-flight validation")
	}

	close(release)
	if err := <-callErr; err != nil {
		t.Fatalf("in-flight validation failed: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if key.IsAlive() {
		t.Fatal("Close left the API key alive")
	}
	if err := auth.Authenticate(context.Background(), sealed(t, "ccccccbchvth")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Authenticate after Close = %v, want ErrClosed", err)
	}
}

func TestCloseWaitsForInFlightValidation(t *testing.T) {
	v := &splitBorrowValidator{entered: make(chan struct{}), release: make(chan struct{})}
	key := sealed(t, "a2V5")
	auth, err := NewAuthenticator(Config{ClientID: "id", APIKey: key}, v)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	closeDuringCall(t, auth, key, v.entered, v.release)
}

// TestCloseWaitsForInFlightYubiCloudExchange is the reported case: the
// YubiCloud response arrives after Close was called, and its signature must
// still be verifiable with the API key.
func TestCloseWaitsForInFlightYubiCloudExchange(t *testing.T) {
	skipUnderFIPSActivation(t)
	rawKey := []byte("my-api-key-bytes")
	entered := make(chan struct{})
	release := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		query := r.URL.Query()
		reply := url.Values{}
		reply.Set("status", "OK")
		reply.Set("nonce", query.Get("nonce"))
		reply.Set("otp", query.Get("otp"))
		fmt.Fprintf(w, "status=OK\nnonce=%s\notp=%s\nh=%s\n",
			reply.Get("nonce"), reply.Get("otp"), referenceSignature(reply, rawKey))
	}))
	defer server.Close()

	key := sealed(t, "bXktYXBpLWtleS1ieXRlcw==") // base64 of rawKey
	auth, err := NewAuthenticator(Config{ClientID: "id", APIKey: key}, NewHTTPValidator(server.Client(), server.URL))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	closeDuringCall(t, auth, key, entered, release)
}
