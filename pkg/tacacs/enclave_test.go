package tacacs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// TestAuthenticateWithEnclaveCredentials drives a real TACACS+ exchange: the
// server only replies when the packet obfuscation keyed by the shared secret
// matches, so a successful login proves the borrowed key reached tacplus
// intact, and the pass/fail split proves the password did.
func TestAuthenticateWithEnclaveCredentials(t *testing.T) {
	skipUnderFIPSActivation(t)
	addr, cleanup := startTestServer(t, simpleHandler{creds: map[string]string{"user": "pass"}})
	defer cleanup()

	auth, err := NewAuthenticator(addr, sealed(t, testSecret), WithPrivLevel(15))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Close()
	if auth.privLevel != 15 {
		t.Fatalf("privLevel = %d, want 15", auth.privLevel)
	}

	password := sealed(t, "pass")
	if err := auth.Authenticate(context.Background(), "user", password); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !password.IsAlive() {
		t.Fatal("Authenticate destroyed a borrowed password")
	}
	if err := auth.Authenticate(context.Background(), "user", sealed(t, "wrong")); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("wrong password: err = %v, want ErrAuthenticationFailed", err)
	}
}

// TestCloseDestroysSecretAfterUse proves the authenticator now has a release
// point: after real exchanges, Close unmaps the key tacplus was lent, and the
// authenticator refuses further use instead of handing tacplus dead pages.
func TestCloseDestroysSecretAfterUse(t *testing.T) {
	skipUnderFIPSActivation(t)
	addr, cleanup := startTestServer(t, simpleHandler{creds: map[string]string{"user": "pass"}})
	defer cleanup()

	secret := sealed(t, testSecret)
	auth, err := NewAuthenticator(addr, secret)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := auth.Authenticate(context.Background(), "user", sealed(t, "pass")); err != nil {
			t.Fatalf("Authenticate #%d: %v", i, err)
		}
	}

	if err := auth.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if secret.IsAlive() {
		t.Fatal("Close left the shared secret alive")
	}
	if err := auth.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := auth.Authenticate(context.Background(), "user", sealed(t, "pass")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Authenticate after Close = %v, want ErrClosed", err)
	}
}

func TestNewAuthenticatorDestroysSecretOnRefusal(t *testing.T) {
	skipUnderFIPSActivation(t)
	secret := sealed(t, testSecret)
	if _, err := NewAuthenticator("", secret); !errors.Is(err, ErrEmptyAddress) {
		t.Fatalf("err = %v, want ErrEmptyAddress", err)
	}
	if secret.IsAlive() {
		t.Fatal("refused construction left the shared secret alive")
	}
}

func TestNewAuthenticatorRejectsMissingSecret(t *testing.T) {
	skipUnderFIPSActivation(t)
	if _, err := NewAuthenticator("127.0.0.1:49", nil); !errors.Is(err, ErrMissingSharedSecret) {
		t.Fatalf("nil secret: err = %v, want ErrMissingSharedSecret", err)
	}
	dead := sealed(t, testSecret)
	dead.Destroy()
	_, err := NewAuthenticator("127.0.0.1:49", dead)
	if !errors.Is(err, ErrMissingSharedSecret) || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("destroyed secret: err = %v", err)
	}
}

func TestAuthenticateRejectsDestroyedPassword(t *testing.T) {
	skipUnderFIPSActivation(t)
	auth, err := NewAuthenticator("127.0.0.1:0", sealed(t, testSecret))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Close()

	password := sealed(t, "pass")
	password.Destroy()
	err = auth.Authenticate(context.Background(), "user", password)
	if !errors.Is(err, ErrMissingPassword) || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("err = %v, want ErrMissingPassword joined with ErrEnclaveDestroyed", err)
	}
}

// TestSecretIsNeverRenderedByTheAuthenticator: the key lives only in the
// enclave, whose String method redacts it, so no formatting of the
// authenticator can print it.
func TestSecretIsNeverRenderedByTheAuthenticator(t *testing.T) {
	skipUnderFIPSActivation(t)
	auth, err := NewAuthenticator("127.0.0.1:49", sealed(t, testSecret))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Close()

	rendered := fmt.Sprintf("%v %+v %s", auth, auth, auth.secret)
	if strings.Contains(rendered, testSecret) {
		t.Errorf("authenticator rendered the shared secret: %s", rendered)
	}
}
