package radius

import (
	"bytes"
	"context"
	"testing"

	radiuslib "layeh.com/radius"

	secretpkg "github.com/jeremyhahn/go-auth/pkg/secret"
)

// secretCapturingExchanger records the shared secret the packet carried, as a
// copy taken while the exchange is in progress.
//
// The copy is not incidental: the packet's Secret aliases the opened enclave
// buffer, which is unmapped as soon as Authenticate returns. Reading it
// afterwards faults the process, so a test that wants to assert on the key has
// to take its copy here, inside the call.
type secretCapturingExchanger struct {
	resp   *radiuslib.Packet
	seen   []byte
	called int
}

func (e *secretCapturingExchanger) exchange(_ context.Context, packet *radiuslib.Packet, _ string) (*radiuslib.Packet, error) {
	e.called++
	e.seen = append([]byte(nil), packet.Secret...)
	return e.resp, nil
}

func TestNewAuthenticatorWithSecretValidatesInputs(t *testing.T) {
	skipUnderFIPSActivation(t)
	sealed, err := secretpkg.NewString("shared-secret")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sealed.Destroy()

	if _, err := NewAuthenticatorWithSecret("", sealed); err == nil {
		t.Error("expected error for empty address")
	}
	if _, err := NewAuthenticatorWithSecret("127.0.0.1:1812", nil); err == nil {
		t.Error("expected error for nil secret")
	}

	destroyed, err := secretpkg.NewString("shared-secret")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	destroyed.Destroy()
	if _, err := NewAuthenticatorWithSecret("127.0.0.1:1812", destroyed); err == nil {
		t.Error("expected error for a destroyed secret")
	}
}

func TestAuthenticateWithProtectedSecret(t *testing.T) {
	skipUnderFIPSActivation(t)
	const shared = "shared-secret"

	sealed, err := secretpkg.NewString(shared)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sealed.Destroy()

	ex := &secretCapturingExchanger{resp: radiuslib.New(radiuslib.CodeAccessAccept, []byte(shared))}
	auth, err := NewAuthenticatorWithSecret("127.0.0.1:1812", sealed, WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("NewAuthenticatorWithSecret: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "jane", "password"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if ex.called != 1 {
		t.Fatalf("exchange called %d times, want 1", ex.called)
	}
	if !bytes.Equal(ex.seen, []byte(shared)) {
		t.Fatalf("packet carried %q, want %q", ex.seen, shared)
	}
}

// TestStringConstructorSealsTheSecret is the migration check: the deprecated
// string constructor now stores the secret the protected way, so both paths
// put the same bytes on the wire and neither keeps a string field.
func TestStringConstructorSealsTheSecret(t *testing.T) {
	skipUnderFIPSActivation(t)
	const shared = "shared-secret"

	ex := &secretCapturingExchanger{resp: radiuslib.New(radiuslib.CodeAccessAccept, []byte(shared))}
	auth, err := NewAuthenticator("127.0.0.1:1812", shared, WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if auth.secret == nil {
		t.Fatal("string constructor did not seal the secret")
	}

	if err := auth.Authenticate(context.Background(), "jane", "password"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !bytes.Equal(ex.seen, []byte(shared)) {
		t.Fatalf("packet carried %q, want %q", ex.seen, shared)
	}
}

// TestAuthenticateAfterSecretDestroyed proves the authenticator holds no
// plaintext copy of the shared secret: once the caller releases it, no packet
// can be built.
func TestAuthenticateAfterSecretDestroyed(t *testing.T) {
	skipUnderFIPSActivation(t)
	sealed, err := secretpkg.NewString("shared-secret")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}

	ex := &secretCapturingExchanger{resp: radiuslib.New(radiuslib.CodeAccessAccept, []byte("shared-secret"))}
	auth, err := NewAuthenticatorWithSecret("127.0.0.1:1812", sealed, WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("NewAuthenticatorWithSecret: %v", err)
	}

	sealed.Destroy()

	if err := auth.Authenticate(context.Background(), "jane", "password"); err == nil {
		t.Fatal("Authenticate succeeded after the secret was destroyed")
	}
	if ex.called != 0 {
		t.Fatalf("exchange was called %d times after the secret was destroyed", ex.called)
	}
}
