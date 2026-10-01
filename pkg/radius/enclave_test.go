package radius

import (
	"bytes"
	"context"
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	radiuslib "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// capturingExchanger records the shared secret and the decrypted
// User-Password the packet carried, as copies taken while the exchange is in
// progress: the packet's Secret aliases the borrowed enclave pages.
type capturingExchanger struct {
	resp     *radiuslib.Packet
	secret   []byte
	password []byte
	called   int
}

func (e *capturingExchanger) exchange(_ context.Context, packet *radiuslib.Packet, _ string) (*radiuslib.Packet, error) {
	e.called++
	e.secret = append([]byte(nil), packet.Secret...)
	pw, err := rfc2865.UserPassword_Lookup(packet)
	if err != nil {
		return nil, err
	}
	e.password = pw
	return e.resp, nil
}

func TestAuthenticateSendsTheEnclaveCredentials(t *testing.T) {
	skipUnderFIPSActivation(t)
	const shared = "shared-secret"

	ex := &capturingExchanger{resp: radiuslib.New(radiuslib.CodeAccessAccept, []byte(shared))}
	auth, err := NewAuthenticator("127.0.0.1:1812", sealed(t, shared), WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Close()

	password := sealed(t, "password")
	if err := auth.Authenticate(context.Background(), "jane", password); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if ex.called != 1 {
		t.Fatalf("exchange called %d times, want 1", ex.called)
	}
	if !bytes.Equal(ex.secret, []byte(shared)) {
		t.Fatalf("packet carried secret %q, want %q", ex.secret, shared)
	}
	if string(ex.password) != "password" {
		t.Fatalf("User-Password decrypted to %q", ex.password)
	}
	if !password.IsAlive() {
		t.Fatal("Authenticate destroyed a borrowed password")
	}
}

func TestNewAuthenticatorDestroysSecretOnRefusal(t *testing.T) {
	skipUnderFIPSActivation(t)
	cases := map[string]func(secret *enclave.MemoryEnclave) (*Authenticator, error){
		"empty address": func(s *enclave.MemoryEnclave) (*Authenticator, error) {
			return NewAuthenticator("", s)
		},
		"TLS without config": func(s *enclave.MemoryEnclave) (*Authenticator, error) {
			return NewAuthenticator("127.0.0.1:2083", s, WithTLSConfig(nil))
		},
	}
	for name, construct := range cases {
		t.Run(name, func(t *testing.T) {
			secret := sealed(t, "shared-secret")
			if _, err := construct(secret); err == nil {
				t.Fatal("construction succeeded")
			}
			if secret.IsAlive() {
				t.Fatal("refused construction left the shared secret alive")
			}
		})
	}
}

func TestNewAuthenticatorRejectsMissingSecret(t *testing.T) {
	skipUnderFIPSActivation(t)
	if _, err := NewAuthenticator("127.0.0.1:1812", nil); !errors.Is(err, ErrMissingSharedSecret) {
		t.Fatalf("nil secret: err = %v, want ErrMissingSharedSecret", err)
	}
	dead := sealed(t, "shared-secret")
	dead.Destroy()
	_, err := NewAuthenticator("127.0.0.1:1812", dead)
	if !errors.Is(err, ErrMissingSharedSecret) || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("destroyed secret: err = %v", err)
	}
}

func TestAuthenticateRejectsDestroyedPassword(t *testing.T) {
	skipUnderFIPSActivation(t)
	ex := &capturingExchanger{resp: radiuslib.New(radiuslib.CodeAccessAccept, []byte("s"))}
	auth, err := NewAuthenticator("127.0.0.1:1812", sealed(t, "s"), WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Close()

	password := sealed(t, "password")
	password.Destroy()
	err = auth.Authenticate(context.Background(), "jane", password)
	if !errors.Is(err, ErrMissingPassword) || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("err = %v, want ErrMissingPassword joined with ErrEnclaveDestroyed", err)
	}
	if ex.called != 0 {
		t.Fatalf("exchange called %d times with a destroyed password", ex.called)
	}
}

// TestCloseDestroysSecretAndRefusesFurtherUse proves the authenticator is the
// owner: Close wipes the shared secret, and nothing is sent afterwards.
func TestCloseDestroysSecretAndRefusesFurtherUse(t *testing.T) {
	skipUnderFIPSActivation(t)
	secret := sealed(t, "shared-secret")
	ex := &capturingExchanger{resp: radiuslib.New(radiuslib.CodeAccessAccept, []byte("shared-secret"))}
	auth, err := NewAuthenticator("127.0.0.1:1812", secret, WithPacketExchanger(ex))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
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
	if err := auth.Authenticate(context.Background(), "jane", sealed(t, "password")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Authenticate after Close = %v, want ErrClosed", err)
	}
	if ex.called != 0 {
		t.Fatalf("exchange called %d times after Close", ex.called)
	}
}
