// Excluded from fips140only builds: RFC 8907 §4.5 obfuscates every packet body
// with an MD5-based keystream, which GODEBUG=fips140=only refuses to execute,
// so these tests cannot run in that build.

//go:build !fips140only

package tacacs

import (
	"context"
	"fmt"
	"strings"
	"testing"

	secretpkg "github.com/jeremyhahn/go-auth/pkg/secret"
)

func TestNewAuthenticatorWithSecretValidatesInputs(t *testing.T) {
	sealed, err := secretpkg.NewString(testSecret)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sealed.Destroy()

	if _, err := NewAuthenticatorWithSecret("", sealed); err == nil {
		t.Error("expected error for empty address")
	}
	if _, err := NewAuthenticatorWithSecret("127.0.0.1:49", nil); err == nil {
		t.Error("expected error for nil secret")
	}

	destroyed, err := secretpkg.NewString(testSecret)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	destroyed.Destroy()
	if _, err := NewAuthenticatorWithSecret("127.0.0.1:49", destroyed); err == nil {
		t.Error("expected error for a destroyed secret")
	}
}

// TestAuthenticateWithProtectedSecret drives a real TACACS+ exchange with the
// shared secret held in protected memory: the server only replies when the
// packet obfuscation keyed by that secret matches, so a successful login is
// proof the sealed key reached the wire intact.
func TestAuthenticateWithProtectedSecret(t *testing.T) {
	addr, cleanup := startTestServer(t, simpleHandler{creds: map[string]string{"user": "pass"}})
	defer cleanup()

	sealed, err := secretpkg.NewString(testSecret)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sealed.Destroy()

	auth, err := NewAuthenticatorWithSecret(addr, sealed, WithPrivLevel(15))
	if err != nil {
		t.Fatalf("NewAuthenticatorWithSecret: %v", err)
	}
	if auth.privLevel != 15 {
		t.Fatalf("privLevel = %d, want 15", auth.privLevel)
	}

	if err := auth.Authenticate(context.Background(), "user", "pass"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := auth.Authenticate(context.Background(), "user", "wrong"); err == nil {
		t.Fatal("expected a rejection for the wrong password")
	}
}

// TestStringConstructorSealsTheSecret checks the deprecated constructor now
// stores its secret the protected way, and that a session keyed from it still
// authenticates.
func TestStringConstructorSealsTheSecret(t *testing.T) {
	addr, cleanup := startTestServer(t, simpleHandler{creds: map[string]string{"user": "pass"}})
	defer cleanup()

	auth, err := NewAuthenticator(addr, testSecret)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if auth.secret == nil {
		t.Fatal("string constructor did not seal the secret")
	}
	if err := auth.Authenticate(context.Background(), "user", "pass"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

// TestSecretIsNeverPlaintextInTheAuthenticator is the verification the issue
// asks for, in the shape this backend allows: the authenticator holds the key
// only in a locked buffer, so nothing in its rendered form is the secret, and
// there is no exported way to reach it.
func TestSecretIsNeverPlaintextInTheAuthenticator(t *testing.T) {
	addr, cleanup := startTestServer(t, simpleHandler{creds: map[string]string{"user": "pass"}})
	defer cleanup()

	sealed, err := secretpkg.NewString(testSecret)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sealed.Destroy()

	auth, err := NewAuthenticatorWithSecret(addr, sealed)
	if err != nil {
		t.Fatalf("NewAuthenticatorWithSecret: %v", err)
	}
	if err := auth.Authenticate(context.Background(), "user", "pass"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	rendered := fmt.Sprintf("%#v %+v", auth, auth)
	if strings.Contains(rendered, testSecret) {
		t.Errorf("authenticator rendered the shared secret: %s", rendered)
	}
}

// TestAuthenticatorCopiesTheSecret pins the ownership rule: the authenticator
// takes its own locked copy, so releasing the caller's secret does not disable
// it. Every other backend borrows instead; TACACS+ copies because tacplus
// reads the key from goroutines nothing joins, so the bytes must stay mapped
// for as long as the authenticator can be used.
func TestAuthenticatorCopiesTheSecret(t *testing.T) {
	addr, cleanup := startTestServer(t, simpleHandler{creds: map[string]string{"user": "pass"}})
	defer cleanup()

	sealed, err := secretpkg.NewString(testSecret)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}

	auth, err := NewAuthenticatorWithSecret(addr, sealed)
	if err != nil {
		t.Fatalf("NewAuthenticatorWithSecret: %v", err)
	}

	sealed.Destroy()

	if err := auth.Authenticate(context.Background(), "user", "pass"); err != nil {
		t.Fatalf("Authenticate after the caller released its secret: %v", err)
	}
}
