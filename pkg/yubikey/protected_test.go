package yubikey

import (
	"context"
	"testing"

	secretpkg "github.com/jeremyhahn/go-auth/pkg/secret"
)

// protectedValidator implements both validator interfaces so a test can see
// which one the authenticator chose.
type protectedValidator struct {
	fakeValidator
	protectedCalls int
	protectedKey   string
}

func (p *protectedValidator) ValidateProtected(_ context.Context, clientID string, apiKey *secretpkg.Secret, otp string) error {
	p.protectedCalls++
	p.lastClient = clientID
	p.lastOTP = otp
	if err := apiKey.OpenString(func(key string) error { p.protectedKey = key; return nil }); err != nil {
		return err
	}
	return p.err
}

func TestConfigValidateProtectedAPIKey(t *testing.T) {
	sealed, err := secretpkg.NewString("api-key")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sealed.Destroy()

	if err := (Config{ClientID: "id", ProtectedAPIKey: sealed}).validate(); err != nil {
		t.Errorf("protected key rejected: %v", err)
	}
	if err := (Config{ClientID: "id", APIKey: "api-key", ProtectedAPIKey: sealed}).validate(); err == nil {
		t.Error("both key forms accepted")
	}

	destroyed, err := secretpkg.NewString("api-key")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	destroyed.Destroy()
	if err := (Config{ClientID: "id", ProtectedAPIKey: destroyed}).validate(); err == nil {
		t.Error("destroyed key accepted")
	}
}

func TestAuthenticatePrefersTheProtectedValidator(t *testing.T) {
	const apiKey = "bXktYXBpLWtleQ=="

	sealed, err := secretpkg.NewString(apiKey)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sealed.Destroy()

	validator := &protectedValidator{}
	auth, err := NewAuthenticator(Config{ClientID: "id", ProtectedAPIKey: sealed}, validator)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if err := auth.Authenticate(context.Background(), "ccccccbdefgh"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if validator.protectedCalls != 1 {
		t.Fatalf("ValidateProtected called %d times, want 1", validator.protectedCalls)
	}
	if validator.calls != 0 {
		t.Fatalf("the deprecated Validate was called %d times", validator.calls)
	}
	if validator.protectedKey != apiKey {
		t.Fatalf("validator saw key %q, want %q", validator.protectedKey, apiKey)
	}
}

// TestAuthenticateSealsTheStringAPIKey checks the internal migration: a config
// still using the deprecated string field reaches a protected validator as a
// sealed secret rather than as a string.
func TestAuthenticateSealsTheStringAPIKey(t *testing.T) {
	const apiKey = "bXktYXBpLWtleQ=="

	validator := &protectedValidator{}
	auth, err := NewAuthenticator(Config{ClientID: "id", APIKey: apiKey}, validator)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if err := auth.Authenticate(context.Background(), "ccccccbdefgh"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if validator.protectedCalls != 1 {
		t.Fatalf("ValidateProtected called %d times, want 1", validator.protectedCalls)
	}
	if validator.protectedKey != apiKey {
		t.Fatalf("validator saw key %q, want %q", validator.protectedKey, apiKey)
	}
}

// TestAuthenticateFallsBackToTheStringValidator keeps the deprecated interface
// working: a validator that only implements OTPValidator is still called, with
// the key opened for the duration of that call.
func TestAuthenticateFallsBackToTheStringValidator(t *testing.T) {
	const apiKey = "bXktYXBpLWtleQ=="

	sealed, err := secretpkg.NewString(apiKey)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sealed.Destroy()

	validator := &fakeValidator{}
	auth, err := NewAuthenticator(Config{ClientID: "id", ProtectedAPIKey: sealed}, validator)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if err := auth.Authenticate(context.Background(), "ccccccbdefgh"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if validator.calls != 1 {
		t.Fatalf("Validate called %d times, want 1", validator.calls)
	}
	if validator.lastKey != apiKey {
		t.Fatalf("validator saw key %q, want %q", validator.lastKey, apiKey)
	}
}

// TestAuthenticateAfterAPIKeyDestroyed proves nothing in the authenticator
// caches the plaintext key between calls.
func TestAuthenticateAfterAPIKeyDestroyed(t *testing.T) {
	sealed, err := secretpkg.NewString("bXktYXBpLWtleQ==")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}

	validator := &protectedValidator{}
	auth, err := NewAuthenticator(Config{ClientID: "id", ProtectedAPIKey: sealed}, validator)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	sealed.Destroy()

	if err := auth.Authenticate(context.Background(), "ccccccbdefgh"); err == nil {
		t.Fatal("Authenticate succeeded after the API key was destroyed")
	}
}
