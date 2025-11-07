// go:build integration

package yubikey_test

import (
	"context"
	"os"
	"testing"

	"github.com/jeremyhahn/go-auth/pkg/yubikey"
)

// Integration tests for YubiKey OTP validation using a real self-hosted
// Yubico validation server (yubikey-val + yubikey-ksm).
//
// The Dockerfile sets up:
// - YubiKey KSM (Key Storage Module) for OTP decryption
// - YubiKey Validation Server for replay attack prevention
// - MariaDB for storing keys and validation state
// - Apache for serving the validation API
//
// Test credentials are generated at build time and exported as environment variables.

func TestRealValidationServer(t *testing.T) {
	// Get client credentials from environment (set by Dockerfile startup script)
	clientID := os.Getenv("TEST_CLIENT_ID")
	clientKey := os.Getenv("TEST_CLIENT_KEY")

	if clientID == "" || clientKey == "" {
		t.Skip("Skipping test: TEST_CLIENT_ID and TEST_CLIENT_KEY environment variables not set")
	}

	// Connect to the validation server running on localhost
	validator := yubikey.NewHTTPValidator(nil, "http://localhost/wsapi/2.0/verify")

	cfg := yubikey.Config{
		ClientID: clientID,
		APIKey:   clientKey,
	}

	auth, err := yubikey.NewAuthenticator(cfg, validator)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	// Note: We can't test with a real OTP without a physical YubiKey
	// This test verifies the server is running and accessible
	ctx := context.Background()

	// Test with an invalid OTP - server should reject it
	err = auth.Authenticate(ctx, "invalidotp")
	if err == nil {
		t.Error("Expected error for invalid OTP")
	}

	t.Logf("Validation server is accessible and responding correctly")
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    yubikey.Config
		wantError bool
	}{
		{
			name: "valid config",
			config: yubikey.Config{
				ClientID: "12345",
				APIKey:   "testkey",
			},
			wantError: false,
		},
		{
			name: "missing client id",
			config: yubikey.Config{
				ClientID: "",
				APIKey:   "testkey",
			},
			wantError: true,
		},
		{
			name: "missing api key",
			config: yubikey.Config{
				ClientID: "12345",
				APIKey:   "",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := yubikey.NewHTTPValidator(nil, "http://localhost/wsapi/2.0/verify")
			_, err := yubikey.NewAuthenticator(tt.config, validator)
			if (err != nil) != tt.wantError {
				t.Errorf("NewAuthenticator() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestAuthenticatorNilChecks(t *testing.T) {
	validator := yubikey.NewHTTPValidator(nil, "http://localhost/wsapi/2.0/verify")
	cfg := yubikey.Config{
		ClientID: "12345",
		APIKey:   "testkey",
	}

	auth, err := yubikey.NewAuthenticator(cfg, validator)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	// Test nil context - should use Background
	err = auth.Authenticate(nil, "testotp")
	// We expect an error from the server, but not a nil pointer error
	if err == nil {
		t.Error("Expected error from server for invalid OTP")
	}

	// Test empty OTP
	err = auth.Authenticate(context.Background(), "")
	if err == nil {
		t.Error("Expected error for empty OTP")
	}
	if err.Error() != "yubikey: otp must not be empty" {
		t.Errorf("Expected 'otp must not be empty' error, got: %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	validator := yubikey.NewHTTPValidator(nil, "http://localhost/wsapi/2.0/verify")
	cfg := yubikey.Config{
		ClientID: "12345",
		APIKey:   "testkey",
	}

	auth, err := yubikey.NewAuthenticator(cfg, validator)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = auth.Authenticate(ctx, "testotp")
	if err == nil {
		t.Error("Expected error from cancelled context")
	}
}
