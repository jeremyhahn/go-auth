//go:build integration

package otp_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jhahn/go-auth/pkg/otp"
)

func TestIntegration_TOTP_EndToEnd(t *testing.T) {
	// Test complete TOTP workflow: secret generation → provisioning URI → code validation
	secret, err := otp.GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	// Test with multiple configurations
	tests := []struct {
		name      string
		algorithm otp.Algorithm
		digits    uint
	}{
		{"SHA1_6digits", otp.AlgorithmSHA1, 6},
		{"SHA256_6digits", otp.AlgorithmSHA256, 6},
		{"SHA512_6digits", otp.AlgorithmSHA512, 6},
		{"SHA1_7digits", otp.AlgorithmSHA1, 7},
		{"SHA1_8digits", otp.AlgorithmSHA1, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := otp.Config{
				Type:        otp.TypeTOTP,
				Secret:      secret,
				Issuer:      "IntegrationTest",
				AccountName: "test@example.com",
				Algorithm:   tt.algorithm,
				Digits:      tt.digits,
				Period:      30,
				Skew:        1,
			}

			auth, err := otp.NewAuthenticator(cfg)
			if err != nil {
				t.Fatalf("Failed to create authenticator: %v", err)
			}

			// Verify provisioning URI is generated
			uri := auth.GetProvisioningURI()
			if uri == "" {
				t.Error("Provisioning URI is empty")
			}
			if len(uri) < 15 || uri[:15] != "otpauth://totp/" {
				t.Errorf("Invalid URI scheme, expected otpauth://totp/, got: %s", uri)
			}

			// Generate current TOTP code
			code, err := auth.Generate()
			if err != nil {
				t.Fatalf("Failed to generate code: %v", err)
			}

			if len(code) != int(tt.digits) {
				t.Errorf("Expected %d digit code, got %d digits: %s", tt.digits, len(code), code)
			}

			// Validate the generated code
			ctx := context.Background()
			if err := auth.Authenticate(ctx, code); err != nil {
				t.Errorf("Failed to validate generated code: %v", err)
			}
		})
	}
}

func TestIntegration_TOTP_TimeSkew(t *testing.T) {
	secret, err := otp.GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	cfg := otp.Config{
		Type:        otp.TypeTOTP,
		Secret:      secret,
		Issuer:      "SkewTest",
		AccountName: "skew@example.com",
		Period:      2, // Short period for faster testing
		Skew:        2, // Allow ±2 periods
	}

	auth, err := otp.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	ctx := context.Background()

	// Generate code at current time
	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	// Code should be valid immediately
	if err := auth.Authenticate(ctx, code); err != nil {
		t.Errorf("Code should be valid immediately: %v", err)
	}

	// Wait for next period
	time.Sleep(2 * time.Second)

	// Code should still be valid within skew window
	if err := auth.Authenticate(ctx, code); err != nil {
		t.Errorf("Code should be valid within skew window: %v", err)
	}

	// Wait until code is definitely expired (beyond skew window)
	time.Sleep(5 * time.Second)

	// Code should now be expired
	if err := auth.Authenticate(ctx, code); err == nil {
		t.Error("Code should be expired after skew window")
	}
}

func TestIntegration_HOTP_EndToEnd(t *testing.T) {
	// Test complete HOTP workflow with counter management
	secret, err := otp.GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	cfg := otp.Config{
		Type:        otp.TypeHOTP,
		Secret:      secret,
		Issuer:      "HOTPTest",
		AccountName: "hotp@example.com",
		Counter:     0,
	}

	auth, err := otp.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	ctx := context.Background()

	// Test counter progression 0 → 1 → 2 → 3 → 4
	for counter := uint64(0); counter < 5; counter++ {
		t.Run(fmt.Sprintf("counter_%d", counter), func(t *testing.T) {
			// Generate code for this counter
			code, err := auth.Generate(counter)
			if err != nil {
				t.Fatalf("Failed to generate code for counter %d: %v", counter, err)
			}

			// Validate and get new counter
			newCounter, err := auth.ValidateCounter(ctx, code, counter)
			if err != nil {
				t.Errorf("Failed to validate code for counter %d: %v", counter, err)
			}

			if newCounter != counter+1 {
				t.Errorf("Expected counter %d, got %d", counter+1, newCounter)
			}

			// Verify code with old counter is still mathematically valid
			// (replay prevention is handled at application level by tracking counter)
			if _, err := auth.ValidateCounter(ctx, code, counter); err != nil {
				t.Errorf("Code should still be valid for counter %d: %v", counter, err)
			}

			// Verify code does NOT work with wrong counter
			if _, err := auth.ValidateCounter(ctx, code, counter+2); err == nil {
				t.Error("Code should not be valid for wrong counter")
			}
		})
	}
}

func TestIntegration_MultiUser(t *testing.T) {
	// Test multiple users with different secrets
	ctx := context.Background()

	// Create two users with different secrets
	secret1, _ := otp.GenerateSecret()
	secret2, _ := otp.GenerateSecret()

	user1Auth, err := otp.NewAuthenticator(otp.Config{
		Type:        otp.TypeTOTP,
		Secret:      secret1,
		Issuer:      "MultiUser",
		AccountName: "user1@example.com",
	})
	if err != nil {
		t.Fatalf("Failed to create user1 authenticator: %v", err)
	}

	user2Auth, err := otp.NewAuthenticator(otp.Config{
		Type:        otp.TypeTOTP,
		Secret:      secret2,
		Issuer:      "MultiUser",
		AccountName: "user2@example.com",
	})
	if err != nil {
		t.Fatalf("Failed to create user2 authenticator: %v", err)
	}

	// Generate codes for each user
	code1, err := user1Auth.Generate()
	if err != nil {
		t.Fatalf("Failed to generate code for user1: %v", err)
	}

	code2, err := user2Auth.Generate()
	if err != nil {
		t.Fatalf("Failed to generate code for user2: %v", err)
	}

	// Each user's code should validate for themselves
	if err := user1Auth.Authenticate(ctx, code1); err != nil {
		t.Errorf("User1 code should validate for user1: %v", err)
	}
	if err := user2Auth.Authenticate(ctx, code2); err != nil {
		t.Errorf("User2 code should validate for user2: %v", err)
	}

	// Cross-validation should fail
	if err := user1Auth.Authenticate(ctx, code2); err == nil {
		t.Error("User2 code should not validate for user1")
	}
	if err := user2Auth.Authenticate(ctx, code1); err == nil {
		t.Error("User1 code should not validate for user2")
	}

	// Test HOTP counter independence
	hotpUser1, _ := otp.NewAuthenticator(otp.Config{
		Type:        otp.TypeHOTP,
		Secret:      secret1,
		Issuer:      "MultiUser",
		AccountName: "hotp1@example.com",
		Counter:     0,
	})

	hotpUser2, _ := otp.NewAuthenticator(otp.Config{
		Type:        otp.TypeHOTP,
		Secret:      secret2,
		Issuer:      "MultiUser",
		AccountName: "hotp2@example.com",
		Counter:     0,
	})

	hotpCode1, _ := hotpUser1.Generate(0)
	hotpCode2, _ := hotpUser2.Generate(0)

	// Each HOTP should validate independently
	if _, err := hotpUser1.ValidateCounter(ctx, hotpCode1, 0); err != nil {
		t.Errorf("HOTP user1 should validate: %v", err)
	}
	if _, err := hotpUser2.ValidateCounter(ctx, hotpCode2, 0); err != nil {
		t.Errorf("HOTP user2 should validate: %v", err)
	}
}

func TestIntegration_ConcurrentAuthentication(t *testing.T) {
	secret, err := otp.GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	auth, err := otp.NewAuthenticator(otp.Config{
		Type:        otp.TypeTOTP,
		Secret:      secret,
		Issuer:      "ConcurrentTest",
		AccountName: "concurrent@example.com",
	})
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	// Generate one code
	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	// Validate concurrently from 50 goroutines
	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount, failCount int32

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			if err := auth.Authenticate(ctx, code); err != nil {
				atomic.AddInt32(&failCount, 1)
			} else {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}

	wg.Wait()

	// All validations should succeed (TOTP is stateless)
	if successCount != numGoroutines {
		t.Errorf("Expected %d successes, got %d (failures: %d)", numGoroutines, successCount, failCount)
	}
}

func TestIntegration_ConcurrentHOTP(t *testing.T) {
	secret, err := otp.GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	auth, err := otp.NewAuthenticator(otp.Config{
		Type:        otp.TypeHOTP,
		Secret:      secret,
		Issuer:      "ConcurrentHOTP",
		AccountName: "hotp@example.com",
		Counter:     0,
	})
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	// Test concurrent reads (validation) of the same HOTP code
	// Multiple goroutines should be able to validate the same code concurrently
	const numGoroutines = 20
	ctx := context.Background()

	// Generate one code for counter 0
	code, err := auth.Generate(0)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	// Validate the same code concurrently from multiple goroutines
	var wg sync.WaitGroup
	var successCount, failCount atomic.Int32

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, err := auth.ValidateCounter(ctx, code, 0)
			if err != nil {
				failCount.Add(1)
			} else {
				successCount.Add(1)
			}
		}()
	}

	wg.Wait()

	// All validations should succeed (HOTP validation itself is stateless)
	if successCount.Load() != numGoroutines {
		t.Errorf("Expected %d successes, got %d (failures: %d)",
			numGoroutines, successCount.Load(), failCount.Load())
	}
}

func TestIntegration_ProvisioningURI(t *testing.T) {
	secret, err := otp.GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	tests := []struct {
		name     string
		cfg      otp.Config
		expected string
	}{
		{
			name: "TOTP",
			cfg: otp.Config{
				Type:        otp.TypeTOTP,
				Secret:      secret,
				Issuer:      "TestApp",
				AccountName: "user@test.com",
				Algorithm:   otp.AlgorithmSHA256,
				Digits:      8,
				Period:      60,
			},
			expected: "otpauth://totp/",
		},
		{
			name: "HOTP",
			cfg: otp.Config{
				Type:        otp.TypeHOTP,
				Secret:      secret,
				Issuer:      "TestApp",
				AccountName: "user@test.com",
				Algorithm:   otp.AlgorithmSHA512,
				Digits:      7,
				Counter:     100,
			},
			expected: "otpauth://hotp/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := otp.NewAuthenticator(tt.cfg)
			if err != nil {
				t.Fatalf("Failed to create authenticator: %v", err)
			}

			uri := auth.GetProvisioningURI()
			if uri == "" {
				t.Error("URI should not be empty")
			}

			// Verify URI starts with correct scheme
			if uri[:len(tt.expected)] != tt.expected {
				t.Errorf("Expected URI to start with %s, got %s", tt.expected, uri[:len(tt.expected)])
			}

			// Verify required components are present
			requiredComponents := []string{
				"secret=" + secret,
				"issuer=TestApp",
				"algorithm=",
				"digits=",
			}

			for _, component := range requiredComponents {
				if !contains(uri, component) {
					t.Errorf("URI missing required component: %s", component)
				}
			}

			// Verify type-specific components
			if tt.cfg.Type == otp.TypeTOTP {
				if !contains(uri, "period=") {
					t.Error("TOTP URI missing period parameter")
				}
			} else {
				if !contains(uri, "counter=") {
					t.Error("HOTP URI missing counter parameter")
				}
			}
		})
	}
}

func TestIntegration_ErrorHandling(t *testing.T) {
	secret, err := otp.GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	auth, err := otp.NewAuthenticator(otp.Config{
		Type:        otp.TypeTOTP,
		Secret:      secret,
		Issuer:      "ErrorTest",
		AccountName: "error@test.com",
	})
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	tests := []struct {
		name string
		code string
	}{
		{"empty_code", ""},
		{"too_short", "123"},
		{"too_long", "1234567890"},
		{"invalid_chars", "abcdef"},
		{"special_chars", "12@#$%"},
		{"spaces", "12 34 56"},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := auth.Authenticate(ctx, tt.code); err == nil {
				t.Errorf("Expected error for invalid code %q", tt.code)
			}
		})
	}

	// Test context cancellation
	t.Run("context_cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		code, _ := auth.Generate()
		if err := auth.Authenticate(ctx, code); err != context.Canceled {
			t.Errorf("Expected context.Canceled, got %v", err)
		}
	})

	// Test context timeout
	t.Run("context_timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		time.Sleep(10 * time.Millisecond)

		code, _ := auth.Generate()
		if err := auth.Authenticate(ctx, code); err != context.DeadlineExceeded {
			t.Errorf("Expected context.DeadlineExceeded, got %v", err)
		}
	})
}

func TestIntegration_SecretGeneration(t *testing.T) {
	// Generate multiple secrets and ensure they're unique
	secrets := make(map[string]bool)
	count := 100

	for i := 0; i < count; i++ {
		secret, err := otp.GenerateSecret()
		if err != nil {
			t.Fatalf("Failed to generate secret %d: %v", i, err)
		}

		if secret == "" {
			t.Error("Generated secret is empty")
		}

		if secrets[secret] {
			t.Errorf("Duplicate secret generated: %s", secret)
		}
		secrets[secret] = true

		// Verify secret can be used to create authenticator
		_, err = otp.NewAuthenticator(otp.Config{
			Type:        otp.TypeTOTP,
			Secret:      secret,
			Issuer:      "SecretTest",
			AccountName: fmt.Sprintf("test%d@example.com", i),
		})
		if err != nil {
			t.Errorf("Failed to create authenticator with generated secret: %v", err)
		}
	}

	if len(secrets) != count {
		t.Errorf("Expected %d unique secrets, got %d", count, len(secrets))
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
