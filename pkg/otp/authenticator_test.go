package otp

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestNewAuthenticator tests authenticator construction
func TestNewAuthenticator(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr error
	}{
		{
			name: "valid TOTP config",
			cfg: Config{
				Type:        TypeTOTP,
				Secret:      "JBSWY3DPEHPK3PXP",
				Issuer:      "TestApp",
				AccountName: "user@example.com",
				Digits:      6,
				Period:      30,
				Algorithm:   AlgorithmSHA1,
				Skew:        1,
			},
			wantErr: nil,
		},
		{
			name: "valid HOTP config",
			cfg: Config{
				Type:        TypeHOTP,
				Secret:      "JBSWY3DPEHPK3PXP",
				Issuer:      "TestApp",
				AccountName: "user@example.com",
				Digits:      6,
				Counter:     0,
				Algorithm:   AlgorithmSHA1,
			},
			wantErr: nil,
		},
		{
			name: "valid SHA256 config",
			cfg: Config{
				Type:        TypeTOTP,
				Secret:      "JBSWY3DPEHPK3PXP",
				Issuer:      "TestApp",
				AccountName: "user@example.com",
				Algorithm:   AlgorithmSHA256,
			},
			wantErr: nil,
		},
		{
			name: "valid SHA512 config",
			cfg: Config{
				Type:        TypeTOTP,
				Secret:      "JBSWY3DPEHPK3PXP",
				Issuer:      "TestApp",
				AccountName: "user@example.com",
				Algorithm:   AlgorithmSHA512,
			},
			wantErr: nil,
		},
		{
			name: "valid 7 digit config",
			cfg: Config{
				Type:        TypeTOTP,
				Secret:      "JBSWY3DPEHPK3PXP",
				Issuer:      "TestApp",
				AccountName: "user@example.com",
				Digits:      7,
			},
			wantErr: nil,
		},
		{
			name: "valid 8 digit config",
			cfg: Config{
				Type:        TypeTOTP,
				Secret:      "JBSWY3DPEHPK3PXP",
				Issuer:      "TestApp",
				AccountName: "user@example.com",
				Digits:      8,
			},
			wantErr: nil,
		},
		{
			name: "missing secret",
			cfg: Config{
				Type:        TypeTOTP,
				Issuer:      "TestApp",
				AccountName: "user@example.com",
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "invalid type",
			cfg: Config{
				Type:        "invalid",
				Secret:      "JBSWY3DPEHPK3PXP",
				Issuer:      "TestApp",
				AccountName: "user@example.com",
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "invalid digits",
			cfg: Config{
				Type:        TypeTOTP,
				Secret:      "JBSWY3DPEHPK3PXP",
				Issuer:      "TestApp",
				AccountName: "user@example.com",
				Digits:      5,
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "invalid algorithm",
			cfg: Config{
				Type:        TypeTOTP,
				Secret:      "JBSWY3DPEHPK3PXP",
				Issuer:      "TestApp",
				AccountName: "user@example.com",
				Algorithm:   "MD5",
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "invalid base32 secret",
			cfg: Config{
				Type:        TypeTOTP,
				Secret:      "invalid@secret!",
				Issuer:      "TestApp",
				AccountName: "user@example.com",
			},
			wantErr: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewAuthenticator(tt.cfg)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if auth == nil {
				t.Fatal("expected authenticator, got nil")
			}
		})
	}
}

// TestAuthenticateTOTP tests TOTP validation
func TestAuthenticateTOTP(t *testing.T) {
	cfg := Config{
		Type:        TypeTOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Issuer:      "TestApp",
		AccountName: "user@example.com",
		Digits:      6,
		Period:      30,
		Algorithm:   AlgorithmSHA1,
		Skew:        1,
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Generate current TOTP code
	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	tests := []struct {
		name    string
		ctx     context.Context
		code    string
		wantErr error
	}{
		{
			name:    "valid code",
			ctx:     context.Background(),
			code:    code,
			wantErr: nil,
		},
		{
			name:    "nil context",
			ctx:     nil,
			code:    code,
			wantErr: nil,
		},
		{
			name:    "invalid code",
			ctx:     context.Background(),
			code:    "000000",
			wantErr: ErrInvalidCode,
		},
		{
			name:    "empty code",
			ctx:     context.Background(),
			code:    "",
			wantErr: ErrInvalidCode,
		},
		{
			name:    "wrong length code",
			ctx:     context.Background(),
			code:    "12345",
			wantErr: ErrInvalidCode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.Authenticate(tt.ctx, tt.code)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestAuthenticateTOTPWithSkew tests TOTP time skew tolerance
func TestAuthenticateTOTPWithSkew(t *testing.T) {
	cfg := Config{
		Type:        TypeTOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Issuer:      "TestApp",
		AccountName: "user@example.com",
		Digits:      6,
		Period:      30,
		Algorithm:   AlgorithmSHA1,
		Skew:        2, // Allow 2 periods of skew
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Generate current code
	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	// Should accept current code
	if err := auth.Authenticate(context.Background(), code); err != nil {
		t.Errorf("failed to authenticate with current code: %v", err)
	}
}

// TestAuthenticateHOTP tests HOTP validation
func TestAuthenticateHOTP(t *testing.T) {
	cfg := Config{
		Type:        TypeHOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Issuer:      "TestApp",
		AccountName: "user@example.com",
		Digits:      6,
		Counter:     0,
		Algorithm:   AlgorithmSHA1,
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Generate code for counter 0
	code, err := auth.Generate(0)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	// Test ValidateCounter
	newCounter, err := auth.ValidateCounter(context.Background(), code, 0)
	if err != nil {
		t.Errorf("failed to validate counter: %v", err)
	}
	if newCounter != 1 {
		t.Errorf("expected new counter 1, got %d", newCounter)
	}

	// Test with wrong counter
	_, err = auth.ValidateCounter(context.Background(), code, 5)
	if err == nil {
		t.Error("expected error validating with wrong counter")
	}
}

// TestValidateCounter tests HOTP counter validation
func TestValidateCounter(t *testing.T) {
	cfg := Config{
		Type:        TypeHOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Issuer:      "TestApp",
		AccountName: "user@example.com",
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	tests := []struct {
		name        string
		ctx         context.Context
		counter     uint64
		wantCounter uint64
		wantErr     error
	}{
		{
			name:        "valid counter 0",
			ctx:         context.Background(),
			counter:     0,
			wantCounter: 1,
			wantErr:     nil,
		},
		{
			name:        "valid counter 5",
			ctx:         context.Background(),
			counter:     5,
			wantCounter: 6,
			wantErr:     nil,
		},
		{
			name:        "valid counter 100",
			ctx:         context.Background(),
			counter:     100,
			wantCounter: 101,
			wantErr:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := auth.Generate(tt.counter)
			if err != nil {
				t.Fatalf("failed to generate code: %v", err)
			}

			newCounter, err := auth.ValidateCounter(tt.ctx, code, tt.counter)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if newCounter != tt.wantCounter {
				t.Errorf("expected counter %d, got %d", tt.wantCounter, newCounter)
			}
		})
	}
}

// TestGenerate tests code generation
func TestGenerate(t *testing.T) {
	t.Run("TOTP", func(t *testing.T) {
		cfg := Config{
			Type:        TypeTOTP,
			Secret:      "JBSWY3DPEHPK3PXP",
			Issuer:      "TestApp",
			AccountName: "user@example.com",
			Digits:      6,
		}

		auth, err := NewAuthenticator(cfg)
		if err != nil {
			t.Fatalf("failed to create authenticator: %v", err)
		}

		code, err := auth.Generate()
		if err != nil {
			t.Fatalf("failed to generate code: %v", err)
		}

		if len(code) != 6 {
			t.Errorf("expected 6 digit code, got %d digits", len(code))
		}
	})

	t.Run("HOTP", func(t *testing.T) {
		cfg := Config{
			Type:        TypeHOTP,
			Secret:      "JBSWY3DPEHPK3PXP",
			Issuer:      "TestApp",
			AccountName: "user@example.com",
			Digits:      6,
		}

		auth, err := NewAuthenticator(cfg)
		if err != nil {
			t.Fatalf("failed to create authenticator: %v", err)
		}

		code, err := auth.Generate(0)
		if err != nil {
			t.Fatalf("failed to generate code: %v", err)
		}

		if len(code) != 6 {
			t.Errorf("expected 6 digit code, got %d digits", len(code))
		}
	})

	t.Run("7 digits", func(t *testing.T) {
		cfg := Config{
			Type:        TypeTOTP,
			Secret:      "JBSWY3DPEHPK3PXP",
			Issuer:      "TestApp",
			AccountName: "user@example.com",
			Digits:      7,
		}

		auth, err := NewAuthenticator(cfg)
		if err != nil {
			t.Fatalf("failed to create authenticator: %v", err)
		}

		code, err := auth.Generate()
		if err != nil {
			t.Fatalf("failed to generate code: %v", err)
		}

		if len(code) != 7 {
			t.Errorf("expected 7 digit code, got %d digits", len(code))
		}
	})

	t.Run("8 digits", func(t *testing.T) {
		cfg := Config{
			Type:        TypeTOTP,
			Secret:      "JBSWY3DPEHPK3PXP",
			Issuer:      "TestApp",
			AccountName: "user@example.com",
			Digits:      8,
		}

		auth, err := NewAuthenticator(cfg)
		if err != nil {
			t.Fatalf("failed to create authenticator: %v", err)
		}

		code, err := auth.Generate()
		if err != nil {
			t.Fatalf("failed to generate code: %v", err)
		}

		if len(code) != 8 {
			t.Errorf("expected 8 digit code, got %d digits", len(code))
		}
	})
}

// TestGetProvisioningURI tests provisioning URI generation
func TestGetProvisioningURI(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		wantContain []string
	}{
		{
			name: "TOTP URI",
			cfg: Config{
				Type:        TypeTOTP,
				Secret:      "JBSWY3DPEHPK3PXP",
				Issuer:      "TestApp",
				AccountName: "user@example.com",
			},
			wantContain: []string{
				"otpauth://totp/",
				"TestApp:user@example.com",
				"secret=JBSWY3DPEHPK3PXP",
				"issuer=TestApp",
			},
		},
		{
			name: "HOTP URI",
			cfg: Config{
				Type:        TypeHOTP,
				Secret:      "JBSWY3DPEHPK3PXP",
				Issuer:      "TestApp",
				AccountName: "user@example.com",
				Counter:     0,
			},
			wantContain: []string{
				"otpauth://hotp/",
				"TestApp:user@example.com",
				"secret=JBSWY3DPEHPK3PXP",
				"issuer=TestApp",
				"counter=0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewAuthenticator(tt.cfg)
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}

			uri := auth.GetProvisioningURI()
			if uri == "" {
				t.Fatal("expected non-empty URI")
			}

			for _, want := range tt.wantContain {
				if !contains(uri, want) {
					t.Errorf("URI %q does not contain %q", uri, want)
				}
			}
		})
	}
}

// TestGenerateSecret tests secret generation
func TestGenerateSecret(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}

	if secret == "" {
		t.Fatal("expected non-empty secret")
	}

	// Secret should be base32 encoded (only uppercase letters and digits 2-7)
	for _, c := range secret {
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == '=') {
			t.Errorf("invalid character in secret: %c", c)
		}
	}

	// Generate multiple secrets to ensure randomness
	secret2, err := GenerateSecret()
	if err != nil {
		t.Fatalf("failed to generate second secret: %v", err)
	}

	if secret == secret2 {
		t.Error("generated secrets should be different")
	}
}

// TestContextCancellation tests context cancellation
func TestContextCancellation(t *testing.T) {
	cfg := Config{
		Type:        TypeTOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Issuer:      "TestApp",
		AccountName: "user@example.com",
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	code, _ := auth.Generate()
	err = auth.Authenticate(ctx, code)
	if err == nil {
		t.Error("expected error with cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}

// TestContextTimeout tests context timeout
func TestContextTimeout(t *testing.T) {
	cfg := Config{
		Type:        TypeTOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Issuer:      "TestApp",
		AccountName: "user@example.com",
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(10 * time.Millisecond) // Ensure timeout

	code, _ := auth.Generate()
	err = auth.Authenticate(ctx, code)
	if err == nil {
		t.Error("expected error with timed out context")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded error, got %v", err)
	}
}

// TestNilAuthenticator tests operations on nil authenticator
func TestNilAuthenticator(t *testing.T) {
	var auth *Authenticator

	t.Run("Authenticate", func(t *testing.T) {
		err := auth.Authenticate(context.Background(), "123456")
		if err == nil {
			t.Fatal("expected error with nil authenticator")
		}
		if !errors.Is(err, ErrNilAuthenticator) {
			t.Errorf("expected ErrNilAuthenticator, got %v", err)
		}
	})

	t.Run("ValidateCounter", func(t *testing.T) {
		_, err := auth.ValidateCounter(context.Background(), "123456", 0)
		if err == nil {
			t.Fatal("expected error with nil authenticator")
		}
		if !errors.Is(err, ErrNilAuthenticator) {
			t.Errorf("expected ErrNilAuthenticator, got %v", err)
		}
	})

	t.Run("Generate", func(t *testing.T) {
		_, err := auth.Generate()
		if err == nil {
			t.Fatal("expected error with nil authenticator")
		}
		if !errors.Is(err, ErrNilAuthenticator) {
			t.Errorf("expected ErrNilAuthenticator, got %v", err)
		}
	})

	t.Run("GetProvisioningURI", func(t *testing.T) {
		uri := auth.GetProvisioningURI()
		if uri != "" {
			t.Errorf("expected empty URI with nil authenticator, got %q", uri)
		}
	})
}

// TestAlgorithms tests different hash algorithms
func TestAlgorithms(t *testing.T) {
	algorithms := []Algorithm{AlgorithmSHA1, AlgorithmSHA256, AlgorithmSHA512}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			cfg := Config{
				Type:        TypeTOTP,
				Secret:      "JBSWY3DPEHPK3PXP",
				Issuer:      "TestApp",
				AccountName: "user@example.com",
				Algorithm:   algo,
			}

			auth, err := NewAuthenticator(cfg)
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}

			code, err := auth.Generate()
			if err != nil {
				t.Fatalf("failed to generate code: %v", err)
			}

			err = auth.Authenticate(context.Background(), code)
			if err != nil {
				t.Errorf("failed to authenticate: %v", err)
			}
		})
	}
}

// TestDefaults tests default configuration values
func TestDefaults(t *testing.T) {
	cfg := Config{
		Type:        TypeTOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Issuer:      "TestApp",
		AccountName: "user@example.com",
		// No digits, period, algorithm, or skew specified
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	// Default is 6 digits
	if len(code) != 6 {
		t.Errorf("expected 6 digit code (default), got %d digits", len(code))
	}

	// Should be able to authenticate
	err = auth.Authenticate(context.Background(), code)
	if err != nil {
		t.Errorf("failed to authenticate with defaults: %v", err)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// TestHOTPWithoutCounter tests HOTP generate without counter
func TestHOTPWithoutCounter(t *testing.T) {
	cfg := Config{
		Type:        TypeHOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Issuer:      "TestApp",
		AccountName: "user@example.com",
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// HOTP Generate without counter should error
	_, err = auth.Generate()
	if err == nil {
		t.Fatal("expected error when generating HOTP without counter")
	}
}

// TestTOTPValidateCounterError tests TOTP ValidateCounter returns error
func TestTOTPValidateCounterError(t *testing.T) {
	cfg := Config{
		Type:        TypeTOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Issuer:      "TestApp",
		AccountName: "user@example.com",
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// ValidateCounter should only work with HOTP
	_, err = auth.ValidateCounter(context.Background(), "123456", 0)
	if err == nil {
		t.Fatal("expected error when calling ValidateCounter on TOTP authenticator")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

// TestValidateCounterWithEmptyCode tests ValidateCounter with empty code
func TestValidateCounterWithEmptyCode(t *testing.T) {
	cfg := Config{
		Type:        TypeHOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Issuer:      "TestApp",
		AccountName: "user@example.com",
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	_, err = auth.ValidateCounter(context.Background(), "", 0)
	if err == nil {
		t.Fatal("expected error with empty code")
	}
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

// TestValidateCounterWithNilContext tests ValidateCounter with nil context
func TestValidateCounterWithNilContext(t *testing.T) {
	cfg := Config{
		Type:        TypeHOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Issuer:      "TestApp",
		AccountName: "user@example.com",
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	code, err := auth.Generate(0)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	// Should work with nil context
	counter, err := auth.ValidateCounter(nil, code, 0)
	if err != nil {
		t.Errorf("unexpected error with nil context: %v", err)
	}
	if counter != 1 {
		t.Errorf("expected counter 1, got %d", counter)
	}
}

// TestValidateCounterWithCancelledContext tests ValidateCounter with cancelled context
func TestValidateCounterWithCancelledContext(t *testing.T) {
	cfg := Config{
		Type:        TypeHOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Issuer:      "TestApp",
		AccountName: "user@example.com",
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	code, err := auth.Generate(0)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = auth.ValidateCounter(ctx, code, 0)
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// TestAuthenticateHOTPWithContext tests HOTP authentication with valid code
func TestAuthenticateHOTPWithContext(t *testing.T) {
	cfg := Config{
		Type:        TypeHOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Issuer:      "TestApp",
		AccountName: "user@example.com",
		Counter:     0,
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	code, err := auth.Generate(0)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	// Test with valid code at configured counter
	err = auth.Authenticate(context.Background(), code)
	if err != nil {
		t.Errorf("failed to authenticate with valid HOTP code: %v", err)
	}
}
