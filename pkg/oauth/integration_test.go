package oauth

import (
	"context"
	"testing"
	"time"
)

func TestAuthenticator_InvalidConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "missing provider",
			config: &Config{
				ClientID: "test",
				Flow:     FlowTokenValidation,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAuthenticator(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAuthenticator() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthenticator_ValidateToken_MissingToken(t *testing.T) {
	config := &Config{
		Provider: Google(),
		ClientID: "test-client",
		Flow:     FlowTokenValidation,
		Validation: TokenValidationConfig{
			Method:  ValidationJWT,
			JWKSURL: "https://www.googleapis.com/oauth2/v3/certs",
		},
	}

	// Note: We can't test actual token validation without a real JWKS server
	// This test just verifies error handling for missing tokens
	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	_, err = auth.ValidateToken(context.Background(), "")
	if err != ErrMissingToken {
		t.Errorf("Expected ErrMissingToken, got %v", err)
	}
}

func TestAuthenticator_FlowValidation(t *testing.T) {
	tests := []struct {
		name        string
		flow        FlowType
		method      string
		expectError bool
	}{
		{
			name:        "password flow with wrong method",
			flow:        FlowPassword,
			method:      "AuthenticateClientCredentials",
			expectError: true,
		},
		{
			name:        "client credentials with wrong method",
			flow:        FlowClientCredentials,
			method:      "AuthenticatePassword",
			expectError: true,
		},
		{
			name:        "token validation with exchange",
			flow:        FlowTokenValidation,
			method:      "ExchangeAuthorizationCode",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Provider:     Google(),
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				Flow:         tt.flow,
				RedirectURL:  "http://localhost/callback",
			}

			if tt.flow == FlowTokenValidation {
				config.Validation = TokenValidationConfig{
					Method:  ValidationJWT,
					JWKSURL: "https://www.googleapis.com/oauth2/v3/certs",
				}
			}

			auth, err := NewAuthenticator(config)
			if err != nil {
				t.Fatalf("NewAuthenticator() failed: %v", err)
			}
			defer auth.Close()

			ctx := context.Background()
			var testErr error

			switch tt.method {
			case "AuthenticateClientCredentials":
				_, testErr = auth.AuthenticateClientCredentials(ctx)
			case "AuthenticatePassword":
				_, testErr = auth.AuthenticatePassword(ctx, "user", "pass")
			case "ExchangeAuthorizationCode":
				_, testErr = auth.ExchangeAuthorizationCode(ctx, "code", "verifier")
			}

			if tt.expectError && testErr == nil {
				t.Error("Expected error but got nil")
			}
		})
	}
}

func TestAuthenticator_ClearCache(t *testing.T) {
	config := &Config{
		Provider: Google(),
		ClientID: "test-client",
		Flow:     FlowTokenValidation,
		Validation: TokenValidationConfig{
			Method:  ValidationJWT,
			JWKSURL: "https://www.googleapis.com/oauth2/v3/certs",
		},
		Cache: CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     5 * time.Minute,
		},
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	// Clear cache should not panic
	auth.ClearCache()
}

func TestAuthenticator_BuildAuthURL(t *testing.T) {
	config := &Config{
		Provider:    Google(),
		ClientID:    "test-client",
		Flow:        FlowAuthorizationCode,
		RedirectURL: "http://localhost:8080/callback",
		Scopes:      []string{"openid", "profile"},
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	t.Run("without PKCE", func(t *testing.T) {
		authURL, verifier, err := auth.BuildAuthURL("state123", false, nil)
		if err != nil {
			t.Fatalf("BuildAuthURL() failed: %v", err)
		}

		if authURL == "" {
			t.Error("Expected non-empty auth URL")
		}

		if verifier != "" {
			t.Error("Expected empty verifier when PKCE is disabled")
		}
	})

	t.Run("with PKCE", func(t *testing.T) {
		authURL, verifier, err := auth.BuildAuthURL("state123", true, nil)
		if err != nil {
			t.Fatalf("BuildAuthURL() failed: %v", err)
		}

		if authURL == "" {
			t.Error("Expected non-empty auth URL")
		}

		if verifier == "" {
			t.Error("Expected non-empty verifier when PKCE is enabled")
		}
	})

	t.Run("with additional params", func(t *testing.T) {
		params := map[string]string{
			"prompt": "consent",
		}
		authURL, _, err := auth.BuildAuthURL("state123", false, params)
		if err != nil {
			t.Fatalf("BuildAuthURL() failed: %v", err)
		}

		if authURL == "" {
			t.Error("Expected non-empty auth URL")
		}
	})
}

func TestAuthenticator_BuildAuthURL_WrongFlow(t *testing.T) {
	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Flow:         FlowClientCredentials,
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	_, _, err = auth.BuildAuthURL("state", false, nil)
	if err == nil {
		t.Error("Expected error when calling BuildAuthURL with wrong flow")
	}
}

func TestAuthenticator_Authenticate(t *testing.T) {
	config := &Config{
		Provider: Google(),
		ClientID: "test-client",
		Flow:     FlowTokenValidation,
		Validation: TokenValidationConfig{
			Method:  ValidationJWT,
			JWKSURL: "https://www.googleapis.com/oauth2/v3/certs",
		},
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	// Test the convenience Authenticate method
	err = auth.Authenticate(context.Background(), "ignored", "")
	if err != ErrMissingToken {
		t.Errorf("Expected ErrMissingToken, got %v", err)
	}
}

func TestAuthenticator_ContextHandling(t *testing.T) {
	config := &Config{
		Provider: Google(),
		ClientID: "test-client",
		Flow:     FlowTokenValidation,
		Validation: TokenValidationConfig{
			Method:  ValidationJWT,
			JWKSURL: "https://www.googleapis.com/oauth2/v3/certs",
		},
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	t.Run("nil context", func(t *testing.T) {
		// Should default to background context
		err := auth.Authenticate(nil, "", "token")
		// Will fail validation but shouldn't panic on nil context
		if err == nil {
			t.Error("Expected validation error")
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := auth.Authenticate(ctx, "", "token")
		if err == nil {
			t.Error("Expected context canceled error")
		}
	})
}
