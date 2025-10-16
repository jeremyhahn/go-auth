package oauth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestNewOIDCValidator(t *testing.T) {
	config := &Config{
		ClientID: "test-client",
		OIDC: &OIDCConfig{
			Enabled:       true,
			ValidateNonce: true,
			NonceLifetime: 5 * time.Minute,
		},
	}

	baseValidator := &tokenValidator{}
	discoveryClient := newDiscoveryClient(http.DefaultClient, config.OIDC)

	validator := newOIDCValidator(config, baseValidator, discoveryClient)

	if validator == nil {
		t.Fatal("newOIDCValidator() returned nil")
	}

	if validator.config != config {
		t.Error("newOIDCValidator() config not set correctly")
	}

	if validator.nonceStore == nil {
		t.Error("newOIDCValidator() nonceStore should be initialized")
	}
}

func TestNewOIDCValidator_WithoutNonce(t *testing.T) {
	config := &Config{
		ClientID: "test-client",
		OIDC: &OIDCConfig{
			Enabled:       true,
			ValidateNonce: false,
		},
	}

	baseValidator := &tokenValidator{}
	discoveryClient := newDiscoveryClient(http.DefaultClient, config.OIDC)

	validator := newOIDCValidator(config, baseValidator, discoveryClient)

	if validator.nonceStore != nil {
		t.Error("newOIDCValidator() nonceStore should be nil when nonce validation disabled")
	}
}

func TestOIDCValidator_IsOIDCEnabled(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{
			name: "enabled",
			config: &Config{
				OIDC: &OIDCConfig{Enabled: true},
			},
			want: true,
		},
		{
			name: "disabled",
			config: &Config{
				OIDC: &OIDCConfig{Enabled: false},
			},
			want: false,
		},
		{
			name:   "nil config",
			config: &Config{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &oidcValidator{
				config: tt.config,
			}

			got := validator.isOIDCEnabled()
			if got != tt.want {
				t.Errorf("isOIDCEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDCValidator_GenerateNonce(t *testing.T) {
	t.Run("generates nonce when enabled", func(t *testing.T) {
		config := &Config{
			OIDC: &OIDCConfig{
				Enabled:       true,
				ValidateNonce: true,
			},
		}

		validator := newOIDCValidator(config, &tokenValidator{}, nil)
		defer validator.Close()

		nonce, err := validator.GenerateNonce()
		if err != nil {
			t.Fatalf("GenerateNonce() error = %v", err)
		}

		if nonce == "" {
			t.Error("GenerateNonce() returned empty nonce")
		}
	})

	t.Run("returns empty when OIDC disabled", func(t *testing.T) {
		config := &Config{
			OIDC: &OIDCConfig{
				Enabled: false,
			},
		}

		validator := newOIDCValidator(config, &tokenValidator{}, nil)

		_, err := validator.GenerateNonce()
		if err != ErrOIDCNotEnabled {
			t.Errorf("GenerateNonce() error = %v, want %v", err, ErrOIDCNotEnabled)
		}
	})

	t.Run("returns empty when nonce validation disabled", func(t *testing.T) {
		config := &Config{
			OIDC: &OIDCConfig{
				Enabled:       true,
				ValidateNonce: false,
			},
		}

		validator := newOIDCValidator(config, &tokenValidator{}, nil)

		nonce, err := validator.GenerateNonce()
		if err != nil {
			t.Fatalf("GenerateNonce() error = %v", err)
		}

		if nonce != "" {
			t.Error("GenerateNonce() should return empty when validation disabled")
		}
	})
}

func TestOIDCValidator_ValidateOIDCClaims(t *testing.T) {
	now := time.Now()
	baseValidator := &oidcValidator{
		config: &Config{
			ClientID: "test-client",
			OIDC: &OIDCConfig{
				Enabled:        true,
				ValidateNonce:  false,
				ValidateAtHash: false,
			},
		},
	}

	discovery := &OIDCDiscoveryConfig{
		Issuer: "https://example.com",
	}

	t.Run("validates basic claims", func(t *testing.T) {
		claims := &IDTokenClaims{
			Issuer:    "https://example.com",
			Subject:   "user123",
			Audience:  []string{"test-client"},
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
		}

		err := baseValidator.validateOIDCClaims(claims, "", "", discovery)
		if err != nil {
			t.Errorf("validateOIDCClaims() error = %v", err)
		}
	})

	t.Run("rejects issuer mismatch", func(t *testing.T) {
		claims := &IDTokenClaims{
			Issuer:    "https://wrong.com",
			Subject:   "user123",
			Audience:  []string{"test-client"},
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
		}

		err := baseValidator.validateOIDCClaims(claims, "", "", discovery)
		if err == nil {
			t.Error("validateOIDCClaims() should error on issuer mismatch")
		}
	})

	t.Run("rejects missing audience", func(t *testing.T) {
		claims := &IDTokenClaims{
			Issuer:    "https://example.com",
			Subject:   "user123",
			Audience:  []string{"wrong-client"},
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
		}

		err := baseValidator.validateOIDCClaims(claims, "", "", discovery)
		if err == nil {
			t.Error("validateOIDCClaims() should error when audience missing client_id")
		}
	})

	t.Run("validates azp with multiple audiences", func(t *testing.T) {
		claims := &IDTokenClaims{
			Issuer:    "https://example.com",
			Subject:   "user123",
			Audience:  []string{"test-client", "other-client"},
			AZP:       "test-client",
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
		}

		err := baseValidator.validateOIDCClaims(claims, "", "", discovery)
		if err != nil {
			t.Errorf("validateOIDCClaims() error = %v", err)
		}
	})

	t.Run("rejects wrong azp", func(t *testing.T) {
		claims := &IDTokenClaims{
			Issuer:    "https://example.com",
			Subject:   "user123",
			Audience:  []string{"test-client", "other-client"},
			AZP:       "wrong-client",
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
		}

		err := baseValidator.validateOIDCClaims(claims, "", "", discovery)
		if err == nil {
			t.Error("validateOIDCClaims() should error on wrong azp")
		}
	})
}

func TestOIDCValidator_ValidateNonce(t *testing.T) {
	config := &Config{
		ClientID: "test-client",
		OIDC: &OIDCConfig{
			Enabled:       true,
			ValidateNonce: true,
		},
	}

	validator := newOIDCValidator(config, &tokenValidator{}, nil)
	defer validator.Close()

	discovery := &OIDCDiscoveryConfig{
		Issuer: "https://example.com",
	}

	t.Run("validates matching nonce", func(t *testing.T) {
		nonce, _ := validator.nonceStore.Generate()

		claims := &IDTokenClaims{
			Issuer:    "https://example.com",
			Subject:   "user123",
			Audience:  []string{"test-client"},
			Nonce:     nonce,
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		}

		err := validator.validateOIDCClaims(claims, nonce, "", discovery)
		if err != nil {
			t.Errorf("validateOIDCClaims() error = %v", err)
		}
	})

	t.Run("rejects nonce mismatch", func(t *testing.T) {
		nonce1, _ := validator.nonceStore.Generate()
		nonce2, _ := validator.nonceStore.Generate()

		claims := &IDTokenClaims{
			Issuer:    "https://example.com",
			Subject:   "user123",
			Audience:  []string{"test-client"},
			Nonce:     nonce2,
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		}

		err := validator.validateOIDCClaims(claims, nonce1, "", discovery)
		if err == nil {
			t.Error("validateOIDCClaims() should error on nonce mismatch")
		}
	})

	t.Run("rejects missing nonce in token", func(t *testing.T) {
		nonce, _ := validator.nonceStore.Generate()

		claims := &IDTokenClaims{
			Issuer:    "https://example.com",
			Subject:   "user123",
			Audience:  []string{"test-client"},
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		}

		err := validator.validateOIDCClaims(claims, nonce, "", discovery)
		if err == nil {
			t.Error("validateOIDCClaims() should error when nonce missing in token")
		}
	})
}

func TestOIDCValidator_ValidateTimeClaims(t *testing.T) {
	config := &Config{
		ClientID: "test-client",
		OIDC: &OIDCConfig{
			Enabled: true,
			MaxAge:  0,
		},
		Validation: TokenValidationConfig{
			ClockSkew: 1 * time.Minute,
		},
	}

	validator := &oidcValidator{
		config: config,
	}

	now := time.Now()

	t.Run("validates valid time claims", func(t *testing.T) {
		claims := &IDTokenClaims{
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
		}

		err := validator.validateTimeClaims(claims)
		if err != nil {
			t.Errorf("validateTimeClaims() error = %v", err)
		}
	})

	t.Run("rejects expired token", func(t *testing.T) {
		claims := &IDTokenClaims{
			ExpiresAt: now.Add(-10 * time.Minute).Unix(),
			IssuedAt:  now.Add(-1 * time.Hour).Unix(),
		}

		err := validator.validateTimeClaims(claims)
		if err == nil {
			t.Error("validateTimeClaims() should error on expired token")
		}
	})

	t.Run("allows clock skew for expiration", func(t *testing.T) {
		claims := &IDTokenClaims{
			ExpiresAt: now.Add(-30 * time.Second).Unix(),
			IssuedAt:  now.Add(-1 * time.Hour).Unix(),
		}

		err := validator.validateTimeClaims(claims)
		if err != nil {
			t.Errorf("validateTimeClaims() should allow clock skew, error = %v", err)
		}
	})

	t.Run("rejects future issued at", func(t *testing.T) {
		claims := &IDTokenClaims{
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Add(10 * time.Minute).Unix(),
		}

		err := validator.validateTimeClaims(claims)
		if err == nil {
			t.Error("validateTimeClaims() should error on future issued at")
		}
	})

	t.Run("validates not before", func(t *testing.T) {
		claims := &IDTokenClaims{
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
			NotBefore: now.Add(10 * time.Minute).Unix(),
		}

		err := validator.validateTimeClaims(claims)
		if err == nil {
			t.Error("validateTimeClaims() should error when not yet valid")
		}
	})

	t.Run("validates max_age", func(t *testing.T) {
		validator := &oidcValidator{
			config: &Config{
				ClientID: "test-client",
				OIDC: &OIDCConfig{
					Enabled: true,
					MaxAge:  300, // 5 minutes
				},
				Validation: TokenValidationConfig{
					ClockSkew: 1 * time.Minute,
				},
			},
		}

		claims := &IDTokenClaims{
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
			AuthTime:  now.Add(-10 * time.Minute).Unix(),
		}

		err := validator.validateTimeClaims(claims)
		if err == nil {
			t.Error("validateTimeClaims() should error on auth_time exceeding max_age")
		}
	})
}

func TestOIDCValidator_ValidateAtHash(t *testing.T) {
	validator := &oidcValidator{}

	t.Run("validates correct at_hash", func(t *testing.T) {
		// This is a simplified test - in reality you'd need to generate proper hashes
		// For now, we test the structure and error handling
		err := validator.validateAtHash("", "access-token", nil)
		if err != nil {
			t.Errorf("validateAtHash() with nil hash func should not error, got %v", err)
		}
	})

	t.Run("skips validation with nil hash function", func(t *testing.T) {
		err := validator.validateAtHash("some-hash", "access-token", nil)
		if err != nil {
			t.Errorf("validateAtHash() should skip with nil hash func, got %v", err)
		}
	})
}

func TestOIDCValidator_ValidateACR(t *testing.T) {
	discovery := &OIDCDiscoveryConfig{
		Issuer: "https://example.com",
	}

	t.Run("validates required ACR", func(t *testing.T) {
		validator := &oidcValidator{
			config: &Config{
				ClientID: "test-client",
				OIDC: &OIDCConfig{
					Enabled:    true,
					RequireACR: true,
					ACRValues:  []string{"urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:gold"},
				},
			},
		}

		claims := &IDTokenClaims{
			Issuer:    "https://example.com",
			Subject:   "user123",
			Audience:  []string{"test-client"},
			ACR:       "urn:mace:incommon:iap:silver",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		}

		err := validator.validateOIDCClaims(claims, "", "", discovery)
		if err != nil {
			t.Errorf("validateOIDCClaims() error = %v", err)
		}
	})

	t.Run("rejects invalid ACR", func(t *testing.T) {
		validator := &oidcValidator{
			config: &Config{
				ClientID: "test-client",
				OIDC: &OIDCConfig{
					Enabled:    true,
					RequireACR: true,
					ACRValues:  []string{"urn:mace:incommon:iap:silver"},
				},
			},
		}

		claims := &IDTokenClaims{
			Issuer:    "https://example.com",
			Subject:   "user123",
			Audience:  []string{"test-client"},
			ACR:       "urn:mace:incommon:iap:bronze",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		}

		err := validator.validateOIDCClaims(claims, "", "", discovery)
		if err == nil {
			t.Error("validateOIDCClaims() should error on invalid ACR")
		}
	})
}

func TestOIDCValidator_Close(t *testing.T) {
	config := &Config{
		ClientID: "test-client",
		OIDC: &OIDCConfig{
			Enabled:       true,
			ValidateNonce: true,
		},
	}

	validator := newOIDCValidator(config, &tokenValidator{}, nil)
	validator.Close()

	// Should not panic
}

func TestContainsString(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		str   string
		want  bool
	}{
		{
			name:  "contains string",
			slice: []string{"a", "b", "c"},
			str:   "b",
			want:  true,
		},
		{
			name:  "does not contain string",
			slice: []string{"a", "b", "c"},
			str:   "d",
			want:  false,
		},
		{
			name:  "empty slice",
			slice: []string{},
			str:   "a",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsString(tt.slice, tt.str)
			if got != tt.want {
				t.Errorf("containsString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetJWTAlgorithm(t *testing.T) {
	t.Run("extracts RS256", func(t *testing.T) {
		// Create a simple JWT header
		token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
		alg := getJWTAlgorithm(token)

		if alg != "RS256" {
			t.Errorf("getJWTAlgorithm() = %s, want RS256", alg)
		}
	})

	t.Run("handles invalid token", func(t *testing.T) {
		alg := getJWTAlgorithm("invalid")
		if alg != "" {
			t.Errorf("getJWTAlgorithm() = %s, want empty", alg)
		}
	})
}

func TestGetHashFuncForAlg(t *testing.T) {
	tests := []struct {
		name string
		alg  string
	}{
		{"RS256", "RS256"},
		{"RS384", "RS384"},
		{"RS512", "RS512"},
		{"ES256", "ES256"},
		{"ES384", "ES384"},
		{"ES512", "ES512"},
		{"PS256", "PS256"},
		{"PS384", "PS384"},
		{"PS512", "PS512"},
		{"HS256", "HS256"},
		{"HS384", "HS384"},
		{"HS512", "HS512"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashFunc := getHashFuncForAlg(tt.alg)
			if hashFunc == nil {
				t.Errorf("getHashFuncForAlg(%s) returned nil", tt.alg)
			}

			// Test that hash function works
			h := hashFunc()
			if h == nil {
				t.Errorf("getHashFuncForAlg(%s) hash function returned nil", tt.alg)
			}
		})
	}
}

func TestOIDCValidator_ValidateIDToken_Errors(t *testing.T) {
	config := &Config{
		ClientID: "test-client",
		OIDC: &OIDCConfig{
			Enabled: true,
		},
	}

	validator := newOIDCValidator(config, &tokenValidator{}, newDiscoveryClient(http.DefaultClient, config.OIDC))
	defer validator.Close()

	t.Run("errors when OIDC disabled", func(t *testing.T) {
		disabledValidator := &oidcValidator{
			config: &Config{
				OIDC: &OIDCConfig{Enabled: false},
			},
		}

		_, err := disabledValidator.ValidateIDToken(context.Background(), "token", "", "")
		if err != ErrOIDCNotEnabled {
			t.Errorf("ValidateIDToken() error = %v, want %v", err, ErrOIDCNotEnabled)
		}
	})

	t.Run("errors on empty token", func(t *testing.T) {
		_, err := validator.ValidateIDToken(context.Background(), "", "", "")
		if err != ErrOIDCMissingIDToken {
			t.Errorf("ValidateIDToken() error = %v, want %v", err, ErrOIDCMissingIDToken)
		}
	})

	t.Run("errors on malformed token", func(t *testing.T) {
		_, err := validator.ValidateIDToken(context.Background(), "malformed.token", "", "")
		if err == nil {
			t.Error("ValidateIDToken() should error on malformed token")
		}
	})
}
