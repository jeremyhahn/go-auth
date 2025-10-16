package oauth

import (
	"testing"
	"time"
)

func TestConfig_Validate(t *testing.T) {
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
				ClientID: "test-client",
				Flow:     FlowTokenValidation,
			},
			wantErr: true,
		},
		{
			name: "missing client id",
			config: &Config{
				Provider: Google(),
				Flow:     FlowTokenValidation,
			},
			wantErr: true,
		},
		{
			name: "token validation without jwks url",
			config: &Config{
				Provider: Google(),
				ClientID: "test-client",
				Flow:     FlowTokenValidation,
				Validation: TokenValidationConfig{
					Method: ValidationJWT,
				},
			},
			wantErr: true,
		},
		{
			name: "valid token validation config",
			config: &Config{
				Provider: Google(),
				ClientID: "test-client",
				Flow:     FlowTokenValidation,
				Validation: TokenValidationConfig{
					Method:  ValidationJWT,
					JWKSURL: "https://www.googleapis.com/oauth2/v3/certs",
				},
			},
			wantErr: false,
		},
		{
			name: "client credentials without secret",
			config: &Config{
				Provider: Google(),
				ClientID: "test-client",
				Flow:     FlowClientCredentials,
			},
			wantErr: true,
		},
		{
			name: "valid client credentials",
			config: &Config{
				Provider:     Google(),
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				Flow:         FlowClientCredentials,
			},
			wantErr: false,
		},
		{
			name: "authorization code without redirect url",
			config: &Config{
				Provider:     Google(),
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				Flow:         FlowAuthorizationCode,
			},
			wantErr: true,
		},
		{
			name: "valid authorization code",
			config: &Config{
				Provider:     Google(),
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				Flow:         FlowAuthorizationCode,
				RedirectURL:  "http://localhost:8080/callback",
			},
			wantErr: false,
		},
		{
			name: "invalid flow type",
			config: &Config{
				Provider: Google(),
				ClientID: "test-client",
				Flow:     "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_ValidateDefaults(t *testing.T) {
	config := &Config{
		Provider: Google(),
		ClientID: "test-client",
		Flow:     FlowTokenValidation,
		Validation: TokenValidationConfig{
			Method:  ValidationJWT,
			JWKSURL: "https://www.googleapis.com/oauth2/v3/certs",
		},
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	// Check defaults are set
	if config.Timeout <= 0 {
		t.Error("Expected default timeout to be set")
	}

	if config.Validation.ClockSkew <= 0 {
		t.Error("Expected default clock skew to be set")
	}

	if config.Timeout != 30*time.Second {
		t.Errorf("Expected timeout to be 30s, got %v", config.Timeout)
	}

	if config.Validation.ClockSkew != 60*time.Second {
		t.Errorf("Expected clock skew to be 60s, got %v", config.Validation.ClockSkew)
	}
}

func TestConfig_ValidateCacheDefaults(t *testing.T) {
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
		},
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	if config.Cache.MaxSize <= 0 {
		t.Error("Expected default cache max size to be set")
	}

	if config.Cache.TTL <= 0 {
		t.Error("Expected default cache TTL to be set")
	}
}
