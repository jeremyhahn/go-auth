package oauth

import "testing"

func TestGoogleProvider(t *testing.T) {
	provider := Google()

	if provider.Name() != "google" {
		t.Errorf("Expected name 'google', got %s", provider.Name())
	}

	if provider.AuthURL() == "" {
		t.Error("Expected non-empty auth URL")
	}

	if provider.TokenURL() == "" {
		t.Error("Expected non-empty token URL")
	}

	if provider.JWKSURL() == "" {
		t.Error("Expected non-empty JWKS URL")
	}

	if provider.Issuer() == "" {
		t.Error("Expected non-empty issuer")
	}
}

func TestMicrosoftProvider(t *testing.T) {
	provider := Microsoft()

	if provider.Name() != "microsoft" {
		t.Errorf("Expected name 'microsoft', got %s", provider.Name())
	}

	if provider.AuthURL() == "" {
		t.Error("Expected non-empty auth URL")
	}

	if provider.TokenURL() == "" {
		t.Error("Expected non-empty token URL")
	}

	if provider.JWKSURL() == "" {
		t.Error("Expected non-empty JWKS URL")
	}
}

func TestGitHubProvider(t *testing.T) {
	provider := GitHub()

	if provider.Name() != "github" {
		t.Errorf("Expected name 'github', got %s", provider.Name())
	}

	if provider.AuthURL() == "" {
		t.Error("Expected non-empty auth URL")
	}

	if provider.TokenURL() == "" {
		t.Error("Expected non-empty token URL")
	}
}

func TestOktaProvider(t *testing.T) {
	domain := "dev-12345.okta.com"
	provider := Okta(domain)

	if provider.Name() != "okta" {
		t.Errorf("Expected name 'okta', got %s", provider.Name())
	}

	if provider.AuthURL() == "" {
		t.Error("Expected non-empty auth URL")
	}

	if provider.TokenURL() == "" {
		t.Error("Expected non-empty token URL")
	}

	if provider.JWKSURL() == "" {
		t.Error("Expected non-empty JWKS URL")
	}

	if provider.IntrospectionURL() == "" {
		t.Error("Expected non-empty introspection URL")
	}
}

func TestAuth0Provider(t *testing.T) {
	domain := "myapp.us.auth0.com"
	provider := Auth0(domain)

	if provider.Name() != "auth0" {
		t.Errorf("Expected name 'auth0', got %s", provider.Name())
	}

	if provider.AuthURL() == "" {
		t.Error("Expected non-empty auth URL")
	}

	if provider.TokenURL() == "" {
		t.Error("Expected non-empty token URL")
	}

	if provider.JWKSURL() == "" {
		t.Error("Expected non-empty JWKS URL")
	}
}

func TestKeycloakProvider(t *testing.T) {
	baseURL := "https://keycloak.example.com"
	realm := "master"
	provider := Keycloak(baseURL, realm)

	if provider.Name() != "keycloak" {
		t.Errorf("Expected name 'keycloak', got %s", provider.Name())
	}

	if provider.AuthURL() == "" {
		t.Error("Expected non-empty auth URL")
	}

	if provider.TokenURL() == "" {
		t.Error("Expected non-empty token URL")
	}

	if provider.JWKSURL() == "" {
		t.Error("Expected non-empty JWKS URL")
	}

	if provider.IntrospectionURL() == "" {
		t.Error("Expected non-empty introspection URL")
	}
}

func TestCustomProvider(t *testing.T) {
	tests := []struct {
		name    string
		config  ProviderConfig
		wantErr bool
	}{
		{
			name: "valid custom provider",
			config: ProviderConfig{
				ProviderName:  "custom",
				TokenEndpoint: "https://provider.com/token",
			},
			wantErr: false,
		},
		{
			name: "missing provider name",
			config: ProviderConfig{
				TokenEndpoint: "https://provider.com/token",
			},
			wantErr: true,
		},
		{
			name: "missing token endpoint",
			config: ProviderConfig{
				ProviderName: "custom",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := CustomProvider(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("CustomProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && provider == nil {
				t.Error("Expected non-nil provider")
			}

			if !tt.wantErr {
				if provider.Name() != tt.config.ProviderName {
					t.Errorf("Expected name %s, got %s", tt.config.ProviderName, provider.Name())
				}
			}
		})
	}
}
