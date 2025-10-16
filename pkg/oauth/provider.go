package oauth

import (
	"fmt"
	"strings"
)

// Provider defines the interface for OAuth 2.0 providers.
type Provider interface {
	// Name returns the provider's identifier.
	Name() string

	// AuthURL returns the authorization endpoint URL.
	AuthURL() string

	// TokenURL returns the token endpoint URL.
	TokenURL() string

	// JWKSURL returns the JWKS endpoint URL for JWT validation.
	JWKSURL() string

	// IntrospectionURL returns the token introspection endpoint URL (optional).
	IntrospectionURL() string

	// Issuer returns the expected token issuer.
	Issuer() string

	// UserInfoURL returns the OIDC UserInfo endpoint URL (optional).
	// Returns empty string if the provider doesn't support OIDC UserInfo.
	UserInfoURL() string
}

// ProviderConfig holds configuration for a custom OAuth provider.
type ProviderConfig struct {
	ProviderName          string
	AuthEndpoint          string
	TokenEndpoint         string
	JWKSEndpoint          string
	IntrospectionEndpoint string
	IssuerURL             string
	UserInfoEndpoint      string
}

// customProvider implements Provider with user-supplied configuration.
type customProvider struct {
	config ProviderConfig
}

// CustomProvider creates a Provider from custom configuration.
func CustomProvider(cfg ProviderConfig) (Provider, error) {
	if strings.TrimSpace(cfg.ProviderName) == "" {
		return nil, fmt.Errorf("%w: provider name is required", ErrInvalidConfiguration)
	}
	if strings.TrimSpace(cfg.TokenEndpoint) == "" {
		return nil, fmt.Errorf("%w: token endpoint is required", ErrInvalidConfiguration)
	}
	return &customProvider{config: cfg}, nil
}

func (p *customProvider) Name() string             { return p.config.ProviderName }
func (p *customProvider) AuthURL() string          { return p.config.AuthEndpoint }
func (p *customProvider) TokenURL() string         { return p.config.TokenEndpoint }
func (p *customProvider) JWKSURL() string          { return p.config.JWKSEndpoint }
func (p *customProvider) IntrospectionURL() string { return p.config.IntrospectionEndpoint }
func (p *customProvider) Issuer() string           { return p.config.IssuerURL }
func (p *customProvider) UserInfoURL() string      { return p.config.UserInfoEndpoint }

// Pre-configured provider implementations

type googleProvider struct{}

// Google returns a pre-configured Google OAuth provider.
func Google() Provider {
	return &googleProvider{}
}

func (p *googleProvider) Name() string { return "google" }
func (p *googleProvider) AuthURL() string {
	return "https://accounts.google.com/o/oauth2/v2/auth"
}
func (p *googleProvider) TokenURL() string {
	return "https://oauth2.googleapis.com/token"
}
func (p *googleProvider) JWKSURL() string {
	return "https://www.googleapis.com/oauth2/v3/certs"
}
func (p *googleProvider) IntrospectionURL() string {
	return "https://oauth2.googleapis.com/tokeninfo"
}
func (p *googleProvider) Issuer() string {
	return "https://accounts.google.com"
}
func (p *googleProvider) UserInfoURL() string {
	return "https://openidconnect.googleapis.com/v1/userinfo"
}

type microsoftProvider struct{}

// Microsoft returns a pre-configured Microsoft OAuth provider (Azure AD v2).
func Microsoft() Provider {
	return &microsoftProvider{}
}

func (p *microsoftProvider) Name() string { return "microsoft" }
func (p *microsoftProvider) AuthURL() string {
	return "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
}
func (p *microsoftProvider) TokenURL() string {
	return "https://login.microsoftonline.com/common/oauth2/v2.0/token"
}
func (p *microsoftProvider) JWKSURL() string {
	return "https://login.microsoftonline.com/common/discovery/v2.0/keys"
}
func (p *microsoftProvider) IntrospectionURL() string {
	return "" // Microsoft uses JWT validation
}
func (p *microsoftProvider) Issuer() string {
	return "https://login.microsoftonline.com/common/v2.0"
}
func (p *microsoftProvider) UserInfoURL() string {
	return "https://graph.microsoft.com/oidc/userinfo"
}

type githubProvider struct{}

// GitHub returns a pre-configured GitHub OAuth provider.
func GitHub() Provider {
	return &githubProvider{}
}

func (p *githubProvider) Name() string { return "github" }
func (p *githubProvider) AuthURL() string {
	return "https://github.com/login/oauth/authorize"
}
func (p *githubProvider) TokenURL() string {
	return "https://github.com/login/oauth/access_token"
}
func (p *githubProvider) JWKSURL() string {
	return "" // GitHub doesn't use JWT tokens by default
}
func (p *githubProvider) IntrospectionURL() string {
	return "" // GitHub uses API calls for validation
}
func (p *githubProvider) Issuer() string {
	return "https://github.com"
}
func (p *githubProvider) UserInfoURL() string {
	return "" // GitHub doesn't support OIDC UserInfo
}

type oktaProvider struct {
	domain string
}

// Okta returns a pre-configured Okta OAuth provider.
// domain should be your Okta domain (e.g., "dev-12345.okta.com").
func Okta(domain string) Provider {
	return &oktaProvider{domain: domain}
}

func (p *oktaProvider) Name() string { return "okta" }
func (p *oktaProvider) AuthURL() string {
	return fmt.Sprintf("https://%s/oauth2/v1/authorize", p.domain)
}
func (p *oktaProvider) TokenURL() string {
	return fmt.Sprintf("https://%s/oauth2/v1/token", p.domain)
}
func (p *oktaProvider) JWKSURL() string {
	return fmt.Sprintf("https://%s/oauth2/v1/keys", p.domain)
}
func (p *oktaProvider) IntrospectionURL() string {
	return fmt.Sprintf("https://%s/oauth2/v1/introspect", p.domain)
}
func (p *oktaProvider) Issuer() string {
	return fmt.Sprintf("https://%s", p.domain)
}
func (p *oktaProvider) UserInfoURL() string {
	return fmt.Sprintf("https://%s/oauth2/v1/userinfo", p.domain)
}

type auth0Provider struct {
	domain string
}

// Auth0 returns a pre-configured Auth0 OAuth provider.
// domain should be your Auth0 domain (e.g., "myapp.us.auth0.com").
func Auth0(domain string) Provider {
	return &auth0Provider{domain: domain}
}

func (p *auth0Provider) Name() string { return "auth0" }
func (p *auth0Provider) AuthURL() string {
	return fmt.Sprintf("https://%s/authorize", p.domain)
}
func (p *auth0Provider) TokenURL() string {
	return fmt.Sprintf("https://%s/oauth/token", p.domain)
}
func (p *auth0Provider) JWKSURL() string {
	return fmt.Sprintf("https://%s/.well-known/jwks.json", p.domain)
}
func (p *auth0Provider) IntrospectionURL() string {
	return fmt.Sprintf("https://%s/oauth/introspect", p.domain)
}
func (p *auth0Provider) Issuer() string {
	return fmt.Sprintf("https://%s/", p.domain)
}
func (p *auth0Provider) UserInfoURL() string {
	return fmt.Sprintf("https://%s/userinfo", p.domain)
}

type keycloakProvider struct {
	baseURL string
	realm   string
}

// Keycloak returns a pre-configured Keycloak OAuth provider.
// baseURL is your Keycloak server URL (e.g., "https://keycloak.example.com").
// realm is the Keycloak realm name (e.g., "master").
func Keycloak(baseURL, realm string) Provider {
	return &keycloakProvider{baseURL: baseURL, realm: realm}
}

func (p *keycloakProvider) Name() string { return "keycloak" }
func (p *keycloakProvider) AuthURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", p.baseURL, p.realm)
}
func (p *keycloakProvider) TokenURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", p.baseURL, p.realm)
}
func (p *keycloakProvider) JWKSURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", p.baseURL, p.realm)
}
func (p *keycloakProvider) IntrospectionURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", p.baseURL, p.realm)
}
func (p *keycloakProvider) Issuer() string {
	return fmt.Sprintf("%s/realms/%s", p.baseURL, p.realm)
}
func (p *keycloakProvider) UserInfoURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", p.baseURL, p.realm)
}
