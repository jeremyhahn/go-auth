package oauth

import "time"

// OIDCConfig contains OpenID Connect specific configuration.
// When nil or Enabled=false, the authenticator operates in pure OAuth 2.0 mode.
type OIDCConfig struct {
	// Enabled determines if OIDC features are active.
	Enabled bool

	// DiscoveryURL is the OIDC discovery endpoint URL.
	// If empty, will attempt to construct from Issuer + "/.well-known/openid-configuration"
	DiscoveryURL string

	// SkipDiscovery disables automatic discovery and uses manually configured endpoints.
	SkipDiscovery bool

	// Discovery contains cached discovery configuration (populated automatically).
	Discovery *OIDCDiscoveryConfig

	// DiscoveryCacheTTL determines how long to cache discovery documents.
	// Default: 24 hours
	DiscoveryCacheTTL time.Duration

	// ValidateNonce enables nonce validation for ID tokens (recommended).
	ValidateNonce bool

	// NonceLifetime determines how long nonces are valid.
	// Default: 10 minutes
	NonceLifetime time.Duration

	// RequireIDToken causes token exchanges to fail if no ID token is returned.
	RequireIDToken bool

	// ValidateAtHash enables at_hash validation in ID tokens.
	ValidateAtHash bool

	// MaxAge is the maximum authentication age in seconds.
	// If set and auth_time + max_age < now, authentication is considered stale.
	MaxAge int

	// ACRValues are the Authentication Context Class References to request.
	ACRValues []string

	// RequireACR causes validation to fail if the acr claim doesn't match ACRValues.
	RequireACR bool

	// UserInfoConfig contains settings for UserInfo endpoint calls.
	UserInfo UserInfoConfig
}

// UserInfoConfig contains settings for UserInfo endpoint interactions.
type UserInfoConfig struct {
	// Enabled determines if UserInfo endpoint should be called.
	Enabled bool

	// CacheTTL determines how long to cache UserInfo responses.
	// Default: 5 minutes
	CacheTTL time.Duration

	// Timeout is the HTTP timeout for UserInfo requests.
	// Default: 10 seconds
	Timeout time.Duration
}

// OIDCDiscoveryConfig represents an OIDC discovery document.
// Based on OpenID Connect Discovery 1.0 specification.
type OIDCDiscoveryConfig struct {
	// Issuer is the OIDC issuer identifier.
	Issuer string `json:"issuer"`

	// AuthorizationEndpoint is the authorization endpoint URL.
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// TokenEndpoint is the token endpoint URL.
	TokenEndpoint string `json:"token_endpoint"`

	// UserInfoEndpoint is the UserInfo endpoint URL.
	UserInfoEndpoint string `json:"userinfo_endpoint"`

	// JWKSUri is the JWKS endpoint URL.
	JWKSUri string `json:"jwks_uri"`

	// RegistrationEndpoint is the client registration endpoint URL.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// ScopesSupported lists supported OAuth 2.0 scopes.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// ResponseTypesSupported lists supported OAuth 2.0 response types.
	ResponseTypesSupported []string `json:"response_types_supported"`

	// ResponseModesSupported lists supported OAuth 2.0 response modes.
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	// GrantTypesSupported lists supported OAuth 2.0 grant types.
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// ACRValuesSupported lists supported Authentication Context Class References.
	ACRValuesSupported []string `json:"acr_values_supported,omitempty"`

	// SubjectTypesSupported lists supported subject identifier types.
	SubjectTypesSupported []string `json:"subject_types_supported"`

	// IDTokenSigningAlgValuesSupported lists supported signing algorithms for ID tokens.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// IDTokenEncryptionAlgValuesSupported lists supported encryption algorithms for ID tokens.
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`

	// IDTokenEncryptionEncValuesSupported lists supported encryption encoding methods for ID tokens.
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`

	// UserInfoSigningAlgValuesSupported lists supported signing algorithms for UserInfo.
	UserInfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported,omitempty"`

	// UserInfoEncryptionAlgValuesSupported lists supported encryption algorithms for UserInfo.
	UserInfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`

	// UserInfoEncryptionEncValuesSupported lists supported encryption encoding methods for UserInfo.
	UserInfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported lists supported client authentication methods.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// ClaimsSupported lists supported claim names.
	ClaimsSupported []string `json:"claims_supported,omitempty"`

	// CodeChallengeMethodsSupported lists supported PKCE challenge methods.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`

	// IntrospectionEndpoint is the token introspection endpoint URL.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// RevocationEndpoint is the token revocation endpoint URL.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// EndSessionEndpoint is the logout endpoint URL.
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`

	// FetchedAt tracks when this discovery document was retrieved.
	FetchedAt time.Time `json:"-"`
}

// Expired returns true if the discovery document should be refreshed.
func (d *OIDCDiscoveryConfig) Expired(ttl time.Duration) bool {
	if d == nil || d.FetchedAt.IsZero() {
		return true
	}
	return time.Since(d.FetchedAt) > ttl
}

// Validate checks if the discovery document contains required fields.
func (d *OIDCDiscoveryConfig) Validate() error {
	if d == nil {
		return ErrOIDCDiscoveryFailed
	}
	if d.Issuer == "" {
		return ErrOIDCInvalidDiscovery
	}
	if d.AuthorizationEndpoint == "" {
		return ErrOIDCInvalidDiscovery
	}
	if d.TokenEndpoint == "" {
		return ErrOIDCInvalidDiscovery
	}
	if d.JWKSUri == "" {
		return ErrOIDCInvalidDiscovery
	}
	if len(d.ResponseTypesSupported) == 0 {
		return ErrOIDCInvalidDiscovery
	}
	if len(d.SubjectTypesSupported) == 0 {
		return ErrOIDCInvalidDiscovery
	}
	if len(d.IDTokenSigningAlgValuesSupported) == 0 {
		return ErrOIDCInvalidDiscovery
	}
	return nil
}

// DefaultOIDCConfig returns an OIDCConfig with sensible defaults.
func DefaultOIDCConfig() *OIDCConfig {
	return &OIDCConfig{
		Enabled:           true,
		SkipDiscovery:     false,
		DiscoveryCacheTTL: 24 * time.Hour,
		ValidateNonce:     true,
		NonceLifetime:     10 * time.Minute,
		RequireIDToken:    false,
		ValidateAtHash:    true,
		UserInfo: UserInfoConfig{
			Enabled:  true,
			CacheTTL: 5 * time.Minute,
			Timeout:  10 * time.Second,
		},
	}
}
