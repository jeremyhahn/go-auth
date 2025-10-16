package oauth

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"
)

// FlowType identifies the OAuth 2.0 flow to use.
type FlowType string

const (
	// FlowTokenValidation validates existing tokens without issuing new ones.
	FlowTokenValidation FlowType = "token_validation"

	// FlowClientCredentials uses OAuth 2.0 client credentials flow.
	FlowClientCredentials FlowType = "client_credentials"

	// FlowPassword uses OAuth 2.0 resource owner password credentials flow.
	FlowPassword FlowType = "password"

	// FlowAuthorizationCode uses OAuth 2.0 authorization code flow with PKCE.
	FlowAuthorizationCode FlowType = "authorization_code"
)

// ValidationMethod identifies how tokens should be validated.
type ValidationMethod string

const (
	// ValidationJWT performs local JWT validation using JWKS.
	ValidationJWT ValidationMethod = "jwt"

	// ValidationIntrospection performs remote token introspection.
	ValidationIntrospection ValidationMethod = "introspection"

	// ValidationHybrid attempts JWT first, falls back to introspection.
	ValidationHybrid ValidationMethod = "hybrid"
)

// TokenValidationConfig contains settings for token validation.
type TokenValidationConfig struct {
	// Method determines how tokens are validated.
	Method ValidationMethod

	// JWKSURL is the URL to the provider's JWKS endpoint for JWT validation.
	JWKSURL string

	// IntrospectionURL is the URL to the OAuth introspection endpoint.
	IntrospectionURL string

	// Audience specifies the expected audience claim (optional).
	Audience string

	// Issuer specifies the expected issuer claim (optional).
	Issuer string

	// ClockSkew allows for clock drift between systems.
	ClockSkew time.Duration

	// RequiredClaims specifies claim names that must be present in the token.
	RequiredClaims []string
}

// CacheConfig contains settings for token caching.
type CacheConfig struct {
	// Enabled determines if caching is active.
	Enabled bool

	// MaxSize is the maximum number of tokens to cache (LRU eviction).
	MaxSize int

	// TTL is how long to cache valid tokens.
	TTL time.Duration
}

// Config contains the complete OAuth authenticator configuration.
type Config struct {
	// Provider is the OAuth provider configuration.
	Provider Provider

	// Flow determines which OAuth flow to use.
	Flow FlowType

	// ClientID is the OAuth client identifier.
	ClientID string

	// ClientSecret is the OAuth client secret (required for some flows).
	ClientSecret string

	// Scopes are the OAuth scopes to request.
	Scopes []string

	// RedirectURL is the callback URL for authorization code flow.
	RedirectURL string

	// Validation contains token validation settings.
	Validation TokenValidationConfig

	// Cache contains token caching settings.
	Cache CacheConfig

	// OIDC contains OpenID Connect specific configuration.
	// When nil or OIDC.Enabled=false, operates in pure OAuth 2.0 mode.
	// This is fully backward compatible - existing OAuth-only code is unaffected.
	OIDC *OIDCConfig

	// Timeout is the HTTP client timeout for OAuth requests.
	Timeout time.Duration

	// TLSConfig allows custom TLS configuration.
	TLSConfig *tls.Config

	// InsecureSkipVerify disables TLS certificate verification (not recommended).
	InsecureSkipVerify bool
}

// Validate checks if the configuration is valid for the specified flow.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("%w: config is nil", ErrInvalidConfiguration)
	}

	if c.Provider == nil {
		return fmt.Errorf("%w: provider is required", ErrInvalidConfiguration)
	}

	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("%w: client_id is required", ErrInvalidConfiguration)
	}

	// Validate flow-specific requirements
	switch c.Flow {
	case FlowTokenValidation:
		if err := c.validateTokenValidation(); err != nil {
			return err
		}
	case FlowClientCredentials:
		if err := c.validateClientCredentials(); err != nil {
			return err
		}
	case FlowPassword:
		if err := c.validatePassword(); err != nil {
			return err
		}
	case FlowAuthorizationCode:
		if err := c.validateAuthorizationCode(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: %s", ErrFlowNotSupported, c.Flow)
	}

	// Validate OIDC configuration if enabled
	if c.OIDC != nil && c.OIDC.Enabled {
		if err := c.validateOIDC(); err != nil {
			return err
		}
	}

	// Validate cache config
	if c.Cache.Enabled {
		if c.Cache.MaxSize <= 0 {
			c.Cache.MaxSize = 1000 // Default
		}
		if c.Cache.TTL <= 0 {
			c.Cache.TTL = 5 * time.Minute // Default
		}
	}

	// Set default timeout if not specified
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}

	return nil
}

func (c *Config) validateTokenValidation() error {
	if c.Validation.Method == "" {
		c.Validation.Method = ValidationHybrid // Default
	}

	switch c.Validation.Method {
	case ValidationJWT:
		if strings.TrimSpace(c.Validation.JWKSURL) == "" {
			return fmt.Errorf("%w: jwks_url required for jwt validation", ErrInvalidConfiguration)
		}
	case ValidationIntrospection:
		if strings.TrimSpace(c.Validation.IntrospectionURL) == "" {
			return fmt.Errorf("%w: introspection_url required for introspection validation", ErrInvalidConfiguration)
		}
		if strings.TrimSpace(c.ClientSecret) == "" {
			return fmt.Errorf("%w: client_secret required for introspection", ErrInvalidConfiguration)
		}
	case ValidationHybrid:
		if strings.TrimSpace(c.Validation.JWKSURL) == "" {
			return fmt.Errorf("%w: jwks_url required for hybrid validation", ErrInvalidConfiguration)
		}
		// Introspection URL is optional for hybrid (JWT-only fallback is acceptable)
	default:
		return fmt.Errorf("%w: validation method %s", ErrInvalidConfiguration, c.Validation.Method)
	}

	// Set default clock skew
	if c.Validation.ClockSkew <= 0 {
		c.Validation.ClockSkew = 60 * time.Second
	}

	return nil
}

func (c *Config) validateClientCredentials() error {
	if strings.TrimSpace(c.ClientSecret) == "" {
		return fmt.Errorf("%w: client_secret required for client credentials flow", ErrInvalidConfiguration)
	}
	if c.Provider.TokenURL() == "" {
		return fmt.Errorf("%w: token_url required for client credentials flow", ErrInvalidConfiguration)
	}
	return nil
}

func (c *Config) validatePassword() error {
	if strings.TrimSpace(c.ClientSecret) == "" {
		return fmt.Errorf("%w: client_secret required for password flow", ErrInvalidConfiguration)
	}
	if c.Provider.TokenURL() == "" {
		return fmt.Errorf("%w: token_url required for password flow", ErrInvalidConfiguration)
	}
	return nil
}

func (c *Config) validateAuthorizationCode() error {
	if strings.TrimSpace(c.RedirectURL) == "" {
		return fmt.Errorf("%w: redirect_url required for authorization code flow", ErrInvalidConfiguration)
	}
	if c.Provider.AuthURL() == "" {
		return fmt.Errorf("%w: auth_url required for authorization code flow", ErrInvalidConfiguration)
	}
	if c.Provider.TokenURL() == "" {
		return fmt.Errorf("%w: token_url required for authorization code flow", ErrInvalidConfiguration)
	}
	return nil
}

func (c *Config) validateOIDC() error {
	if c.OIDC == nil {
		return nil
	}

	// Set defaults for OIDC configuration
	if c.OIDC.DiscoveryCacheTTL <= 0 {
		c.OIDC.DiscoveryCacheTTL = 24 * time.Hour
	}

	if c.OIDC.NonceLifetime <= 0 {
		c.OIDC.NonceLifetime = 10 * time.Minute
	}

	if c.OIDC.UserInfo.CacheTTL <= 0 {
		c.OIDC.UserInfo.CacheTTL = 5 * time.Minute
	}

	if c.OIDC.UserInfo.Timeout <= 0 {
		c.OIDC.UserInfo.Timeout = 10 * time.Second
	}

	// If discovery is enabled, we need an issuer
	if !c.OIDC.SkipDiscovery {
		if c.Validation.Issuer == "" && c.Provider.Issuer() == "" {
			return fmt.Errorf("%w: issuer required for oidc discovery", ErrInvalidConfiguration)
		}

		// If no explicit discovery URL, we'll construct it from the issuer
		if c.OIDC.DiscoveryURL == "" {
			issuer := c.Validation.Issuer
			if issuer == "" {
				issuer = c.Provider.Issuer()
			}
			if issuer == "" {
				return fmt.Errorf("%w: issuer required for oidc discovery", ErrInvalidConfiguration)
			}
		}
	}

	// If discovery is skipped, manual configuration must be provided
	if c.OIDC.SkipDiscovery && c.OIDC.Discovery == nil {
		return fmt.Errorf("%w: oidc discovery document required when discovery is disabled", ErrInvalidConfiguration)
	}

	return nil
}
