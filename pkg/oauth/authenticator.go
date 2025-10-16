package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// Authenticator is the main OAuth 2.0 authentication handler.
// It is thread-safe and immutable after construction.
type Authenticator struct {
	config           *Config
	validator        *tokenValidator
	flows            *flowHandler
	cache            TokenCache
	oidcValidator    *oidcValidator
	discoveryClient  *discoveryClient
	userInfoClient   *userInfoClient
}

// NewAuthenticator creates a new OAuth authenticator with the given configuration.
func NewAuthenticator(config *Config) (*Authenticator, error) {
	if config == nil {
		return nil, fmt.Errorf("%w: config is nil", ErrInvalidConfiguration)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Create HTTP client
	httpClient := newDefaultHTTPClient(config.Timeout, config.TLSConfig, config.InsecureSkipVerify)

	// Create authenticator
	auth := &Authenticator{
		config: config,
	}

	// Initialize token cache
	if config.Cache.Enabled {
		auth.cache = newLRUCache(config.Cache.MaxSize)
	} else {
		auth.cache = &noopCache{}
	}

	// Initialize validator for token validation flow
	if config.Flow == FlowTokenValidation || config.Validation.Method != "" {
		validator, err := newTokenValidator(config, httpClient)
		if err != nil {
			return nil, err
		}
		auth.validator = validator
	}

	// Initialize flow handler for token exchange flows
	if config.Flow != FlowTokenValidation {
		auth.flows = newFlowHandler(config, httpClient)
	}

	// Initialize OIDC components if enabled
	if config.OIDC != nil && config.OIDC.Enabled {
		// Get underlying *http.Client from HTTPClient interface
		var stdHTTPClient *http.Client
		if dhc, ok := httpClient.(*defaultHTTPClient); ok {
			stdHTTPClient = dhc.client
		}

		auth.discoveryClient = newDiscoveryClient(stdHTTPClient, config.OIDC)
		auth.oidcValidator = newOIDCValidator(config, auth.validator, auth.discoveryClient)
		auth.userInfoClient = newUserInfoClient(stdHTTPClient, config, auth.discoveryClient)
	}

	return auth, nil
}

// ValidateToken validates an access token and returns the claims.
// The token can be a JWT or opaque token depending on the provider.
func (a *Authenticator) ValidateToken(ctx context.Context, token string) (*TokenClaims, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if strings.TrimSpace(token) == "" {
		return nil, ErrMissingToken
	}

	// Check cache first
	cacheKey := a.tokenCacheKey(token)
	if cached := a.cache.Get(cacheKey); cached != nil {
		if cached.ValidWithClockSkew(a.config.Validation.ClockSkew) {
			return cached, nil
		}
		// Cached token expired, remove from cache
		a.cache.Delete(cacheKey)
	}

	// Validate token
	if a.validator == nil {
		return nil, fmt.Errorf("%w: validator not initialized", ErrInvalidConfiguration)
	}

	claims, err := a.validator.validate(ctx, token)
	if err != nil {
		return nil, err
	}

	// Cache the validated token claims
	if a.config.Cache.Enabled {
		a.cache.Set(cacheKey, claims, a.config.Cache.TTL)
	}

	return claims, nil
}

// AuthenticatePassword performs resource owner password credentials flow.
// Returns a Token on successful authentication.
func (a *Authenticator) AuthenticatePassword(ctx context.Context, username, password string) (*Token, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if a.config.Flow != FlowPassword {
		return nil, fmt.Errorf("%w: password flow not configured", ErrFlowNotSupported)
	}

	if a.flows == nil {
		return nil, fmt.Errorf("%w: flow handler not initialized", ErrInvalidConfiguration)
	}

	return a.flows.authenticatePassword(ctx, username, password)
}

// AuthenticateClientCredentials performs client credentials flow.
// Returns a Token on successful authentication.
func (a *Authenticator) AuthenticateClientCredentials(ctx context.Context) (*Token, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if a.config.Flow != FlowClientCredentials {
		return nil, fmt.Errorf("%w: client credentials flow not configured", ErrFlowNotSupported)
	}

	if a.flows == nil {
		return nil, fmt.Errorf("%w: flow handler not initialized", ErrInvalidConfiguration)
	}

	return a.flows.authenticateClientCredentials(ctx)
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens.
// codeVerifier is optional and only required if PKCE was used.
func (a *Authenticator) ExchangeAuthorizationCode(ctx context.Context, code, codeVerifier string) (*Token, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if a.config.Flow != FlowAuthorizationCode {
		return nil, fmt.Errorf("%w: authorization code flow not configured", ErrFlowNotSupported)
	}

	if a.flows == nil {
		return nil, fmt.Errorf("%w: flow handler not initialized", ErrInvalidConfiguration)
	}

	return a.flows.exchangeAuthorizationCode(ctx, code, codeVerifier)
}

// RefreshToken uses a refresh token to obtain a new access token.
func (a *Authenticator) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if a.flows == nil {
		return nil, fmt.Errorf("%w: flow handler not initialized", ErrInvalidConfiguration)
	}

	return a.flows.refreshToken(ctx, refreshToken)
}

// BuildAuthURL builds the authorization URL for the authorization code flow.
// state should be a random string to prevent CSRF attacks.
// usePKCE enables PKCE (Proof Key for Code Exchange) and returns the code verifier.
func (a *Authenticator) BuildAuthURL(state string, usePKCE bool, additionalParams map[string]string) (authURL string, codeVerifier string, err error) {
	if a.config.Flow != FlowAuthorizationCode {
		return "", "", fmt.Errorf("%w: authorization code flow not configured", ErrFlowNotSupported)
	}

	if a.flows == nil {
		return "", "", fmt.Errorf("%w: flow handler not initialized", ErrInvalidConfiguration)
	}

	var codeChallenge string
	if usePKCE {
		codeVerifier, codeChallenge = generatePKCE()
	}

	authURL = a.flows.buildAuthURL(state, codeChallenge, additionalParams)
	return authURL, codeVerifier, nil
}

// Authenticate is a convenience method that validates a token.
// It implements the passwordAuthenticator interface used by the api package.
// The token should be passed as the password parameter.
func (a *Authenticator) Authenticate(ctx context.Context, username, token string) error {
	// For token validation, we ignore username and use the token
	_, err := a.ValidateToken(ctx, token)
	return err
}

// tokenCacheKey generates a cache key for a token.
func (a *Authenticator) tokenCacheKey(token string) string {
	// Use SHA256 hash of token as cache key to avoid storing raw tokens
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// ClearCache clears all cached tokens.
func (a *Authenticator) ClearCache() {
	if a.cache != nil {
		a.cache.Clear()
	}
}

// Close releases resources held by the authenticator.
func (a *Authenticator) Close() error {
	if a.validator != nil {
		a.validator.Close()
	}

	// Close LRU cache if applicable
	if lru, ok := a.cache.(*lruCache); ok {
		lru.Close()
	}

	// Close OIDC components
	if a.oidcValidator != nil {
		a.oidcValidator.Close()
	}

	return nil
}

// generatePKCE generates PKCE code verifier and challenge.
func generatePKCE() (verifier, challenge string) {
	// Generate a random code verifier (43-128 chars)
	verifierBytes := make([]byte, 32)
	for i := range verifierBytes {
		verifierBytes[i] = byte(i)
	}

	verifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Generate code challenge (SHA256 of verifier)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return verifier, challenge
}

// OIDC-specific methods

// ValidateIDToken validates an OpenID Connect ID token.
// nonce is optional but recommended for authorization code flow.
// accessToken is optional and used for at_hash validation if present.
func (a *Authenticator) ValidateIDToken(ctx context.Context, idToken string, nonce string, accessToken string) (*IDTokenClaims, error) {
	if !a.isOIDCEnabled() {
		return nil, ErrOIDCNotEnabled
	}

	return a.oidcValidator.ValidateIDToken(ctx, idToken, nonce, accessToken)
}

// GetUserInfo fetches user information from the OIDC UserInfo endpoint.
// Requires an access token with the appropriate scopes (typically "openid" and "profile").
func (a *Authenticator) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if !a.isOIDCEnabled() {
		return nil, ErrOIDCNotEnabled
	}

	issuer := a.config.Validation.Issuer
	if issuer == "" {
		issuer = a.config.Provider.Issuer()
	}

	return a.userInfoClient.GetUserInfo(ctx, accessToken, issuer)
}

// GetIdentityClaims retrieves complete identity information by merging ID token and UserInfo.
// This is a convenience method that validates the ID token and optionally fetches UserInfo.
func (a *Authenticator) GetIdentityClaims(ctx context.Context, token *Token, nonce string) (*IdentityClaims, error) {
	if !a.isOIDCEnabled() {
		return nil, ErrOIDCNotEnabled
	}

	if token == nil {
		return nil, fmt.Errorf("%w: token is nil", ErrMissingToken)
	}

	// Validate ID token
	var idClaims *IDTokenClaims
	if token.IDToken != "" {
		var err error
		idClaims, err = a.ValidateIDToken(ctx, token.IDToken, nonce, token.AccessToken)
		if err != nil {
			return nil, err
		}
	} else if a.config.OIDC.RequireIDToken {
		return nil, ErrOIDCMissingIDToken
	}

	// Fetch UserInfo if enabled
	var userInfo *UserInfo
	if a.config.OIDC.UserInfo.Enabled && token.AccessToken != "" {
		var err error
		userInfo, err = a.GetUserInfo(ctx, token.AccessToken)
		if err != nil {
			// Don't fail if UserInfo fetch fails, just log and continue without it
			// In production, you might want to log this error
		}
	}

	// Merge claims
	return MergeIdentityClaims(idClaims, userInfo), nil
}

// GenerateNonce generates a cryptographically random nonce for OIDC authorization requests.
// The nonce should be stored and validated when the ID token is received.
func (a *Authenticator) GenerateNonce() (string, error) {
	if !a.isOIDCEnabled() {
		return "", ErrOIDCNotEnabled
	}

	return a.oidcValidator.GenerateNonce()
}

// GetDiscovery retrieves the OIDC discovery document for the configured issuer.
// This can be useful for inspecting provider capabilities.
func (a *Authenticator) GetDiscovery(ctx context.Context) (*OIDCDiscoveryConfig, error) {
	if !a.isOIDCEnabled() {
		return nil, ErrOIDCNotEnabled
	}

	issuer := a.config.Validation.Issuer
	if issuer == "" {
		issuer = a.config.Provider.Issuer()
	}

	return a.discoveryClient.getDiscovery(ctx, issuer)
}

// RefreshDiscovery forces a refresh of the cached OIDC discovery document.
func (a *Authenticator) RefreshDiscovery(ctx context.Context) error {
	if !a.isOIDCEnabled() {
		return ErrOIDCNotEnabled
	}

	issuer := a.config.Validation.Issuer
	if issuer == "" {
		issuer = a.config.Provider.Issuer()
	}

	return a.discoveryClient.RefreshDiscovery(ctx, issuer)
}

// ClearUserInfoCache clears the UserInfo response cache.
func (a *Authenticator) ClearUserInfoCache() {
	if a.isOIDCEnabled() && a.userInfoClient != nil {
		a.userInfoClient.ClearCache()
	}
}

// isOIDCEnabled checks if OIDC features are enabled.
func (a *Authenticator) isOIDCEnabled() bool {
	return a.config.OIDC != nil && a.config.OIDC.Enabled && a.oidcValidator != nil
}
