package oauth

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/jeremyhahn/go-enclave"
)

// Authenticator is the main OAuth 2.0 authentication handler.
// It is thread-safe and immutable after construction.
type Authenticator struct {
	config          *Config
	validator       *tokenValidator
	flows           *flowHandler
	cache           TokenCache
	oidcValidator   *oidcValidator
	discoveryClient *discoveryClient
	userInfoClient  *userInfoClient
}

// NewAuthenticator creates a new OAuth authenticator with the given configuration.
//
// It takes ownership of config.ClientSecret on every return path: the
// Authenticator destroys it in Close, and NewAuthenticator destroys it before
// returning an error. The caller must not use that enclave again.
func NewAuthenticator(config *Config) (auth *Authenticator, err error) {
	if config == nil {
		return nil, fmt.Errorf("%w: config is nil", ErrInvalidConfiguration)
	}

	defer func() {
		if err != nil {
			config.ClientSecret.Destroy()
		}
	}()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Create HTTP client
	httpClient := newDefaultHTTPClient(config.Timeout, config.TLSConfig, config.InsecureSkipVerify)

	// Create authenticator
	auth = &Authenticator{
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
		validator, verr := newTokenValidator(config, httpClient)
		if verr != nil {
			auth.closeCache()
			return nil, verr
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
//
// The token is borrowed, not destroyed: a bearer token taken from an inbound
// request is typically sealed by the caller and destroyed once this returns.
// It is opened only at the JWT parse boundary and, for introspection, copied
// into a locked request body. Cached claims are keyed by the token's SHA-256
// fingerprint and held in an enclave.
func (a *Authenticator) ValidateToken(ctx context.Context, token *enclave.MemoryEnclave) (*TokenClaims, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := token.WithBytes(func(b []byte) error {
		if len(bytes.TrimSpace(b)) == 0 {
			return ErrMissingToken
		}
		return nil
	}); err != nil {
		return nil, ErrMissingToken
	}

	// Check cache first
	cacheKey, err := tokenFingerprint(token)
	if err != nil {
		return nil, err
	}
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

	// Cache the validated token claims. Claims that cannot be sealed into
	// locked memory fail the call rather than being cached in the clear.
	if a.config.Cache.Enabled {
		if err := a.cache.Set(cacheKey, claims, a.config.Cache.TTL); err != nil {
			return nil, err
		}
	}

	return claims, nil
}

// AuthenticatePassword performs resource owner password credentials flow.
// Returns a Token on successful authentication. The password is borrowed and
// copied from its enclave into a locked request body; it is not destroyed.
func (a *Authenticator) AuthenticatePassword(ctx context.Context, username string, password *enclave.MemoryEnclave) (*Token, error) {
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

// ExchangeAuthorizationCode exchanges an authorization code for tokens without
// PKCE. Use ExchangeAuthorizationCodePKCE for a flow started with
// BuildAuthURLPKCE.
//
// The code stays a string: it arrives in the redirect's query string, which
// net/http has already parsed into strings, and is redeemable exactly once.
func (a *Authenticator) ExchangeAuthorizationCode(ctx context.Context, code string) (*Token, error) {
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

	return a.flows.exchangeAuthorizationCode(ctx, code)
}

// RefreshToken uses a refresh token to obtain a new access token.
//
// The refresh token is borrowed: it is copied from its enclave into a locked
// request body and is not destroyed, so a caller can pass token.RefreshToken()
// straight through and destroy the old Token afterwards. The returned Token is
// the caller's to Destroy.
func (a *Authenticator) RefreshToken(ctx context.Context, refreshToken *enclave.MemoryEnclave) (*Token, error) {
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

// BuildAuthURL builds the authorization URL for the authorization code flow
// without PKCE. state should be a random string to prevent CSRF attacks.
// additionalParams may not set a parameter this package owns; see buildAuthURL's
// reservedAuthParams. Use BuildAuthURLPKCE for a flow with PKCE.
func (a *Authenticator) BuildAuthURL(state string, additionalParams map[string]string) (string, error) {
	if a.config.Flow != FlowAuthorizationCode {
		return "", fmt.Errorf("%w: authorization code flow not configured", ErrFlowNotSupported)
	}

	if a.flows == nil {
		return "", fmt.Errorf("%w: flow handler not initialized", ErrInvalidConfiguration)
	}

	return a.flows.buildAuthURL(state, "", additionalParams)
}

// Authenticate is a convenience method that validates a bearer token. It is
// the pkg/api adapter: username is ignored and the token arrives where other
// backends take a password.
//
// The token is BORROWED and never destroyed here; a nil, destroyed or blank
// token fails with ErrMissingToken.
func (a *Authenticator) Authenticate(ctx context.Context, _ string, token *enclave.MemoryEnclave) error {
	_, err := a.ValidateToken(ctx, token)
	return err
}

// ClearCache clears all cached tokens.
func (a *Authenticator) ClearCache() {
	if a.cache != nil {
		a.cache.Clear()
	}
}

// Close releases resources held by the authenticator and destroys every
// credential it owns: the client secret, the cached claims and the cached
// UserInfo responses. Requests made after Close fail with
// ErrCredentialUnavailable rather than going out without the client secret.
func (a *Authenticator) Close() error {
	if a.validator != nil {
		a.validator.Close()
	}

	a.closeCache()

	if a.userInfoClient != nil {
		a.userInfoClient.Close()
	}

	// Close OIDC components
	if a.oidcValidator != nil {
		a.oidcValidator.Close()
	}

	a.config.ClientSecret.Destroy()

	return nil
}

// closeCache closes the LRU cache, if one is in use, destroying its entries.
func (a *Authenticator) closeCache() {
	if lru, ok := a.cache.(*lruCache); ok {
		lru.Close()
	}
}

// OIDC-specific methods

// ValidateIDToken validates an OpenID Connect ID token.
// nonce is optional but recommended for authorization code flow.
// accessToken is optional (nil) and used for at_hash validation if present.
// Both tokens are borrowed, not destroyed; the ID token is opened only at the
// JWT parse boundary and the access token is hashed inside its enclave.
func (a *Authenticator) ValidateIDToken(ctx context.Context, idToken *enclave.MemoryEnclave, nonce string, accessToken *enclave.MemoryEnclave) (*IDTokenClaims, error) {
	if !a.isOIDCEnabled() {
		return nil, ErrOIDCNotEnabled
	}

	return a.oidcValidator.ValidateIDToken(ctx, idToken, nonce, accessToken)
}

// GetUserInfo fetches user information from the OIDC UserInfo endpoint.
// Requires an access token with the appropriate scopes (typically "openid" and "profile").
// The access token is borrowed, not destroyed.
func (a *Authenticator) GetUserInfo(ctx context.Context, accessToken *enclave.MemoryEnclave) (*UserInfo, error) {
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
// The token is borrowed, not destroyed.
func (a *Authenticator) GetIdentityClaims(ctx context.Context, token *Token, nonce string) (*IdentityClaims, error) {
	if !a.isOIDCEnabled() {
		return nil, ErrOIDCNotEnabled
	}

	if token == nil {
		return nil, fmt.Errorf("%w: token is nil", ErrMissingToken)
	}

	// Validate ID token
	var idClaims *IDTokenClaims
	if token.IDToken().IsAlive() {
		var err error
		idClaims, err = a.ValidateIDToken(ctx, token.IDToken(), nonce, token.AccessToken())
		if err != nil {
			return nil, err
		}
	} else if a.config.OIDC.RequireIDToken {
		return nil, ErrOIDCMissingIDToken
	}

	// Fetch UserInfo if enabled
	var userInfo *UserInfo
	if a.config.OIDC.UserInfo.Enabled && token.AccessToken().IsAlive() {
		var err error
		userInfo, err = a.GetUserInfo(ctx, token.AccessToken())
		if err != nil {
			// A UserInfo fetch failure must not fail authentication: the ID
			// token already carries the authenticated identity. Continue
			// without the supplementary claims.
			userInfo = nil
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
