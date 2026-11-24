package oauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
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

// NewAuthenticator creates an OAuth authenticator and takes ownership of config.ClientSecret on every return path.
func NewAuthenticator(config *Config) (auth *Authenticator, err error) {
	if config == nil {
		return nil, fmt.Errorf("%w: config is nil", ErrInvalidConfiguration)
	}

	defer func() {
		if err != nil {
			err = credential.DestroyAll(err, config.ClientSecret)
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
			if cerr := auth.closeCache(); cerr != nil {
				verr = errors.Join(verr, cerr)
			}
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

// ValidateToken validates a JWT or opaque access token and returns its claims; the token is borrowed and cached claims are keyed by its SHA-256 fingerprint.
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

// ExchangeAuthorizationCode exchanges a code for tokens without PKCE; the single-use code stays a string.
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

// RefreshToken obtains a new token with a borrowed refresh token; the returned Token is the caller's to Destroy.
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

// BuildAuthURL builds the authorization URL without PKCE; additionalParams may not set reserved parameters.
func (a *Authenticator) BuildAuthURL(state string, additionalParams map[string]string) (string, error) {
	if a.config.Flow != FlowAuthorizationCode {
		return "", fmt.Errorf("%w: authorization code flow not configured", ErrFlowNotSupported)
	}

	if a.flows == nil {
		return "", fmt.Errorf("%w: flow handler not initialized", ErrInvalidConfiguration)
	}

	return a.flows.buildAuthURL(state, "", additionalParams)
}

// Authenticate validates a borrowed bearer token for the pkg/api adapter; username is ignored.
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

// Close destroys the client secret and both caches; later requests fail with ErrCredentialUnavailable.
func (a *Authenticator) Close() error {
	if a.validator != nil {
		a.validator.Close()
	}

	errs := []error{a.closeCache()}

	if a.userInfoClient != nil {
		errs = append(errs, a.userInfoClient.Close())
	}

	// Close OIDC components
	if a.oidcValidator != nil {
		a.oidcValidator.Close()
	}

	return errors.Join(append(errs, a.config.ClientSecret.Destroy())...)
}

// closeCache closes the LRU cache, if one is in use, destroying its entries.
func (a *Authenticator) closeCache() error {
	if lru, ok := a.cache.(*lruCache); ok {
		return lru.Close()
	}
	return nil
}

// OIDC-specific methods

// ValidateIDToken validates an OIDC ID token with an optional nonce and access token for at_hash; both tokens are borrowed.
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
