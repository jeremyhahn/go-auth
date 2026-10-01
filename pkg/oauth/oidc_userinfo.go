package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-enclave"
)

// sealedUserInfo is the cached form of a UserInfo. Custom is carried beside it
// because UserInfo excludes it from its own JSON encoding.
type sealedUserInfo struct {
	UserInfo *UserInfo              `json:"userinfo"`
	Custom   map[string]interface{} `json:"custom,omitempty"`
}

// userInfoClient handles UserInfo endpoint requests and caching.
//
// Responses are cached in a sealedLRU keyed by the access token's fingerprint,
// so the cache is bounded by UserInfoConfig.CacheMaxSize and by the
// locked-memory allowance exactly as the claims cache is: an unbounded cache of
// locked pages would be a memory-exhaustion path for anyone able to present
// distinct access tokens.
type userInfoClient struct {
	httpClient      *http.Client
	config          *Config
	cache           *sealedLRU
	discoveryClient *discoveryClient
}

// newUserInfoClient creates a new UserInfo client.
func newUserInfoClient(httpClient *http.Client, config *Config, discoveryClient *discoveryClient) *userInfoClient {
	maxSize := defaultUserInfoCacheMaxSize
	if config.OIDC != nil && config.OIDC.UserInfo.CacheMaxSize > 0 {
		maxSize = config.OIDC.UserInfo.CacheMaxSize
	}

	return &userInfoClient{
		httpClient:      httpClient,
		config:          config,
		cache:           newSealedLRU(maxSize, enclave.NewMemoryEnclave, time.Now),
		discoveryClient: discoveryClient,
	}
}

// GetUserInfo fetches user information from the UserInfo endpoint.
// It uses the access token for authentication and caches the response under
// the token's fingerprint. The access token is borrowed, not destroyed.
func (c *userInfoClient) GetUserInfo(ctx context.Context, accessToken *enclave.MemoryEnclave, issuer string) (*UserInfo, error) {
	if !c.isUserInfoEnabled() {
		return nil, ErrOIDCNotEnabled
	}

	key, err := tokenFingerprint(accessToken)
	if err != nil {
		return nil, fmt.Errorf("%w: access token required", ErrOIDCUserInfoFailed)
	}

	// Check cache first
	if cached := c.getFromCache(key); cached != nil {
		return cached, nil
	}

	// Get UserInfo endpoint URL
	userInfoURL, err := c.getUserInfoEndpoint(ctx, issuer)
	if err != nil {
		return nil, err
	}

	if userInfoURL == "" {
		return nil, fmt.Errorf("%w: userinfo endpoint not configured", ErrOIDCUserInfoFailed)
	}

	// Fetch UserInfo
	userInfo, err := c.fetchUserInfo(ctx, userInfoURL, accessToken)
	if err != nil {
		return nil, err
	}

	// Cache the response
	if err := c.cacheUserInfo(key, userInfo); err != nil {
		return nil, errors.Join(ErrOIDCUserInfoFailed, err)
	}

	return userInfo, nil
}

// fetchUserInfo makes the HTTP request to the UserInfo endpoint.
func (c *userInfoClient) fetchUserInfo(ctx context.Context, userInfoURL string, accessToken *enclave.MemoryEnclave) (*UserInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	// Create request with timeout
	timeout := 10 * time.Second
	if c.config.OIDC != nil && c.config.OIDC.UserInfo.Timeout > 0 {
		timeout = c.config.OIDC.UserInfo.Timeout
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %v", ErrOIDCUserInfoFailed, err)
	}

	// Set authorization header
	if err := accessToken.WithBytes(func(b []byte) error {
		// Residue R5: net/http carries the bearer token only as a header string.
		req.Header.Set("Authorization", "Bearer "+string(b))
		return nil
	}); err != nil {
		return nil, errors.Join(ErrOIDCUserInfoFailed, ErrCredentialUnavailable, err)
	}
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %v", ErrOIDCUserInfoFailed, err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("%w: unexpected status %d: %s", ErrOIDCUserInfoFailed, resp.StatusCode, string(body))
	}

	// Parse response
	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("%w: failed to parse response: %v", ErrOIDCInvalidUserInfo, err)
	}

	// Validate that sub claim is present
	if userInfo.Subject == "" {
		return nil, fmt.Errorf("%w: missing sub claim", ErrOIDCInvalidUserInfo)
	}

	// Initialize Custom map if there are any extra fields
	if userInfo.Custom == nil {
		userInfo.Custom = make(map[string]interface{})
	}

	return &userInfo, nil
}

// getUserInfoEndpoint determines the UserInfo endpoint URL.
func (c *userInfoClient) getUserInfoEndpoint(ctx context.Context, issuer string) (string, error) {
	// Try provider's UserInfoURL() method first
	if providerURL := c.config.Provider.UserInfoURL(); providerURL != "" {
		return providerURL, nil
	}

	// Fall back to discovery document
	if c.discoveryClient != nil {
		discovery, err := c.discoveryClient.getDiscovery(ctx, issuer)
		if err != nil {
			return "", fmt.Errorf("%w: failed to get discovery document: %v", ErrOIDCUserInfoFailed, err)
		}
		return discovery.UserInfoEndpoint, nil
	}

	return "", fmt.Errorf("%w: userinfo endpoint not available", ErrOIDCUserInfoFailed)
}

// getFromCache retrieves a copy of cached UserInfo if available and not
// expired, decoded from its enclave. key is a token fingerprint. A read that
// finds an expired entry destroys it.
func (c *userInfoClient) getFromCache(key string) *UserInfo {
	var cached sealedUserInfo
	if !c.cache.get(key, &cached) || cached.UserInfo == nil {
		return nil
	}

	cached.UserInfo.Custom = cached.Custom
	if cached.UserInfo.Custom == nil {
		cached.UserInfo.Custom = make(map[string]interface{})
	}

	return cached.UserInfo
}

// cacheUserInfo seals UserInfo into an enclave and stores it under key, a
// token fingerprint. It fails, and caches nothing, when the response cannot be
// sealed into locked memory, and with ErrCacheClosed once Close has run; see
// sealedLRU.set for the order in which locked memory is reclaimed.
func (c *userInfoClient) cacheUserInfo(key string, userInfo *UserInfo) error {
	ttl := 5 * time.Minute // Default
	if c.config.OIDC != nil && c.config.OIDC.UserInfo.CacheTTL > 0 {
		ttl = c.config.OIDC.UserInfo.CacheTTL
	}

	return c.cache.set(key, sealedUserInfo{UserInfo: userInfo, Custom: userInfo.Custom}, ttl)
}

// ClearCache removes and destroys all cached UserInfo responses. The cache
// stays usable.
func (c *userInfoClient) ClearCache() {
	c.cache.clear()
}

// Close destroys every cached entry and closes the cache for good: a later
// insert — including one from a request that was in flight during Close —
// fails with ErrCacheClosed instead of leaving an enclave nothing will destroy.
// It is idempotent.
func (c *userInfoClient) Close() {
	c.cache.close()
}

// isUserInfoEnabled checks if UserInfo endpoint calls are enabled.
func (c *userInfoClient) isUserInfoEnabled() bool {
	return c.config.OIDC != nil &&
		c.config.OIDC.Enabled &&
		c.config.OIDC.UserInfo.Enabled
}
