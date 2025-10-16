package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// userInfoEntry represents a cached UserInfo response.
type userInfoEntry struct {
	userInfo  *UserInfo
	expiresAt time.Time
}

// userInfoClient handles UserInfo endpoint requests and caching.
type userInfoClient struct {
	mu             sync.RWMutex
	httpClient     *http.Client
	config         *Config
	cache          map[string]*userInfoEntry
	discoveryClient *discoveryClient
}

// newUserInfoClient creates a new UserInfo client.
func newUserInfoClient(httpClient *http.Client, config *Config, discoveryClient *discoveryClient) *userInfoClient {
	return &userInfoClient{
		httpClient:      httpClient,
		config:          config,
		cache:           make(map[string]*userInfoEntry),
		discoveryClient: discoveryClient,
	}
}

// GetUserInfo fetches user information from the UserInfo endpoint.
// It uses the access token for authentication and caches the response.
func (c *userInfoClient) GetUserInfo(ctx context.Context, accessToken string, issuer string) (*UserInfo, error) {
	if !c.isUserInfoEnabled() {
		return nil, ErrOIDCNotEnabled
	}

	if accessToken == "" {
		return nil, fmt.Errorf("%w: access token required", ErrOIDCUserInfoFailed)
	}

	// Check cache first
	if cached := c.getFromCache(accessToken); cached != nil {
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
	c.cacheUserInfo(accessToken, userInfo)

	return userInfo, nil
}

// fetchUserInfo makes the HTTP request to the UserInfo endpoint.
func (c *userInfoClient) fetchUserInfo(ctx context.Context, userInfoURL string, accessToken string) (*UserInfo, error) {
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
	req.Header.Set("Authorization", "Bearer "+accessToken)
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

// getFromCache retrieves cached UserInfo if available and not expired.
func (c *userInfoClient) getFromCache(accessToken string) *UserInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[accessToken]
	if !exists {
		return nil
	}

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry.userInfo
}

// cacheUserInfo stores UserInfo in the cache.
func (c *userInfoClient) cacheUserInfo(accessToken string, userInfo *UserInfo) {
	ttl := 5 * time.Minute // Default
	if c.config.OIDC != nil && c.config.OIDC.UserInfo.CacheTTL > 0 {
		ttl = c.config.OIDC.UserInfo.CacheTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[accessToken] = &userInfoEntry{
		userInfo:  userInfo,
		expiresAt: time.Now().Add(ttl),
	}

	// Simple cache cleanup: remove expired entries
	c.cleanupExpiredLocked()
}

// cleanupExpiredLocked removes expired entries from the cache.
// Must be called with write lock held.
func (c *userInfoClient) cleanupExpiredLocked() {
	now := time.Now()
	for key, entry := range c.cache {
		if now.After(entry.expiresAt) {
			delete(c.cache, key)
		}
	}
}

// ClearCache removes all cached UserInfo responses.
func (c *userInfoClient) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*userInfoEntry)
}

// isUserInfoEnabled checks if UserInfo endpoint calls are enabled.
func (c *userInfoClient) isUserInfoEnabled() bool {
	return c.config.OIDC != nil &&
		c.config.OIDC.Enabled &&
		c.config.OIDC.UserInfo.Enabled
}
