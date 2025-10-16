package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// discoveryClient handles OIDC discovery document fetching and caching.
type discoveryClient struct {
	mu         sync.RWMutex
	httpClient *http.Client
	config     *OIDCConfig
	cache      *OIDCDiscoveryConfig
}

// newDiscoveryClient creates a new discovery client.
func newDiscoveryClient(httpClient *http.Client, config *OIDCConfig) *discoveryClient {
	return &discoveryClient{
		httpClient: httpClient,
		config:     config,
	}
}

// getDiscovery fetches the OIDC discovery document, using cache if valid.
func (dc *discoveryClient) getDiscovery(ctx context.Context, issuer string) (*OIDCDiscoveryConfig, error) {
	// Check if discovery is disabled
	if dc.config != nil && dc.config.SkipDiscovery {
		if dc.config.Discovery != nil {
			return dc.config.Discovery, nil
		}
		return nil, fmt.Errorf("%w: discovery disabled but no manual configuration provided", ErrOIDCDiscoveryFailed)
	}

	// Check cache first
	dc.mu.RLock()
	cached := dc.cache
	dc.mu.RUnlock()

	ttl := 24 * time.Hour
	if dc.config != nil && dc.config.DiscoveryCacheTTL > 0 {
		ttl = dc.config.DiscoveryCacheTTL
	}

	if cached != nil && !cached.Expired(ttl) {
		return cached, nil
	}

	// Fetch new discovery document
	doc, err := dc.fetchDiscovery(ctx, issuer)
	if err != nil {
		// Return cached document if available, even if expired
		if cached != nil {
			return cached, nil
		}
		return nil, err
	}

	// Validate discovery document
	if err := doc.Validate(); err != nil {
		return nil, err
	}

	// Update cache
	dc.mu.Lock()
	dc.cache = doc
	dc.mu.Unlock()

	return doc, nil
}

// fetchDiscovery retrieves the OIDC discovery document from the provider.
func (dc *discoveryClient) fetchDiscovery(ctx context.Context, issuer string) (*OIDCDiscoveryConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	// Determine discovery URL
	discoveryURL := dc.config.DiscoveryURL
	if discoveryURL == "" {
		discoveryURL = buildDiscoveryURL(issuer)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create discovery request: %v", ErrOIDCDiscoveryFailed, err)
	}

	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := dc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch discovery document: %v", ErrOIDCDiscoveryFailed, err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("%w: unexpected status %d: %s", ErrOIDCDiscoveryFailed, resp.StatusCode, string(body))
	}

	// Parse response
	var doc OIDCDiscoveryConfig
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: failed to parse discovery document: %v", ErrOIDCDiscoveryFailed, err)
	}

	// Set fetch time
	doc.FetchedAt = time.Now()

	return &doc, nil
}

// buildDiscoveryURL constructs the standard OIDC discovery URL from an issuer.
func buildDiscoveryURL(issuer string) string {
	issuer = strings.TrimSpace(issuer)
	issuer = strings.TrimSuffix(issuer, "/")
	return issuer + "/.well-known/openid-configuration"
}

// RefreshDiscovery forces a refresh of the cached discovery document.
func (dc *discoveryClient) RefreshDiscovery(ctx context.Context, issuer string) error {
	doc, err := dc.fetchDiscovery(ctx, issuer)
	if err != nil {
		return err
	}

	if err := doc.Validate(); err != nil {
		return err
	}

	dc.mu.Lock()
	dc.cache = doc
	dc.mu.Unlock()

	return nil
}

// GetCachedDiscovery returns the cached discovery document without fetching.
func (dc *discoveryClient) GetCachedDiscovery() *OIDCDiscoveryConfig {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	return dc.cache
}

// SetDiscovery manually sets the discovery document (for testing or manual configuration).
func (dc *discoveryClient) SetDiscovery(doc *OIDCDiscoveryConfig) error {
	if err := doc.Validate(); err != nil {
		return err
	}

	dc.mu.Lock()
	defer dc.mu.Unlock()
	dc.cache = doc

	return nil
}
