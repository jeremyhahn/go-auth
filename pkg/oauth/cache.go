package oauth

import (
	"sync"
	"time"

	"github.com/jeremyhahn/go-enclave"
)

// TokenCache defines the interface for caching validated tokens.
//
// Keys are token fingerprints (see tokenFingerprint), never tokens.
type TokenCache interface {
	// Get retrieves a copy of the cached token claims by key.
	// Returns nil if not found or expired.
	Get(key string) *TokenClaims

	// Set stores token claims with the specified TTL. It fails, and stores
	// nothing, when the claims cannot be sealed into locked memory, and with
	// ErrCacheClosed once the cache has been closed.
	Set(key string, claims *TokenClaims, ttl time.Duration) error

	// Delete removes a token from the cache.
	Delete(key string)

	// Clear removes all cached tokens.
	Clear()
}

// lruCache is the TokenCache for validated claims: a sealedLRU, which holds
// every lifecycle rule (bounds, eviction, expiry, close), plus a background
// sweep of expired entries.
type lruCache struct {
	*sealedLRU
	stopCleanup chan struct{}
	cleanupOnce sync.Once
}

// newLRUCache creates a new LRU cache with the specified maximum size.
func newLRUCache(maxSize int) *lruCache {
	return newLRUCacheWith(maxSize, enclave.NewMemoryEnclave, time.Now)
}

// newLRUCacheWith creates an LRU cache that seals entries with alloc and reads
// time from now — the seams a test uses to impose a locked-memory budget and
// to move the clock.
func newLRUCacheWith(maxSize int, alloc allocFunc, now func() time.Time) *lruCache {
	cache := &lruCache{
		sealedLRU:   newSealedLRU(maxSize, alloc, now),
		stopCleanup: make(chan struct{}),
	}

	// Start background cleanup goroutine
	go cache.cleanupExpired()

	return cache
}

// Get retrieves a copy of the cached token claims by key, decoded from the
// entry's enclave. The caller owns the copy.
func (c *lruCache) Get(key string) *TokenClaims {
	var claims TokenClaims
	if !c.get(key, &claims) {
		return nil
	}
	return &claims
}

// Set seals token claims into an enclave and stores them with the specified
// TTL; see sealedLRU.set for the order in which locked memory is reclaimed.
func (c *lruCache) Set(key string, claims *TokenClaims, ttl time.Duration) error {
	if claims == nil {
		return nil
	}
	return c.set(key, claims, ttl)
}

// Delete removes a token from the cache, destroying its enclave.
func (c *lruCache) Delete(key string) {
	c.remove(key)
}

// Clear removes all cached tokens, destroying their enclaves.
func (c *lruCache) Clear() {
	c.clear()
}

// cleanupExpired periodically removes expired entries.
func (c *lruCache) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.removeExpiredEntries()
		case <-c.stopCleanup:
			return
		}
	}
}

// removeExpiredEntries removes all expired cache entries.
func (c *lruCache) removeExpiredEntries() {
	c.removeExpired()
}

// Close stops the cleanup goroutine and destroys every cached entry. It is
// idempotent; a closed cache stores nothing.
func (c *lruCache) Close() {
	c.cleanupOnce.Do(func() {
		close(c.stopCleanup)
	})
	c.close()
}

// noopCache is a cache implementation that does nothing (caching disabled).
type noopCache struct{}

func (c *noopCache) Get(key string) *TokenClaims                                  { return nil }
func (c *noopCache) Set(key string, claims *TokenClaims, ttl time.Duration) error { return nil }
func (c *noopCache) Delete(key string)                                            {}
func (c *noopCache) Clear()                                                       {}
