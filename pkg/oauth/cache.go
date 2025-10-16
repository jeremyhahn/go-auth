package oauth

import (
	"container/list"
	"sync"
	"time"
)

// TokenCache defines the interface for caching validated tokens.
type TokenCache interface {
	// Get retrieves a cached token claims by key.
	// Returns nil if not found or expired.
	Get(key string) *TokenClaims

	// Set stores token claims with the specified TTL.
	Set(key string, claims *TokenClaims, ttl time.Duration)

	// Delete removes a token from the cache.
	Delete(key string)

	// Clear removes all cached tokens.
	Clear()
}

// cacheEntry represents a single cached item with expiration.
type cacheEntry struct {
	claims    *TokenClaims
	expiresAt time.Time
	key       string
}

// lruCache implements an in-memory LRU cache with TTL.
type lruCache struct {
	mu          sync.RWMutex
	maxSize     int
	items       map[string]*list.Element
	lruList     *list.List
	stopCleanup chan struct{}
	cleanupOnce sync.Once
}

// newLRUCache creates a new LRU cache with the specified maximum size.
func newLRUCache(maxSize int) *lruCache {
	if maxSize <= 0 {
		maxSize = 1000
	}

	cache := &lruCache{
		maxSize:     maxSize,
		items:       make(map[string]*list.Element),
		lruList:     list.New(),
		stopCleanup: make(chan struct{}),
	}

	// Start background cleanup goroutine
	go cache.cleanupExpired()

	return cache
}

// Get retrieves a cached token claims by key.
func (c *lruCache) Get(key string) *TokenClaims {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		return nil
	}

	entry := elem.Value.(*cacheEntry)

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		c.removeElement(elem)
		return nil
	}

	// Move to front (most recently used)
	c.lruList.MoveToFront(elem)

	return entry.claims
}

// Set stores token claims with the specified TTL.
func (c *lruCache) Set(key string, claims *TokenClaims, ttl time.Duration) {
	if claims == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	expiresAt := time.Now().Add(ttl)

	// Update existing entry
	if elem, ok := c.items[key]; ok {
		entry := elem.Value.(*cacheEntry)
		entry.claims = claims
		entry.expiresAt = expiresAt
		c.lruList.MoveToFront(elem)
		return
	}

	// Add new entry
	entry := &cacheEntry{
		claims:    claims,
		expiresAt: expiresAt,
		key:       key,
	}

	elem := c.lruList.PushFront(entry)
	c.items[key] = elem

	// Evict oldest if over capacity
	if c.lruList.Len() > c.maxSize {
		oldest := c.lruList.Back()
		if oldest != nil {
			c.removeElement(oldest)
		}
	}
}

// Delete removes a token from the cache.
func (c *lruCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.removeElement(elem)
	}
}

// Clear removes all cached tokens.
func (c *lruCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*list.Element)
	c.lruList.Init()
}

// removeElement removes an element from the cache (must be called with lock held).
func (c *lruCache) removeElement(elem *list.Element) {
	entry := elem.Value.(*cacheEntry)
	delete(c.items, entry.key)
	c.lruList.Remove(elem)
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
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var toRemove []*list.Element

	// Collect expired entries
	for elem := c.lruList.Front(); elem != nil; elem = elem.Next() {
		entry := elem.Value.(*cacheEntry)
		if now.After(entry.expiresAt) {
			toRemove = append(toRemove, elem)
		}
	}

	// Remove collected entries
	for _, elem := range toRemove {
		c.removeElement(elem)
	}
}

// Close stops the cleanup goroutine.
func (c *lruCache) Close() {
	c.cleanupOnce.Do(func() {
		close(c.stopCleanup)
	})
}

// noopCache is a cache implementation that does nothing (caching disabled).
type noopCache struct{}

func (c *noopCache) Get(key string) *TokenClaims                            { return nil }
func (c *noopCache) Set(key string, claims *TokenClaims, ttl time.Duration) {}
func (c *noopCache) Delete(key string)                                      {}
func (c *noopCache) Clear()                                                 {}
