package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// nonceEntry represents a stored nonce with its expiration time.
type nonceEntry struct {
	value     string
	expiresAt time.Time
}

// nonceStore manages nonce generation, storage, and validation.
// It is thread-safe and uses in-memory storage with automatic cleanup.
type nonceStore struct {
	mu      sync.RWMutex
	nonces  map[string]*nonceEntry
	ttl     time.Duration
	cleanup *time.Ticker
	done    chan struct{}
}

// newNonceStore creates a new nonce store with the specified TTL.
func newNonceStore(ttl time.Duration) *nonceStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute // Default
	}

	ns := &nonceStore{
		nonces:  make(map[string]*nonceEntry),
		ttl:     ttl,
		cleanup: time.NewTicker(ttl / 2), // Cleanup twice per TTL period
		done:    make(chan struct{}),
	}

	// Start cleanup goroutine
	go ns.cleanupLoop()

	return ns
}

// Generate creates a new cryptographically random nonce and stores it.
// Returns the nonce value which should be included in the authorization request.
func (ns *nonceStore) Generate() (string, error) {
	// Generate 32 random bytes
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	// Encode as base64url (URL-safe, no padding)
	nonce := base64.RawURLEncoding.EncodeToString(b)

	// Store the nonce
	ns.mu.Lock()
	defer ns.mu.Unlock()

	ns.nonces[nonce] = &nonceEntry{
		value:     nonce,
		expiresAt: time.Now().Add(ns.ttl),
	}

	return nonce, nil
}

// Validate checks if a nonce is valid and removes it from storage.
// This implements single-use nonce validation to prevent replay attacks.
func (ns *nonceStore) Validate(nonce string) error {
	if nonce == "" {
		return ErrOIDCInvalidNonce
	}

	ns.mu.Lock()
	defer ns.mu.Unlock()

	entry, exists := ns.nonces[nonce]
	if !exists {
		return ErrOIDCNonceNotFound
	}

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		delete(ns.nonces, nonce)
		return ErrOIDCNonceExpired
	}

	// Delete the nonce (single-use)
	delete(ns.nonces, nonce)

	return nil
}

// cleanupLoop periodically removes expired nonces.
func (ns *nonceStore) cleanupLoop() {
	for {
		select {
		case <-ns.cleanup.C:
			ns.cleanupExpired()
		case <-ns.done:
			return
		}
	}
}

// cleanupExpired removes all expired nonces from the store.
func (ns *nonceStore) cleanupExpired() {
	now := time.Now()

	ns.mu.Lock()
	defer ns.mu.Unlock()

	for nonce, entry := range ns.nonces {
		if now.After(entry.expiresAt) {
			delete(ns.nonces, nonce)
		}
	}
}

// Close stops the cleanup goroutine and releases resources.
func (ns *nonceStore) Close() {
	if ns.cleanup != nil {
		ns.cleanup.Stop()
	}
	close(ns.done)

	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.nonces = nil
}

// Count returns the current number of stored nonces (for testing).
func (ns *nonceStore) Count() int {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return len(ns.nonces)
}
