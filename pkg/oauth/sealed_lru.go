package oauth

import (
	"container/list"
	"errors"
	"sync"
	"time"

	"github.com/jeremyhahn/go-enclave"
)

// defaultCacheMaxSize bounds a sealedLRU constructed without a positive size.
const defaultCacheMaxSize = 1000

// lruEntry is one cached value, held JSON-encoded in an enclave owned by
// the entry: whatever removes the entry from the cache destroys it.
type lruEntry struct {
	sealed    *enclave.MemoryEnclave
	expiresAt time.Time
	key       string
}

// sealedLRU is the bounded, TTL-expiring LRU store behind both caches in this
// package — validated claims and UserInfo responses. Every value lives
// JSON-encoded in a go-enclave enclave, and every way an entry leaves the cache
// destroys it: expiry (on read, on insert, or by sweep), overwrite, capacity or
// budget eviction, Delete, Clear and Close.
//
// The cache is bounded twice. maxSize caps the entry count. The locked-memory
// allowance caps it again, since each entry occupies at least a page.
// Every step that frees locked memory runs BEFORE a new entry is allocated,
// because the allocation is the step a full budget refuses — see set.
//
// It is safe for concurrent use. Every method takes the one mutex for its
// whole duration (a read moves the entry to the front, so even reads write).
type sealedLRU struct {
	mu      sync.Mutex
	maxSize int
	items   map[string]*list.Element
	lruList *list.List
	closed  bool
	alloc   allocFunc
	now     func() time.Time
	// destroyErr is the first failed Destroy of an entry that left the cache.
	// Eviction and expiry have no caller to report to, so close returns it.
	destroyErr error
}

// newSealedLRU returns a cache bounded to maxSize entries (defaultCacheMaxSize
// when not positive) that seals values with alloc and reads time from now.
func newSealedLRU(maxSize int, alloc allocFunc, now func() time.Time) *sealedLRU {
	if maxSize <= 0 {
		maxSize = defaultCacheMaxSize
	}
	return &sealedLRU{
		maxSize: maxSize,
		items:   make(map[string]*list.Element),
		lruList: list.New(),
		alloc:   alloc,
		now:     now,
	}
}

// get decodes the live value cached under key into into and marks it most
// recently used. It reports false on a miss. An entry found expired, or one
// that can no longer be opened, is destroyed rather than left holding locked
// memory until the next insert.
func (c *sealedLRU) get(key string, into any) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		return false
	}

	entry := elem.Value.(*lruEntry)
	if c.now().After(entry.expiresAt) {
		c.removeElement(elem)
		return false
	}

	if err := openJSON(entry.sealed, into); err != nil {
		c.removeElement(elem)
		return false
	}

	c.lruList.MoveToFront(elem)
	return true
}

// set seals value into an enclave and caches it under key for ttl.
//
// Everything happens under the lock, and every step that frees locked memory
// runs BEFORE the new entry is allocated — the allocation is what a full budget
// refuses, so anything freed after it is freed too late:
//
//  1. the closed check, so a request in flight across Close cannot insert
//     after it, and allocates nothing (ErrCacheClosed);
//  2. reclamation of expired entries, and of the entry being replaced;
//  3. the capacity eviction: at maxSize the LRU entry is evicted first;
//  4. the allocation — and if the budget or the kernel still refuses it while
//     the cache holds entries, one more LRU eviction and one retry. A second
//     refusal is returned: the value is not cached, and nothing falls back to
//     ordinary memory.
func (c *sealedLRU) set(key string, value any, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrCacheClosed
	}

	c.removeExpiredLocked()

	if elem, ok := c.items[key]; ok {
		c.removeElement(elem)
	}

	if c.lruList.Len() >= c.maxSize {
		c.removeElement(c.lruList.Back())
	}

	sealed, err := sealJSON(c.alloc, value)
	if err != nil && lockedMemoryRefused(err) && c.lruList.Len() > 0 {
		c.removeElement(c.lruList.Back())
		sealed, err = sealJSON(c.alloc, value)
	}
	if err != nil {
		return err
	}

	c.items[key] = c.lruList.PushFront(&lruEntry{
		sealed:    sealed,
		expiresAt: c.now().Add(ttl),
		key:       key,
	})
	return nil
}

// remove destroys the entry cached under key, if any.
func (c *sealedLRU) remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.removeElement(elem)
	}
}

// clear destroys every entry. The cache stays usable.
func (c *sealedLRU) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.clearLocked()
}

// close destroys every entry and closes the cache for good: every later set
// fails with ErrCacheClosed. It is idempotent. The error is the first failed
// Destroy of any entry the cache has dropped, now or earlier.
func (c *sealedLRU) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	c.clearLocked()
	return c.destroyErr
}

// removeExpired destroys every expired entry.
func (c *sealedLRU) removeExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.removeExpiredLocked()
}

// len reports the number of entries held, expired or not.
func (c *sealedLRU) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.lruList.Len()
}

// clearLocked destroys every entry (must be called with lock held).
func (c *sealedLRU) clearLocked() {
	for elem := c.lruList.Front(); elem != nil; elem = elem.Next() {
		c.noteDestroy(elem.Value.(*lruEntry).sealed)
	}
	c.items = make(map[string]*list.Element)
	c.lruList.Init()
}

// removeExpiredLocked destroys every expired entry (must be called with lock
// held).
func (c *sealedLRU) removeExpiredLocked() {
	now := c.now()
	var expired []*list.Element
	for elem := c.lruList.Front(); elem != nil; elem = elem.Next() {
		if now.After(elem.Value.(*lruEntry).expiresAt) {
			expired = append(expired, elem)
		}
	}
	for _, elem := range expired {
		c.removeElement(elem)
	}
}

// removeElement removes an entry and destroys its enclave (must be called with
// lock held).
func (c *sealedLRU) removeElement(elem *list.Element) {
	entry := elem.Value.(*lruEntry)
	c.noteDestroy(entry.sealed)
	delete(c.items, entry.key)
	c.lruList.Remove(elem)
}

// noteDestroy destroys an entry's enclave and keeps the first failure for
// close to report (must be called with lock held).
func (c *sealedLRU) noteDestroy(sealed *enclave.MemoryEnclave) {
	if err := sealed.Destroy(); err != nil && c.destroyErr == nil {
		c.destroyErr = err
	}
}

// lockedMemoryRefused reports whether an allocation failed for want of locked
// memory — an allocator budget or the kernel's limit — which evicting an entry
// can relieve.
func lockedMemoryRefused(err error) bool {
	return errors.Is(err, enclave.ErrBudgetExhausted) || errors.Is(err, enclave.ErrLockedMemoryUnavailable)
}
