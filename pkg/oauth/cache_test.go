package oauth

import (
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"
)

// sealedEntry returns the enclave the cache holds for key, or nil.
func sealedEntry(c *lruCache, key string) *enclave.MemoryEnclave {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		return nil
	}
	return elem.Value.(*lruEntry).sealed
}

// mustSet stores claims and fails the test if sealing them failed.
func mustSet(t *testing.T, c TokenCache, key string, claims *TokenClaims, ttl time.Duration) {
	t.Helper()
	if err := c.Set(key, claims, ttl); err != nil {
		t.Fatalf("Set(%q) failed: %v", key, err)
	}
}

func TestLRUCache_SetGet(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	claims := &TokenClaims{
		Subject: "user123",
		Email:   "user@example.com",
		Custom:  map[string]interface{}{"tenant": "t1"},
	}

	mustSet(t, cache, "key1", claims, 1*time.Minute)

	retrieved := cache.Get("key1")
	if retrieved == nil {
		t.Fatal("Expected to retrieve cached claims")
	}
	if retrieved.Subject != "user123" || retrieved.Email != "user@example.com" || retrieved.Custom["tenant"] != "t1" {
		t.Errorf("retrieved %+v, want the stored claims", retrieved)
	}

	// The cache holds sealed material, not the caller's struct: what comes back
	// is a fresh copy, so mutating it cannot reach the cache.
	if retrieved == claims {
		t.Error("Get returned the caller's pointer; the cache must hold sealed material")
	}
	retrieved.Subject = "mutated"
	if again := cache.Get("key1"); again == nil || again.Subject != "user123" {
		t.Errorf("mutating a Get result changed the cache: %+v", again)
	}
}

func TestLRUCache_StoresClaimsInAnEnclave(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	mustSet(t, cache, "key1", &TokenClaims{Subject: "user123"}, time.Minute)

	sealed := sealedEntry(cache, "key1")
	if !sealed.IsAlive() {
		t.Fatal("cache entry is not held in a live enclave")
	}
}

func TestLRUCache_GetNonExistent(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	if retrieved := cache.Get("nonexistent"); retrieved != nil {
		t.Error("Expected nil for non-existent key")
	}
}

func TestLRUCache_ExpiryOnGetDestroysTheEnclave(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	// A negative TTL is already expired: no clock has to move.
	mustSet(t, cache, "key1", &TokenClaims{Subject: "user123"}, -time.Second)
	sealed := sealedEntry(cache, "key1")

	if retrieved := cache.Get("key1"); retrieved != nil {
		t.Error("Expected nil for expired key")
	}
	if sealed.IsAlive() {
		t.Error("expired entry's enclave is still alive after Get removed it")
	}
}

func TestLRUCache_ExpirySweepDestroysTheEnclave(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	mustSet(t, cache, "stale", &TokenClaims{Subject: "old"}, -time.Second)
	mustSet(t, cache, "fresh", &TokenClaims{Subject: "new"}, time.Minute)
	stale := sealedEntry(cache, "stale")
	fresh := sealedEntry(cache, "fresh")

	cache.removeExpiredEntries()

	if stale.IsAlive() {
		t.Error("swept entry's enclave is still alive")
	}
	if !fresh.IsAlive() {
		t.Error("sweep destroyed an unexpired entry")
	}
}

func TestLRUCache_EvictionDestroysTheEnclave(t *testing.T) {
	cache := newLRUCache(3)
	defer cache.Close()

	for i := 0; i < 3; i++ {
		mustSet(t, cache, strconv.Itoa(i), &TokenClaims{Subject: strconv.Itoa(i)}, time.Minute)
	}
	oldest := sealedEntry(cache, "0")

	mustSet(t, cache, "3", &TokenClaims{Subject: "3"}, time.Minute)

	if cache.Get("0") != nil {
		t.Error("Expected oldest entry to be evicted")
	}
	if oldest.IsAlive() {
		t.Error("evicted entry's enclave is still alive")
	}
	for _, key := range []string{"1", "2", "3"} {
		if cache.Get(key) == nil {
			t.Errorf("Expected entry %s to still exist", key)
		}
	}
}

func TestLRUCache_OverwriteDestroysTheOldEnclave(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	mustSet(t, cache, "key1", &TokenClaims{Subject: "user123"}, time.Minute)
	first := sealedEntry(cache, "key1")

	mustSet(t, cache, "key1", &TokenClaims{Subject: "user456"}, time.Minute)

	if first.IsAlive() {
		t.Error("overwritten entry's enclave is still alive")
	}
	retrieved := cache.Get("key1")
	if retrieved == nil || retrieved.Subject != "user456" {
		t.Errorf("Expected updated subject 'user456', got %+v", retrieved)
	}
}

func TestLRUCache_DeleteDestroysTheEnclave(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	mustSet(t, cache, "key1", &TokenClaims{Subject: "user123"}, time.Minute)
	sealed := sealedEntry(cache, "key1")

	cache.Delete("key1")

	if cache.Get("key1") != nil {
		t.Error("Expected key to be deleted")
	}
	if sealed.IsAlive() {
		t.Error("deleted entry's enclave is still alive")
	}
}

func TestLRUCache_ClearDestroysEveryEnclave(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	var sealed []*enclave.MemoryEnclave
	for i := 0; i < 5; i++ {
		key := strconv.Itoa(i)
		mustSet(t, cache, key, &TokenClaims{Subject: key}, time.Minute)
		sealed = append(sealed, sealedEntry(cache, key))
	}

	cache.Clear()

	for i, e := range sealed {
		if cache.Get(strconv.Itoa(i)) != nil {
			t.Errorf("Expected key %d to be cleared", i)
		}
		if e.IsAlive() {
			t.Errorf("cleared entry %d's enclave is still alive", i)
		}
	}
}

func TestLRUCache_CloseDestroysEveryEnclave(t *testing.T) {
	cache := newLRUCache(10)

	var sealed []*enclave.MemoryEnclave
	for i := 0; i < 3; i++ {
		key := strconv.Itoa(i)
		mustSet(t, cache, key, &TokenClaims{Subject: key}, time.Minute)
		sealed = append(sealed, sealedEntry(cache, key))
	}

	cache.Close()
	cache.Close() // idempotent

	for i, e := range sealed {
		if e.IsAlive() {
			t.Errorf("entry %d's enclave is still alive after Close", i)
		}
	}

	// A closed cache keeps nothing: storing after Close must not leave live
	// material behind that no one will ever destroy.
	if err := cache.Set("late", &TokenClaims{Subject: "late"}, time.Minute); !errors.Is(err, ErrCacheClosed) {
		t.Errorf("Set() after Close = %v, want ErrCacheClosed", err)
	}
	if cache.Get("late") != nil || sealedEntry(cache, "late") != nil {
		t.Error("a closed cache stored an entry")
	}
}

func TestNoopCache(t *testing.T) {
	cache := &noopCache{}

	mustSet(t, cache, "key1", &TokenClaims{Subject: "user123"}, 1*time.Minute)

	if retrieved := cache.Get("key1"); retrieved != nil {
		t.Error("Expected noop cache to always return nil")
	}

	cache.Delete("key1")
	cache.Clear()
}

func TestLRUCache_NilClaimsAreIgnored(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	mustSet(t, cache, "key1", nil, time.Minute)
	if cache.Get("key1") != nil {
		t.Error("nil claims were cached")
	}
}

func TestLRUCache_ConcurrentAccess(t *testing.T) {
	cache := newLRUCache(5)
	defer cache.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(id int) {
			defer wg.Done()
			key := strconv.Itoa(id % 7)
			if err := cache.Set(key, &TokenClaims{Subject: key}, time.Minute); err != nil {
				t.Errorf("Set failed: %v", err)
			}
		}(i)
		go func(id int) {
			defer wg.Done()
			cache.Get(strconv.Itoa(id % 7))
		}(i)
	}
	wg.Wait()
}
