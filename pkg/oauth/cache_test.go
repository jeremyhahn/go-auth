package oauth

import (
	"testing"
	"time"
)

func TestLRUCache_SetGet(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	claims := &TokenClaims{
		Subject: "user123",
		Email:   "user@example.com",
	}

	// Set and get
	cache.Set("key1", claims, 1*time.Minute)

	retrieved := cache.Get("key1")
	if retrieved == nil {
		t.Fatal("Expected to retrieve cached claims")
	}

	if retrieved.Subject != "user123" {
		t.Errorf("Expected subject 'user123', got %s", retrieved.Subject)
	}
}

func TestLRUCache_GetNonExistent(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	retrieved := cache.Get("nonexistent")
	if retrieved != nil {
		t.Error("Expected nil for non-existent key")
	}
}

func TestLRUCache_Expiration(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	claims := &TokenClaims{
		Subject: "user123",
	}

	// Set with very short TTL
	cache.Set("key1", claims, 1*time.Millisecond)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	retrieved := cache.Get("key1")
	if retrieved != nil {
		t.Error("Expected nil for expired key")
	}
}

func TestLRUCache_LRUEviction(t *testing.T) {
	cache := newLRUCache(3)
	defer cache.Close()

	// Fill cache to capacity
	for i := 0; i < 3; i++ {
		claims := &TokenClaims{Subject: string(rune('A' + i))}
		cache.Set(string(rune('0'+i)), claims, 1*time.Minute)
	}

	// Add one more, should evict oldest
	claims := &TokenClaims{Subject: "D"}
	cache.Set("3", claims, 1*time.Minute)

	// First key should be evicted
	if retrieved := cache.Get("0"); retrieved != nil {
		t.Error("Expected oldest entry to be evicted")
	}

	// Newer entries should exist
	if retrieved := cache.Get("1"); retrieved == nil {
		t.Error("Expected entry to still exist")
	}
}

func TestLRUCache_Delete(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	claims := &TokenClaims{Subject: "user123"}
	cache.Set("key1", claims, 1*time.Minute)

	// Verify it exists
	if retrieved := cache.Get("key1"); retrieved == nil {
		t.Fatal("Expected key to exist before deletion")
	}

	// Delete
	cache.Delete("key1")

	// Verify it's gone
	if retrieved := cache.Get("key1"); retrieved != nil {
		t.Error("Expected key to be deleted")
	}
}

func TestLRUCache_Clear(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	// Add multiple entries
	for i := 0; i < 5; i++ {
		claims := &TokenClaims{Subject: string(rune('A' + i))}
		cache.Set(string(rune('0'+i)), claims, 1*time.Minute)
	}

	// Clear all
	cache.Clear()

	// Verify all are gone
	for i := 0; i < 5; i++ {
		if retrieved := cache.Get(string(rune('0' + i))); retrieved != nil {
			t.Errorf("Expected key %d to be cleared", i)
		}
	}
}

func TestLRUCache_Update(t *testing.T) {
	cache := newLRUCache(10)
	defer cache.Close()

	claims1 := &TokenClaims{Subject: "user123"}
	cache.Set("key1", claims1, 1*time.Minute)

	// Update with new claims
	claims2 := &TokenClaims{Subject: "user456"}
	cache.Set("key1", claims2, 1*time.Minute)

	retrieved := cache.Get("key1")
	if retrieved == nil {
		t.Fatal("Expected to retrieve updated claims")
	}

	if retrieved.Subject != "user456" {
		t.Errorf("Expected updated subject 'user456', got %s", retrieved.Subject)
	}
}

func TestNoopCache(t *testing.T) {
	cache := &noopCache{}

	claims := &TokenClaims{Subject: "user123"}

	// Set should do nothing
	cache.Set("key1", claims, 1*time.Minute)

	// Get should always return nil
	if retrieved := cache.Get("key1"); retrieved != nil {
		t.Error("Expected noop cache to always return nil")
	}

	// Delete and Clear should not panic
	cache.Delete("key1")
	cache.Clear()
}

func TestLRUCache_ConcurrentAccess(t *testing.T) {
	cache := newLRUCache(100)
	defer cache.Close()

	done := make(chan bool)

	// Concurrent writers
	for i := 0; i < 10; i++ {
		go func(id int) {
			claims := &TokenClaims{Subject: string(rune('A' + id))}
			cache.Set(string(rune('0'+id)), claims, 1*time.Minute)
			done <- true
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 10; i++ {
		go func(id int) {
			cache.Get(string(rune('0' + id)))
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}
