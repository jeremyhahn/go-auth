package oauth

import (
	"sync"
	"testing"
	"time"
)

func TestNewNonceStore(t *testing.T) {
	tests := []struct {
		name    string
		ttl     time.Duration
		wantTTL time.Duration
	}{
		{
			name:    "valid ttl",
			ttl:     5 * time.Minute,
			wantTTL: 5 * time.Minute,
		},
		{
			name:    "zero ttl uses default",
			ttl:     0,
			wantTTL: 10 * time.Minute,
		},
		{
			name:    "negative ttl uses default",
			ttl:     -1 * time.Minute,
			wantTTL: 10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := newNonceStore(tt.ttl)
			defer ns.Close()

			if ns == nil {
				t.Fatal("newNonceStore() returned nil")
			}

			if ns.ttl != tt.wantTTL {
				t.Errorf("newNonceStore() ttl = %v, want %v", ns.ttl, tt.wantTTL)
			}

			if ns.nonces == nil {
				t.Error("newNonceStore() nonces map is nil")
			}

			if ns.cleanup == nil {
				t.Error("newNonceStore() cleanup ticker is nil")
			}

			if ns.done == nil {
				t.Error("newNonceStore() done channel is nil")
			}
		})
	}
}

func TestNonceStore_Generate(t *testing.T) {
	ns := newNonceStore(5 * time.Minute)
	defer ns.Close()

	t.Run("generates valid nonce", func(t *testing.T) {
		nonce, err := ns.Generate()
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}

		if nonce == "" {
			t.Error("Generate() returned empty nonce")
		}

		// Check nonce is stored
		if ns.Count() != 1 {
			t.Errorf("Generate() count = %d, want 1", ns.Count())
		}
	})

	t.Run("generates unique nonces", func(t *testing.T) {
		nonce1, err1 := ns.Generate()
		nonce2, err2 := ns.Generate()

		if err1 != nil || err2 != nil {
			t.Fatalf("Generate() errors = %v, %v", err1, err2)
		}

		if nonce1 == nonce2 {
			t.Error("Generate() produced duplicate nonces")
		}

		if ns.Count() != 3 { // Including the one from previous test
			t.Errorf("Generate() count = %d, want 3", ns.Count())
		}
	})

	t.Run("concurrent generation", func(t *testing.T) {
		const goroutines = 100
		var wg sync.WaitGroup
		nonces := make(map[string]bool)
		var mu sync.Mutex

		wg.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				nonce, err := ns.Generate()
				if err != nil {
					t.Errorf("Generate() error = %v", err)
					return
				}

				mu.Lock()
				if nonces[nonce] {
					t.Errorf("Duplicate nonce generated: %s", nonce)
				}
				nonces[nonce] = true
				mu.Unlock()
			}()
		}

		wg.Wait()

		if len(nonces) != goroutines {
			t.Errorf("Generated %d unique nonces, want %d", len(nonces), goroutines)
		}
	})
}

func TestNonceStore_Validate(t *testing.T) {
	ns := newNonceStore(5 * time.Minute)
	defer ns.Close()

	t.Run("validates existing nonce", func(t *testing.T) {
		nonce, err := ns.Generate()
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}

		err = ns.Validate(nonce)
		if err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}

		// Nonce should be removed after validation
		err = ns.Validate(nonce)
		if err != ErrOIDCNonceNotFound {
			t.Errorf("Second Validate() error = %v, want %v", err, ErrOIDCNonceNotFound)
		}
	})

	t.Run("rejects empty nonce", func(t *testing.T) {
		err := ns.Validate("")
		if err != ErrOIDCInvalidNonce {
			t.Errorf("Validate(\"\") error = %v, want %v", err, ErrOIDCInvalidNonce)
		}
	})

	t.Run("rejects non-existent nonce", func(t *testing.T) {
		err := ns.Validate("nonexistent")
		if err != ErrOIDCNonceNotFound {
			t.Errorf("Validate(\"nonexistent\") error = %v, want %v", err, ErrOIDCNonceNotFound)
		}
	})

	t.Run("rejects expired nonce", func(t *testing.T) {
		// Create a separate nonce store with very short TTL and no cleanup
		// to avoid race condition with cleanup goroutine
		ns2 := &nonceStore{
			nonces: make(map[string]*nonceEntry),
			ttl:    50 * time.Millisecond,
		}

		// Manually add expired nonce
		expiredNonce := "expired-nonce-test"
		ns2.nonces[expiredNonce] = &nonceEntry{
			value:     expiredNonce,
			expiresAt: time.Now().Add(-1 * time.Second),
		}

		err := ns2.Validate(expiredNonce)
		if err != ErrOIDCNonceExpired {
			t.Errorf("Validate(expired) error = %v, want %v", err, ErrOIDCNonceExpired)
		}

		// Expired nonce should be removed
		if len(ns2.nonces) != 0 {
			t.Errorf("Validate(expired) should remove nonce, count = %d", len(ns2.nonces))
		}
	})

	t.Run("rejects already used nonce", func(t *testing.T) {
		nonce, err := ns.Generate()
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}

		// First validation succeeds
		err = ns.Validate(nonce)
		if err != nil {
			t.Errorf("First Validate() error = %v, want nil", err)
		}

		// Second validation fails
		err = ns.Validate(nonce)
		if err != ErrOIDCNonceNotFound {
			t.Errorf("Second Validate() error = %v, want %v", err, ErrOIDCNonceNotFound)
		}
	})
}

func TestNonceStore_CleanupExpired(t *testing.T) {
	ns := newNonceStore(50 * time.Millisecond)
	defer ns.Close()

	// Generate multiple nonces
	for i := 0; i < 10; i++ {
		_, err := ns.Generate()
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
	}

	if ns.Count() != 10 {
		t.Fatalf("Count() = %d, want 10", ns.Count())
	}

	// Wait for expiration + cleanup cycle
	time.Sleep(150 * time.Millisecond)

	// Trigger cleanup manually
	ns.cleanupExpired()

	if ns.Count() != 0 {
		t.Errorf("cleanupExpired() count = %d, want 0", ns.Count())
	}
}

func TestNonceStore_CleanupLoop(t *testing.T) {
	ns := newNonceStore(50 * time.Millisecond)

	// Generate nonces
	for i := 0; i < 5; i++ {
		_, err := ns.Generate()
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
	}

	if ns.Count() != 5 {
		t.Fatalf("Count() = %d, want 5", ns.Count())
	}

	// Wait for automatic cleanup
	time.Sleep(150 * time.Millisecond)

	// Close to stop cleanup goroutine
	ns.Close()

	// Nonces should have been cleaned up automatically
	if ns.Count() != 0 {
		t.Errorf("After cleanup loop, count = %d, want 0", ns.Count())
	}
}

func TestNonceStore_Close(t *testing.T) {
	ns := newNonceStore(5 * time.Minute)

	// Generate some nonces
	for i := 0; i < 5; i++ {
		_, err := ns.Generate()
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
	}

	ns.Close()

	// Verify cleanup ticker is stopped and channel is closed
	// Attempting to send to done channel should panic if closed
	defer func() {
		if r := recover(); r == nil {
			t.Error("Close() did not close done channel")
		}
	}()

	ns.done <- struct{}{}
}

func TestNonceStore_Count(t *testing.T) {
	ns := newNonceStore(5 * time.Minute)
	defer ns.Close()

	tests := []struct {
		name      string
		generate  int
		wantCount int
	}{
		{
			name:      "empty store",
			generate:  0,
			wantCount: 0,
		},
		{
			name:      "one nonce",
			generate:  1,
			wantCount: 1,
		},
		{
			name:      "multiple nonces",
			generate:  10,
			wantCount: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset store
			ns.mu.Lock()
			ns.nonces = make(map[string]*nonceEntry)
			ns.mu.Unlock()

			// Generate nonces
			for i := 0; i < tt.generate; i++ {
				_, err := ns.Generate()
				if err != nil {
					t.Fatalf("Generate() error = %v", err)
				}
			}

			if got := ns.Count(); got != tt.wantCount {
				t.Errorf("Count() = %d, want %d", got, tt.wantCount)
			}
		})
	}
}

func TestNonceStore_ConcurrentAccess(t *testing.T) {
	ns := newNonceStore(5 * time.Minute)
	defer ns.Close()

	const goroutines = 50
	var wg sync.WaitGroup

	// Mix of generate, validate, and count operations
	wg.Add(goroutines * 3)

	// Generators
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, err := ns.Generate()
			if err != nil {
				t.Errorf("Generate() error = %v", err)
			}
		}()
	}

	// Validators (will mostly fail, that's ok)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = ns.Validate("test-nonce")
		}()
	}

	// Counters
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = ns.Count()
		}()
	}

	wg.Wait()

	// Should not panic and should have some nonces
	count := ns.Count()
	if count < 0 || count > goroutines {
		t.Errorf("Count() = %d, expected between 0 and %d", count, goroutines)
	}
}

func TestNonceStore_NonceFormat(t *testing.T) {
	ns := newNonceStore(5 * time.Minute)
	defer ns.Close()

	nonce, err := ns.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Nonce should be base64url encoded (43 chars for 32 bytes)
	if len(nonce) != 43 {
		t.Errorf("Generate() nonce length = %d, want 43", len(nonce))
	}

	// Should only contain valid base64url characters
	validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, c := range nonce {
		valid := false
		for _, vc := range validChars {
			if c == vc {
				valid = true
				break
			}
		}
		if !valid {
			t.Errorf("Generate() nonce contains invalid character: %c", c)
		}
	}
}

func TestNonceStore_Expiration(t *testing.T) {
	ttl := 100 * time.Millisecond
	ns := newNonceStore(ttl)
	defer ns.Close()

	nonce, err := ns.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Should be valid immediately
	err = ns.Validate(nonce)
	if err != nil {
		t.Errorf("Validate() immediate error = %v, want nil", err)
	}

	// Generate another nonce and let it expire
	nonce2, err := ns.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Wait for expiration
	time.Sleep(ttl + 50*time.Millisecond)

	// Should be expired or cleaned up (both are valid)
	err = ns.Validate(nonce2)
	if err != ErrOIDCNonceExpired && err != ErrOIDCNonceNotFound {
		t.Errorf("Validate() after expiration error = %v, want %v or %v", err, ErrOIDCNonceExpired, ErrOIDCNonceNotFound)
	}
}
