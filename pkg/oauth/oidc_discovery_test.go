package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewDiscoveryClient(t *testing.T) {
	httpClient := &http.Client{}
	config := &OIDCConfig{
		Enabled: true,
	}

	dc := newDiscoveryClient(httpClient, config)

	if dc == nil {
		t.Fatal("newDiscoveryClient() returned nil")
	}

	if dc.httpClient != httpClient {
		t.Error("newDiscoveryClient() httpClient not set correctly")
	}

	if dc.config != config {
		t.Error("newDiscoveryClient() config not set correctly")
	}
}

func TestDiscoveryClient_GetDiscovery(t *testing.T) {
	validDoc := &OIDCDiscoveryConfig{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/authorize",
		TokenEndpoint:         "https://example.com/token",
		JWKSUri:               "https://example.com/jwks",
		ResponseTypesSupported: []string{"code"},
		SubjectTypesSupported:  []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	t.Run("fetches and caches discovery document", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				t.Errorf("Unexpected path: %s", r.URL.Path)
			}
			if r.Method != http.MethodGet {
				t.Errorf("Unexpected method: %s", r.Method)
			}
			if r.Header.Get("Accept") != "application/json" {
				t.Errorf("Unexpected Accept header: %s", r.Header.Get("Accept"))
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(validDoc)
		}))
		defer server.Close()

		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{})
		doc, err := dc.getDiscovery(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("getDiscovery() error = %v", err)
		}

		if doc.Issuer != validDoc.Issuer {
			t.Errorf("getDiscovery() issuer = %s, want %s", doc.Issuer, validDoc.Issuer)
		}

		// Check cache
		cached := dc.GetCachedDiscovery()
		if cached == nil {
			t.Error("getDiscovery() did not cache document")
		}
	})

	t.Run("uses cached discovery", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(validDoc)
		}))
		defer server.Close()

		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{
			DiscoveryCacheTTL: 1 * time.Hour,
		})

		// First call
		_, err := dc.getDiscovery(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("getDiscovery() error = %v", err)
		}

		// Second call should use cache
		_, err = dc.getDiscovery(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("getDiscovery() error = %v", err)
		}

		if callCount != 1 {
			t.Errorf("getDiscovery() made %d HTTP calls, want 1 (second should use cache)", callCount)
		}
	})

	t.Run("refreshes expired cache", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(validDoc)
		}))
		defer server.Close()

		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{
			DiscoveryCacheTTL: 50 * time.Millisecond,
		})

		// First call
		_, err := dc.getDiscovery(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("getDiscovery() error = %v", err)
		}

		// Wait for cache to expire
		time.Sleep(100 * time.Millisecond)

		// Second call should fetch again
		_, err = dc.getDiscovery(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("getDiscovery() error = %v", err)
		}

		if callCount != 2 {
			t.Errorf("getDiscovery() made %d HTTP calls, want 2 (cache expired)", callCount)
		}
	})

	t.Run("returns cached document on fetch error", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			if callCount == 1 {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(validDoc)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{
			DiscoveryCacheTTL: 50 * time.Millisecond,
		})

		// First call succeeds
		_, err := dc.getDiscovery(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("getDiscovery() error = %v", err)
		}

		// Wait for cache to expire
		time.Sleep(100 * time.Millisecond)

		// Second call fails but returns cached
		doc, err := dc.getDiscovery(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("getDiscovery() error = %v, should return cached", err)
		}
		if doc.Issuer != validDoc.Issuer {
			t.Error("getDiscovery() did not return cached document on error")
		}
	})

	t.Run("handles discovery disabled with manual config", func(t *testing.T) {
		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{
			SkipDiscovery: true,
			Discovery:     validDoc,
		})

		doc, err := dc.getDiscovery(context.Background(), "https://example.com")
		if err != nil {
			t.Fatalf("getDiscovery() error = %v", err)
		}

		if doc != validDoc {
			t.Error("getDiscovery() did not return manual config")
		}
	})

	t.Run("errors when discovery disabled without config", func(t *testing.T) {
		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{
			SkipDiscovery: true,
		})

		_, err := dc.getDiscovery(context.Background(), "https://example.com")
		if err == nil {
			t.Error("getDiscovery() should error when discovery disabled without config")
		}
	})

	t.Run("handles HTTP errors", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
		}))
		defer server.Close()

		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{})
		_, err := dc.getDiscovery(context.Background(), server.URL)
		if err == nil {
			t.Error("getDiscovery() should error on HTTP error")
		}
	})

	t.Run("handles invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{})
		_, err := dc.getDiscovery(context.Background(), server.URL)
		if err == nil {
			t.Error("getDiscovery() should error on invalid JSON")
		}
	})

	t.Run("validates discovery document", func(t *testing.T) {
		invalidDoc := &OIDCDiscoveryConfig{
			Issuer: "https://example.com",
			// Missing required fields
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(invalidDoc)
		}))
		defer server.Close()

		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{})
		_, err := dc.getDiscovery(context.Background(), server.URL)
		if err == nil {
			t.Error("getDiscovery() should error on invalid document")
		}
	})

	t.Run("handles context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(validDoc)
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{})
		_, err := dc.getDiscovery(ctx, server.URL)
		if err == nil {
			t.Error("getDiscovery() should error on cancelled context")
		}
	})

	t.Run("uses custom discovery URL", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/custom-discovery" {
				t.Errorf("Unexpected path: %s, want /custom-discovery", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(validDoc)
		}))
		defer server.Close()

		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{
			DiscoveryURL: server.URL + "/custom-discovery",
		})

		_, err := dc.getDiscovery(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("getDiscovery() error = %v", err)
		}
	})
}

func TestBuildDiscoveryURL(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		want   string
	}{
		{
			name:   "standard issuer",
			issuer: "https://example.com",
			want:   "https://example.com/.well-known/openid-configuration",
		},
		{
			name:   "issuer with trailing slash",
			issuer: "https://example.com/",
			want:   "https://example.com/.well-known/openid-configuration",
		},
		{
			name:   "issuer with path",
			issuer: "https://example.com/oauth",
			want:   "https://example.com/oauth/.well-known/openid-configuration",
		},
		{
			name:   "issuer with whitespace",
			issuer: "  https://example.com  ",
			want:   "https://example.com/.well-known/openid-configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildDiscoveryURL(tt.issuer)
			if got != tt.want {
				t.Errorf("buildDiscoveryURL() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDiscoveryClient_RefreshDiscovery(t *testing.T) {
	validDoc := &OIDCDiscoveryConfig{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/authorize",
		TokenEndpoint:         "https://example.com/token",
		JWKSUri:               "https://example.com/jwks",
		ResponseTypesSupported: []string{"code"},
		SubjectTypesSupported:  []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	t.Run("refreshes cached discovery", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(validDoc)
		}))
		defer server.Close()

		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{})

		// Initial fetch
		_, err := dc.getDiscovery(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("getDiscovery() error = %v", err)
		}

		// Force refresh
		err = dc.RefreshDiscovery(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("RefreshDiscovery() error = %v", err)
		}

		if callCount != 2 {
			t.Errorf("RefreshDiscovery() made %d HTTP calls, want 2", callCount)
		}
	})

	t.Run("validates refreshed document", func(t *testing.T) {
		invalidDoc := &OIDCDiscoveryConfig{
			Issuer: "https://example.com",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(invalidDoc)
		}))
		defer server.Close()

		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{})

		err := dc.RefreshDiscovery(context.Background(), server.URL)
		if err == nil {
			t.Error("RefreshDiscovery() should error on invalid document")
		}
	})
}

func TestDiscoveryClient_SetDiscovery(t *testing.T) {
	validDoc := &OIDCDiscoveryConfig{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/authorize",
		TokenEndpoint:         "https://example.com/token",
		JWKSUri:               "https://example.com/jwks",
		ResponseTypesSupported: []string{"code"},
		SubjectTypesSupported:  []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	t.Run("sets valid discovery document", func(t *testing.T) {
		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{})

		err := dc.SetDiscovery(validDoc)
		if err != nil {
			t.Fatalf("SetDiscovery() error = %v", err)
		}

		cached := dc.GetCachedDiscovery()
		if cached != validDoc {
			t.Error("SetDiscovery() did not set document correctly")
		}
	})

	t.Run("rejects invalid discovery document", func(t *testing.T) {
		invalidDoc := &OIDCDiscoveryConfig{
			Issuer: "https://example.com",
		}

		dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{})

		err := dc.SetDiscovery(invalidDoc)
		if err == nil {
			t.Error("SetDiscovery() should error on invalid document")
		}
	})
}

func TestDiscoveryClient_GetCachedDiscovery(t *testing.T) {
	dc := newDiscoveryClient(http.DefaultClient, &OIDCConfig{})

	t.Run("returns nil when no cache", func(t *testing.T) {
		cached := dc.GetCachedDiscovery()
		if cached != nil {
			t.Error("GetCachedDiscovery() should return nil when no cache")
		}
	})

	t.Run("returns cached document", func(t *testing.T) {
		validDoc := &OIDCDiscoveryConfig{
			Issuer:                "https://example.com",
			AuthorizationEndpoint: "https://example.com/authorize",
			TokenEndpoint:         "https://example.com/token",
			JWKSUri:               "https://example.com/jwks",
			ResponseTypesSupported: []string{"code"},
			SubjectTypesSupported:  []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
		}

		dc.SetDiscovery(validDoc)

		cached := dc.GetCachedDiscovery()
		if cached != validDoc {
			t.Error("GetCachedDiscovery() did not return cached document")
		}
	})
}
