package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestNewUserInfoClient(t *testing.T) {
	httpClient := &http.Client{}
	config := &Config{
		OIDC: &OIDCConfig{
			Enabled: true,
			UserInfo: UserInfoConfig{
				Enabled: true,
			},
		},
	}
	discoveryClient := newDiscoveryClient(httpClient, config.OIDC)

	client := newUserInfoClient(httpClient, config, discoveryClient)

	if client == nil {
		t.Fatal("newUserInfoClient() returned nil")
	}

	if client.httpClient != httpClient {
		t.Error("newUserInfoClient() httpClient not set correctly")
	}

	if client.config != config {
		t.Error("newUserInfoClient() config not set correctly")
	}

	if client.cache == nil {
		t.Error("newUserInfoClient() cache not initialized")
	}
}

func TestUserInfoClient_GetUserInfo(t *testing.T) {
	validUserInfo := &UserInfo{
		Subject:       "user123",
		Name:          "John Doe",
		Email:         "john@example.com",
		EmailVerified: true,
	}

	t.Run("fetches and caches user info", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("Unexpected method: %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("Unexpected Authorization header: %s", r.Header.Get("Authorization"))
			}
			if r.Header.Get("Accept") != "application/json" {
				t.Errorf("Unexpected Accept header: %s", r.Header.Get("Accept"))
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(validUserInfo)
		}))
		defer server.Close()

		// Create a mock provider that returns the test server URL
		provider := &mockUserInfoProvider{
			userInfoURL: server.URL,
		}

		config := &Config{
			Provider: provider,
			OIDC: &OIDCConfig{
				Enabled: true,
				UserInfo: UserInfoConfig{
					Enabled: true,
				},
			},
		}

		client := newUserInfoClient(http.DefaultClient, config, nil)

		info, err := client.GetUserInfo(context.Background(), "test-token", "https://example.com")
		if err != nil {
			t.Fatalf("GetUserInfo() error = %v", err)
		}

		if info.Subject != "user123" {
			t.Errorf("GetUserInfo() Subject = %s, want user123", info.Subject)
		}

		// Check cache
		cached := client.getFromCache("test-token")
		if cached == nil {
			t.Error("GetUserInfo() did not cache response")
		}
	})

	t.Run("uses cached user info", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(validUserInfo)
		}))
		defer server.Close()

		provider := &mockUserInfoProvider{userInfoURL: server.URL}
		config := &Config{
			Provider: provider,
			OIDC: &OIDCConfig{
				Enabled: true,
				UserInfo: UserInfoConfig{
					Enabled:  true,
					CacheTTL: 1 * time.Hour,
				},
			},
		}

		client := newUserInfoClient(http.DefaultClient, config, nil)

		// First call
		_, err := client.GetUserInfo(context.Background(), "test-token", "https://example.com")
		if err != nil {
			t.Fatalf("GetUserInfo() error = %v", err)
		}

		// Second call should use cache
		_, err = client.GetUserInfo(context.Background(), "test-token", "https://example.com")
		if err != nil {
			t.Fatalf("GetUserInfo() error = %v", err)
		}

		if callCount != 1 {
			t.Errorf("GetUserInfo() made %d HTTP calls, want 1 (second should use cache)", callCount)
		}
	})

	t.Run("refreshes expired cache", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(validUserInfo)
		}))
		defer server.Close()

		provider := &mockUserInfoProvider{userInfoURL: server.URL}
		config := &Config{
			Provider: provider,
			OIDC: &OIDCConfig{
				Enabled: true,
				UserInfo: UserInfoConfig{
					Enabled:  true,
					CacheTTL: 50 * time.Millisecond,
				},
			},
		}

		client := newUserInfoClient(http.DefaultClient, config, nil)

		// First call
		_, err := client.GetUserInfo(context.Background(), "test-token", "https://example.com")
		if err != nil {
			t.Fatalf("GetUserInfo() error = %v", err)
		}

		// Wait for cache to expire
		time.Sleep(100 * time.Millisecond)

		// Second call should fetch again
		_, err = client.GetUserInfo(context.Background(), "test-token", "https://example.com")
		if err != nil {
			t.Fatalf("GetUserInfo() error = %v", err)
		}

		if callCount != 2 {
			t.Errorf("GetUserInfo() made %d HTTP calls, want 2 (cache expired)", callCount)
		}
	})

	t.Run("errors when UserInfo disabled", func(t *testing.T) {
		config := &Config{
			OIDC: &OIDCConfig{
				Enabled: true,
				UserInfo: UserInfoConfig{
					Enabled: false,
				},
			},
		}

		client := newUserInfoClient(http.DefaultClient, config, nil)

		_, err := client.GetUserInfo(context.Background(), "test-token", "https://example.com")
		if err != ErrOIDCNotEnabled {
			t.Errorf("GetUserInfo() error = %v, want %v", err, ErrOIDCNotEnabled)
		}
	})

	t.Run("errors on empty access token", func(t *testing.T) {
		config := &Config{
			OIDC: &OIDCConfig{
				Enabled: true,
				UserInfo: UserInfoConfig{
					Enabled: true,
				},
			},
		}

		client := newUserInfoClient(http.DefaultClient, config, nil)

		_, err := client.GetUserInfo(context.Background(), "", "https://example.com")
		if err == nil {
			t.Error("GetUserInfo() should error on empty access token")
		}
	})

	t.Run("handles HTTP errors", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
		}))
		defer server.Close()

		provider := &mockUserInfoProvider{userInfoURL: server.URL}
		config := &Config{
			Provider: provider,
			OIDC: &OIDCConfig{
				Enabled: true,
				UserInfo: UserInfoConfig{
					Enabled: true,
				},
			},
		}

		client := newUserInfoClient(http.DefaultClient, config, nil)

		_, err := client.GetUserInfo(context.Background(), "test-token", "https://example.com")
		if err == nil {
			t.Error("GetUserInfo() should error on HTTP error")
		}
	})

	t.Run("handles invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		provider := &mockUserInfoProvider{userInfoURL: server.URL}
		config := &Config{
			Provider: provider,
			OIDC: &OIDCConfig{
				Enabled: true,
				UserInfo: UserInfoConfig{
					Enabled: true,
				},
			},
		}

		client := newUserInfoClient(http.DefaultClient, config, nil)

		_, err := client.GetUserInfo(context.Background(), "test-token", "https://example.com")
		if err == nil {
			t.Error("GetUserInfo() should error on invalid JSON")
		}
	})

	t.Run("validates subject claim", func(t *testing.T) {
		invalidUserInfo := &UserInfo{
			Name: "John Doe",
			// Missing Subject
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(invalidUserInfo)
		}))
		defer server.Close()

		provider := &mockUserInfoProvider{userInfoURL: server.URL}
		config := &Config{
			Provider: provider,
			OIDC: &OIDCConfig{
				Enabled: true,
				UserInfo: UserInfoConfig{
					Enabled: true,
				},
			},
		}

		client := newUserInfoClient(http.DefaultClient, config, nil)

		_, err := client.GetUserInfo(context.Background(), "test-token", "https://example.com")
		if err == nil {
			t.Error("GetUserInfo() should error when subject missing")
		}
	})

	t.Run("handles context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(validUserInfo)
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		provider := &mockUserInfoProvider{userInfoURL: server.URL}
		config := &Config{
			Provider: provider,
			OIDC: &OIDCConfig{
				Enabled: true,
				UserInfo: UserInfoConfig{
					Enabled: true,
				},
			},
		}

		client := newUserInfoClient(http.DefaultClient, config, nil)

		_, err := client.GetUserInfo(ctx, "test-token", "https://example.com")
		if err == nil {
			t.Error("GetUserInfo() should error on cancelled context")
		}
	})

	t.Run("respects timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(validUserInfo)
		}))
		defer server.Close()

		provider := &mockUserInfoProvider{userInfoURL: server.URL}
		config := &Config{
			Provider: provider,
			OIDC: &OIDCConfig{
				Enabled: true,
				UserInfo: UserInfoConfig{
					Enabled: true,
					Timeout: 50 * time.Millisecond,
				},
			},
		}

		client := newUserInfoClient(http.DefaultClient, config, nil)

		_, err := client.GetUserInfo(context.Background(), "test-token", "https://example.com")
		if err == nil {
			t.Error("GetUserInfo() should error on timeout")
		}
	})

	t.Run("uses discovery for endpoint URL", func(t *testing.T) {
		// Use a shared variable to store the server URL
		var serverURL string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				discovery := &OIDCDiscoveryConfig{
					Issuer:                           serverURL,
					AuthorizationEndpoint:            serverURL + "/authorize",
					TokenEndpoint:                    serverURL + "/token",
					UserInfoEndpoint:                 serverURL + "/userinfo",
					JWKSUri:                          serverURL + "/jwks",
					ResponseTypesSupported:           []string{"code"},
					SubjectTypesSupported:            []string{"public"},
					IDTokenSigningAlgValuesSupported: []string{"RS256"},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(discovery)
			} else if r.URL.Path == "/userinfo" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(validUserInfo)
			}
		}))
		defer server.Close()

		// Set the server URL after server is created
		serverURL = server.URL

		provider := &mockUserInfoProvider{} // No UserInfoURL
		config := &Config{
			Provider: provider,
			OIDC: &OIDCConfig{
				Enabled: true,
				UserInfo: UserInfoConfig{
					Enabled: true,
				},
			},
		}

		discoveryClient := newDiscoveryClient(http.DefaultClient, config.OIDC)
		client := newUserInfoClient(http.DefaultClient, config, discoveryClient)

		info, err := client.GetUserInfo(context.Background(), "test-token", server.URL)
		if err != nil {
			t.Fatalf("GetUserInfo() error = %v", err)
		}

		if info.Subject != "user123" {
			t.Errorf("GetUserInfo() Subject = %s, want user123", info.Subject)
		}
	})
}

func TestUserInfoClient_ClearCache(t *testing.T) {
	config := &Config{
		OIDC: &OIDCConfig{
			Enabled: true,
			UserInfo: UserInfoConfig{
				Enabled: true,
			},
		},
	}

	client := newUserInfoClient(http.DefaultClient, config, nil)

	// Add some entries to cache
	client.cacheUserInfo("token1", &UserInfo{Subject: "user1"})
	client.cacheUserInfo("token2", &UserInfo{Subject: "user2"})

	if len(client.cache) != 2 {
		t.Fatalf("Cache length = %d, want 2", len(client.cache))
	}

	client.ClearCache()

	if len(client.cache) != 0 {
		t.Errorf("ClearCache() cache length = %d, want 0", len(client.cache))
	}
}

func TestUserInfoClient_CacheUserInfo(t *testing.T) {
	config := &Config{
		OIDC: &OIDCConfig{
			Enabled: true,
			UserInfo: UserInfoConfig{
				Enabled:  true,
				CacheTTL: 5 * time.Minute,
			},
		},
	}

	client := newUserInfoClient(http.DefaultClient, config, nil)

	userInfo := &UserInfo{
		Subject: "user123",
		Name:    "John Doe",
	}

	client.cacheUserInfo("test-token", userInfo)

	cached := client.getFromCache("test-token")
	if cached == nil {
		t.Fatal("cacheUserInfo() did not cache user info")
	}

	if cached.Subject != "user123" {
		t.Errorf("Cached Subject = %s, want user123", cached.Subject)
	}
}

func TestUserInfoClient_GetFromCache(t *testing.T) {
	config := &Config{
		OIDC: &OIDCConfig{
			Enabled: true,
			UserInfo: UserInfoConfig{
				Enabled:  true,
				CacheTTL: 50 * time.Millisecond,
			},
		},
	}

	client := newUserInfoClient(http.DefaultClient, config, nil)

	t.Run("returns nil for missing token", func(t *testing.T) {
		cached := client.getFromCache("missing-token")
		if cached != nil {
			t.Error("getFromCache() should return nil for missing token")
		}
	})

	t.Run("returns cached value", func(t *testing.T) {
		userInfo := &UserInfo{Subject: "user123"}
		client.cacheUserInfo("test-token", userInfo)

		cached := client.getFromCache("test-token")
		if cached == nil {
			t.Fatal("getFromCache() returned nil")
		}

		if cached.Subject != "user123" {
			t.Errorf("Cached Subject = %s, want user123", cached.Subject)
		}
	})

	t.Run("returns nil for expired entry", func(t *testing.T) {
		userInfo := &UserInfo{Subject: "user123"}
		client.cacheUserInfo("expired-token", userInfo)

		// Wait for expiration
		time.Sleep(100 * time.Millisecond)

		cached := client.getFromCache("expired-token")
		if cached != nil {
			t.Error("getFromCache() should return nil for expired entry")
		}
	})
}

func TestUserInfoClient_CleanupExpiredLocked(t *testing.T) {
	config := &Config{
		OIDC: &OIDCConfig{
			Enabled: true,
			UserInfo: UserInfoConfig{
				Enabled:  true,
				CacheTTL: 50 * time.Millisecond,
			},
		},
	}

	client := newUserInfoClient(http.DefaultClient, config, nil)

	// Add entries
	for i := 0; i < 10; i++ {
		client.cacheUserInfo(fmt.Sprintf("token%d", i), &UserInfo{Subject: "user"})
	}

	if len(client.cache) != 10 {
		t.Fatalf("Cache length = %d, want 10", len(client.cache))
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Trigger cleanup
	client.mu.Lock()
	client.cleanupExpiredLocked()
	client.mu.Unlock()

	if len(client.cache) != 0 {
		t.Errorf("After cleanup, cache length = %d, want 0", len(client.cache))
	}
}

func TestUserInfoClient_IsUserInfoEnabled(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{
			name: "enabled",
			config: &Config{
				OIDC: &OIDCConfig{
					Enabled: true,
					UserInfo: UserInfoConfig{
						Enabled: true,
					},
				},
			},
			want: true,
		},
		{
			name: "OIDC disabled",
			config: &Config{
				OIDC: &OIDCConfig{
					Enabled: false,
					UserInfo: UserInfoConfig{
						Enabled: true,
					},
				},
			},
			want: false,
		},
		{
			name: "UserInfo disabled",
			config: &Config{
				OIDC: &OIDCConfig{
					Enabled: true,
					UserInfo: UserInfoConfig{
						Enabled: false,
					},
				},
			},
			want: false,
		},
		{
			name:   "nil OIDC config",
			config: &Config{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &userInfoClient{
				config: tt.config,
			}

			got := client.isUserInfoEnabled()
			if got != tt.want {
				t.Errorf("isUserInfoEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserInfoClient_ConcurrentAccess(t *testing.T) {
	config := &Config{
		OIDC: &OIDCConfig{
			Enabled: true,
			UserInfo: UserInfoConfig{
				Enabled: true,
			},
		},
	}

	client := newUserInfoClient(http.DefaultClient, config, nil)

	const goroutines = 50
	var wg sync.WaitGroup

	// Mix of cache writes, reads, and clears
	wg.Add(goroutines * 3)

	// Writers
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			userInfo := &UserInfo{Subject: "user"}
			client.cacheUserInfo(fmt.Sprintf("token%d", n), userInfo)
		}(i)
	}

	// Readers
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			_ = client.getFromCache(fmt.Sprintf("token%d", n))
		}(i)
	}

	// Cache operations
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			if n%10 == 0 {
				client.ClearCache()
			}
		}(i)
	}

	wg.Wait()

	// Should not panic
}

func TestUserInfoClient_GetUserInfoEndpoint(t *testing.T) {
	t.Run("uses provider URL first", func(t *testing.T) {
		provider := &mockUserInfoProvider{
			userInfoURL: "https://provider.com/userinfo",
		}

		config := &Config{
			Provider: provider,
			OIDC: &OIDCConfig{
				Enabled: true,
			},
		}

		client := newUserInfoClient(http.DefaultClient, config, nil)

		url, err := client.getUserInfoEndpoint(context.Background(), "https://example.com")
		if err != nil {
			t.Fatalf("getUserInfoEndpoint() error = %v", err)
		}

		if url != "https://provider.com/userinfo" {
			t.Errorf("getUserInfoEndpoint() = %s, want https://provider.com/userinfo", url)
		}
	})

	t.Run("falls back to discovery", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			discovery := &OIDCDiscoveryConfig{
				Issuer:                           "https://example.com",
				AuthorizationEndpoint:            "https://example.com/authorize",
				TokenEndpoint:                    "https://example.com/token",
				UserInfoEndpoint:                 "https://example.com/userinfo-from-discovery",
				JWKSUri:                          "https://example.com/jwks",
				ResponseTypesSupported:           []string{"code"},
				SubjectTypesSupported:            []string{"public"},
				IDTokenSigningAlgValuesSupported: []string{"RS256"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(discovery)
		}))
		defer server.Close()

		provider := &mockUserInfoProvider{} // No UserInfoURL
		config := &Config{
			Provider: provider,
			OIDC: &OIDCConfig{
				Enabled: true,
			},
		}

		discoveryClient := newDiscoveryClient(http.DefaultClient, config.OIDC)
		client := newUserInfoClient(http.DefaultClient, config, discoveryClient)

		url, err := client.getUserInfoEndpoint(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("getUserInfoEndpoint() error = %v", err)
		}

		if url != "https://example.com/userinfo-from-discovery" {
			t.Errorf("getUserInfoEndpoint() = %s, want discovery URL", url)
		}
	})

	t.Run("errors when no endpoint available", func(t *testing.T) {
		provider := &mockUserInfoProvider{} // No UserInfoURL
		config := &Config{
			Provider: provider,
			OIDC: &OIDCConfig{
				Enabled: true,
			},
		}

		client := newUserInfoClient(http.DefaultClient, config, nil) // No discovery client

		_, err := client.getUserInfoEndpoint(context.Background(), "https://example.com")
		if err == nil {
			t.Error("getUserInfoEndpoint() should error when no endpoint available")
		}
	})
}

// mockUserInfoProvider implements Provider interface for testing
type mockUserInfoProvider struct {
	userInfoURL string
}

func (m *mockUserInfoProvider) Name() string             { return "mock" }
func (m *mockUserInfoProvider) AuthURL() string          { return "" }
func (m *mockUserInfoProvider) TokenURL() string         { return "" }
func (m *mockUserInfoProvider) UserInfoURL() string      { return m.userInfoURL }
func (m *mockUserInfoProvider) JWKSURL() string          { return "" }
func (m *mockUserInfoProvider) Issuer() string           { return "" }
func (m *mockUserInfoProvider) IntrospectionURL() string { return "" }
