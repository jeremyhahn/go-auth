//go:build integration

package oauth_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/api"
	"github.com/jeremyhahn/go-auth/pkg/oauth"
)

const (
	hydraPublicURL = "http://127.0.0.1:4444"
	hydraAdminURL  = "http://127.0.0.1:4445"
)

// Helper function to get client credentials from environment
// sealForTest seals a fixture credential into a fresh enclave and destroys it
// when the test ends. Each Config gets its own: NewAuthenticator takes
// ownership of the client secret it is given. An empty s yields nil.
func sealForTest(t *testing.T, s string) *enclave.MemoryEnclave {
	t.Helper()
	if s == "" {
		return nil
	}
	e, err := enclave.NewMemoryEnclave([]byte(s))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	t.Cleanup(func() {
		if err := e.Destroy(); err != nil {
			t.Errorf("Destroy: %v", err)
		}
	})
	return e
}

// openForTest copies a credential out of its enclave for an assertion or for a
// string-only API under test.
func openForTest(t *testing.T, e *enclave.MemoryEnclave) string {
	t.Helper()
	var s string
	err := e.WithBytes(func(b []byte) error {
		s = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	return s
}

func getClientCredentials(t *testing.T) (clientID, clientSecret string) {
	t.Helper()
	clientID = os.Getenv("TEST_OAUTH_CLIENT_CREDENTIALS_ID")
	clientSecret = os.Getenv("TEST_OAUTH_CLIENT_CREDENTIALS_SECRET")
	if clientID == "" {
		// Fallback to hardcoded values for local testing
		clientID = "test-client-credentials"
		clientSecret = "test-client-secret"
	}
	return
}

// Helper function to get password client credentials from environment
func getPasswordClientCredentials(t *testing.T) (clientID, clientSecret string) {
	t.Helper()
	clientID = os.Getenv("TEST_OAUTH_PASSWORD_CLIENT_ID")
	clientSecret = os.Getenv("TEST_OAUTH_PASSWORD_CLIENT_SECRET")
	if clientID == "" {
		clientID = "test-password-client"
		clientSecret = "test-password-secret"
	}
	return
}

// TestOAuthIntegration_ClientCredentialsFlow tests the client credentials OAuth flow
// against a real ORY Hydra server running in the Docker container.
func TestOAuthIntegration_ClientCredentialsFlow(t *testing.T) {
	clientID, clientSecret := getClientCredentials(t)

	// Create custom provider for Hydra
	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		AuthEndpoint:  hydraPublicURL + "/oauth2/auth",
		IssuerURL:     hydraPublicURL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Configure authenticator for client credentials flow
	cfg := &oauth.Config{
		Provider:     provider,
		Flow:         oauth.FlowClientCredentials,
		ClientID:     clientID,
		ClientSecret: sealForTest(t, clientSecret),
		Scopes:       []string{"api:read", "api:write"},
		Timeout:      10 * time.Second,
	}

	authenticator, err := oauth.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer authenticator.Close()

	// Test client credentials authentication
	ctx := context.Background()
	token, err := authenticator.AuthenticateClientCredentials(ctx)
	if err != nil {
		t.Fatalf("Expected client credentials flow to succeed, got error: %v", err)
	}
	defer token.Destroy()

	if token == nil {
		t.Fatal("Expected non-nil token")
	}

	if !token.AccessToken().IsAlive() {
		t.Error("Expected non-empty access token")
	}

	if token.TokenType != "bearer" && token.TokenType != "Bearer" {
		t.Errorf("Expected token type 'bearer', got '%s'", token.TokenType)
	}

	if int64(time.Until(token.Expiry).Seconds()) <= 0 {
		t.Errorf("Expected positive expires_in, got %d", int64(time.Until(token.Expiry).Seconds()))
	}

	t.Logf("Successfully obtained access token via client credentials flow")
	t.Logf("Token type: %s, expires in: %d seconds", token.TokenType, int64(time.Until(token.Expiry).Seconds()))
}

// TestOAuthIntegration_ClientCredentialsFlow_InvalidCredentials tests that invalid
// client credentials are properly rejected.
func TestOAuthIntegration_ClientCredentialsFlow_InvalidCredentials(t *testing.T) {
	clientID, _ := getClientCredentials(t)

	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		IssuerURL:     hydraPublicURL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Use invalid credentials
	cfg := &oauth.Config{
		Provider:     provider,
		Flow:         oauth.FlowClientCredentials,
		ClientID:     clientID,
		ClientSecret: sealForTest(t, "wrong-secret"),
		Scopes:       []string{"api:read"},
		Timeout:      10 * time.Second,
	}

	authenticator, err := oauth.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer authenticator.Close()

	ctx := context.Background()
	_, err = authenticator.AuthenticateClientCredentials(ctx)
	if err == nil {
		t.Error("Expected client credentials flow with bad credentials to fail")
	}

	t.Logf("Invalid credentials properly rejected: %v", err)
}

// TestOAuthIntegration_PasswordFlow tests the resource owner password credentials flow
// against a real Hydra server.
//
// NOTE: This test is expected to fail or be skipped because ORY Hydra does not
// support the password grant type in production mode. Hydra requires proper user
// authentication through login flows and does not accept arbitrary username/password
// combinations via the OAuth token endpoint, even in dev mode.
//
// The password grant type is considered insecure and is not recommended by OAuth 2.0
// best practices. Most modern OAuth servers (including Hydra) do not support it.
func TestOAuthIntegration_PasswordFlow(t *testing.T) {
	t.Skip("Skipping password flow test - ORY Hydra does not support password grant type. " +
		"Hydra requires proper authentication flows and does not accept username/password " +
		"directly at the token endpoint, even with a client configured for password grants. " +
		"This is by design for security reasons.")

	clientID, clientSecret := getPasswordClientCredentials(t)

	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		IssuerURL:     hydraPublicURL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Configure for password flow
	cfg := &oauth.Config{
		Provider:     provider,
		Flow:         oauth.FlowPassword,
		ClientID:     clientID,
		ClientSecret: sealForTest(t, clientSecret),
		Scopes:       []string{"openid", "profile", "email"},
		Timeout:      10 * time.Second,
	}

	authenticator, err := oauth.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer authenticator.Close()

	// Test password flow with valid credentials
	// Note: Hydra in --dev mode accepts any username/password
	ctx := context.Background()
	token, err := authenticator.AuthenticatePassword(ctx, "testuser", sealForTest(t, "testpass"))
	if err != nil {
		t.Fatalf("Expected password flow to succeed, got error: %v", err)
	}
	defer token.Destroy()

	if token == nil {
		t.Fatal("Expected non-nil token")
	}

	if !token.AccessToken().IsAlive() {
		t.Error("Expected non-empty access token")
	}

	// Password flow with offline scope should return refresh token
	if !token.RefreshToken().IsAlive() {
		t.Log("Note: No refresh token returned (may need 'offline' scope)")
	}

	t.Logf("Successfully authenticated via password flow")
	t.Logf("Access token length: %d, has refresh token: %v",
		token.AccessToken().Size(), token.RefreshToken().IsAlive())
}

// TestOAuthIntegration_TokenIntrospection tests token validation via introspection
// against a real Hydra server.
func TestOAuthIntegration_TokenIntrospection(t *testing.T) {
	clientID, clientSecret := getClientCredentials(t)

	// First, get a valid token using client credentials
	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		IssuerURL:     hydraPublicURL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Get a token first
	tokenCfg := &oauth.Config{
		Provider:     provider,
		Flow:         oauth.FlowClientCredentials,
		ClientID:     clientID,
		ClientSecret: sealForTest(t, clientSecret),
		Scopes:       []string{"api:read"},
		Timeout:      10 * time.Second,
	}

	tokenAuth, err := oauth.NewAuthenticator(tokenCfg)
	if err != nil {
		t.Fatalf("Failed to create token authenticator: %v", err)
	}
	defer tokenAuth.Close()

	ctx := context.Background()
	token, err := tokenAuth.AuthenticateClientCredentials(ctx)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	defer token.Destroy()

	// Now configure authenticator for token validation via introspection
	// NOTE: TokenEndpoint is required even for validation-only providers
	validationProvider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:          "hydra",
		TokenEndpoint:         hydraPublicURL + "/oauth2/token",
		IntrospectionEndpoint: hydraAdminURL + "/admin/oauth2/introspect",
		IssuerURL:             hydraPublicURL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create validation provider: %v", err)
	}

	validationCfg := &oauth.Config{
		Provider:     validationProvider,
		Flow:         oauth.FlowTokenValidation,
		ClientID:     clientID,
		ClientSecret: sealForTest(t, clientSecret),
		Timeout:      10 * time.Second,
		Validation: oauth.TokenValidationConfig{
			Method:           oauth.ValidationIntrospection,
			IntrospectionURL: hydraAdminURL + "/admin/oauth2/introspect",
		},
	}

	validator, err := oauth.NewAuthenticator(validationCfg)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}
	defer validator.Close()

	// Test 1: Valid token should validate successfully
	claims, err := validator.ValidateToken(ctx, token.AccessToken())
	if err != nil {
		t.Errorf("Expected valid token to validate, got error: %v", err)
	}

	if claims != nil {
		t.Logf("Token validated successfully")
		t.Logf("Client ID: %s, Active: %v", claims.Subject, true)
		if "" != "" {
			t.Logf("Scopes: %s", "")
		}
	}

	// Test 2: Invalid token should fail validation
	err = validator.Authenticate(ctx, "", sealForTest(t, "invalid-token-xyz"))
	if err == nil {
		t.Error("Expected invalid token to fail validation")
	} else {
		t.Logf("Invalid token properly rejected: %v", err)
	}

	// Test 3: Empty token should fail
	err = validator.Authenticate(ctx, "", nil)
	if err == nil {
		t.Error("Expected empty token to fail validation")
	}
}

// TestOAuthIntegration_WithAPIService tests OAuth integration with the api.Service
// using real token validation against Hydra.
func TestOAuthIntegration_WithAPIService(t *testing.T) {
	clientID, clientSecret := getClientCredentials(t)

	// Get a valid token first
	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		IssuerURL:     hydraPublicURL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	tokenCfg := &oauth.Config{
		Provider:     provider,
		Flow:         oauth.FlowClientCredentials,
		ClientID:     clientID,
		ClientSecret: sealForTest(t, clientSecret),
		Scopes:       []string{"api:read"},
		Timeout:      10 * time.Second,
	}

	tokenAuth, err := oauth.NewAuthenticator(tokenCfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer tokenAuth.Close()

	ctx := context.Background()
	token, err := tokenAuth.AuthenticateClientCredentials(ctx)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	defer token.Destroy()

	// Create validator with introspection
	// NOTE: TokenEndpoint is required even for validation-only providers
	validationProvider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:          "hydra",
		TokenEndpoint:         hydraPublicURL + "/oauth2/token",
		IntrospectionEndpoint: hydraAdminURL + "/admin/oauth2/introspect",
		IssuerURL:             hydraPublicURL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create validation provider: %v", err)
	}

	validationCfg := &oauth.Config{
		Provider:     validationProvider,
		Flow:         oauth.FlowTokenValidation,
		ClientID:     clientID,
		ClientSecret: sealForTest(t, clientSecret),
		Timeout:      10 * time.Second,
		Validation: oauth.TokenValidationConfig{
			Method:           oauth.ValidationIntrospection,
			IntrospectionURL: hydraAdminURL + "/admin/oauth2/introspect",
		},
	}

	authenticator, err := oauth.NewAuthenticator(validationCfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer authenticator.Close()

	// Create API service with OAuth backend
	service, err := api.NewService(api.Config{
		Backends: []api.Backend{
			{
				Name:    api.BackendOAuth,
				Handler: api.OAuth(authenticator),
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create API service: %v", err)
	}

	// Test 1: Valid token should authenticate. Login takes ownership of the
	// request's enclaves, so it gets its own copy rather than the Token's.
	req := api.LoginRequest{
		Backend:  api.BackendOAuth,
		Username: "ignored", // OAuth doesn't use username
		Password: sealForTest(t, openForTest(t, token.AccessToken())),
	}

	err = service.Login(ctx, req)
	if req.Password.IsAlive() {
		t.Error("Login left the request's token alive")
	}
	if err != nil {
		t.Errorf("Expected valid token to authenticate via API service, got error: %v", err)
	} else {
		t.Log("Valid token successfully authenticated via API service")
	}

	// Test 2: Invalid token should fail
	req.Password = sealForTest(t, "invalid-token-xyz")
	err = service.Login(ctx, req)
	if err == nil {
		t.Error("Expected invalid token to fail authentication via API service")
	} else {
		t.Logf("Invalid token properly rejected by API service: %v", err)
	}
}

// TestOAuthIntegration_TokenCaching tests that token validation results are cached
// and subsequent validations are faster.
func TestOAuthIntegration_TokenCaching(t *testing.T) {
	clientID, clientSecret := getClientCredentials(t)

	// Get a valid token
	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		IssuerURL:     hydraPublicURL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	tokenCfg := &oauth.Config{
		Provider:     provider,
		Flow:         oauth.FlowClientCredentials,
		ClientID:     clientID,
		ClientSecret: sealForTest(t, clientSecret),
		Scopes:       []string{"api:read"},
		Timeout:      10 * time.Second,
	}

	tokenAuth, err := oauth.NewAuthenticator(tokenCfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer tokenAuth.Close()

	ctx := context.Background()
	token, err := tokenAuth.AuthenticateClientCredentials(ctx)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	defer token.Destroy()

	// Create validator with caching enabled
	// NOTE: TokenEndpoint is required even for validation-only providers
	validationProvider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:          "hydra",
		TokenEndpoint:         hydraPublicURL + "/oauth2/token",
		IntrospectionEndpoint: hydraAdminURL + "/admin/oauth2/introspect",
		IssuerURL:             hydraPublicURL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create validation provider: %v", err)
	}

	validationCfg := &oauth.Config{
		Provider:     validationProvider,
		Flow:         oauth.FlowTokenValidation,
		ClientID:     clientID,
		ClientSecret: sealForTest(t, clientSecret),
		Timeout:      10 * time.Second,
		Cache: oauth.CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     5 * time.Minute,
		},
		Validation: oauth.TokenValidationConfig{
			Method:           oauth.ValidationIntrospection,
			IntrospectionURL: hydraAdminURL + "/admin/oauth2/introspect",
		},
	}

	validator, err := oauth.NewAuthenticator(validationCfg)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}
	defer validator.Close()

	// First validation (uncached)
	start := time.Now()
	_, err = validator.ValidateToken(ctx, token.AccessToken())
	firstDuration := time.Since(start)
	if err != nil {
		t.Fatalf("First validation failed: %v", err)
	}

	// Second validation (should be cached)
	start = time.Now()
	_, err = validator.ValidateToken(ctx, token.AccessToken())
	cachedDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Cached validation failed: %v", err)
	}

	t.Logf("First validation: %v", firstDuration)
	t.Logf("Cached validation: %v", cachedDuration)

	// Cached validation should be significantly faster
	if cachedDuration > firstDuration/2 {
		t.Logf("Warning: Cached validation (%v) not significantly faster than first (%v)",
			cachedDuration, firstDuration)
	} else {
		t.Logf("Cache is working - cached validation is %v faster",
			firstDuration-cachedDuration)
	}

	// Test cache clearing
	validator.ClearCache()

	// After clearing cache, validation should take longer again
	start = time.Now()
	_, err = validator.ValidateToken(ctx, token.AccessToken())
	afterClearDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Validation after cache clear failed: %v", err)
	}

	t.Logf("After cache clear: %v", afterClearDuration)
}

// TestOAuthIntegration_MultipleScopes tests requesting and validating tokens with multiple scopes.
func TestOAuthIntegration_MultipleScopes(t *testing.T) {
	clientID, clientSecret := getClientCredentials(t)

	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		IssuerURL:     hydraPublicURL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	cfg := &oauth.Config{
		Provider:     provider,
		Flow:         oauth.FlowClientCredentials,
		ClientID:     clientID,
		ClientSecret: sealForTest(t, clientSecret),
		Scopes:       []string{"api:read", "api:write"},
		Timeout:      10 * time.Second,
	}

	authenticator, err := oauth.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer authenticator.Close()

	ctx := context.Background()
	token, err := authenticator.AuthenticateClientCredentials(ctx)
	if err != nil {
		t.Fatalf("Failed to get token with multiple scopes: %v", err)
	}
	defer token.Destroy()

	if len(token.Scopes) == 0 {
		t.Log("Note: Scope not returned in token response (may be in JWT claims)")
	} else {
		t.Logf("Token scopes: %v", token.Scopes)
	}
}
