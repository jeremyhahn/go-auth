package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewAuthenticator_Success(t *testing.T) {
	// Create a mock JWKS server
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()

	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Flow:         FlowTokenValidation,
		Validation: TokenValidationConfig{
			Method:  ValidationJWT,
			JWKSURL: jwksServer.URL,
		},
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	if auth == nil {
		t.Fatal("Expected non-nil authenticator")
	}

	if auth.config != config {
		t.Error("Config not set correctly")
	}

	if auth.validator == nil {
		t.Error("Expected validator to be initialized")
	}

	if auth.cache == nil {
		t.Error("Expected cache to be initialized")
	}
}

func TestNewAuthenticator_InvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "missing client ID",
			config: &Config{
				Provider: Google(),
				Flow:     FlowTokenValidation,
			},
			wantErr: true,
		},
		{
			name: "invalid flow",
			config: &Config{
				Provider: Google(),
				ClientID: "test-client",
				Flow:     "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewAuthenticator(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAuthenticator() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && auth == nil {
				t.Error("Expected non-nil authenticator")
			}
		})
	}
}

func TestValidateToken_Success(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()

	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Flow:         FlowTokenValidation,
		Validation: TokenValidationConfig{
			Method:   ValidationJWT,
			JWKSURL:  jwksServer.URL,
			Issuer:   "https://accounts.google.com",
			Audience: "test-client",
		},
		Cache: CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     5 * time.Minute,
		},
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	// Generate a valid JWT
	token := createTestJWT(t, privateKey, jwt.MapClaims{
		"sub":   "user123",
		"iss":   "https://accounts.google.com",
		"aud":   "test-client",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"email": "test@example.com",
		"name":  "Test User",
	})

	ctx := context.Background()
	claims, err := auth.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("ValidateToken() failed: %v", err)
	}

	if claims.Subject != "user123" {
		t.Errorf("Expected subject 'user123', got '%s'", claims.Subject)
	}

	if claims.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", claims.Email)
	}

	// Second call should hit cache
	claims2, err := auth.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("ValidateToken() second call failed: %v", err)
	}

	if claims2.Subject != claims.Subject {
		t.Error("Cached claims don't match")
	}
}

func TestValidateToken_InvalidToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()

	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Flow:         FlowTokenValidation,
		Validation: TokenValidationConfig{
			Method:  ValidationJWT,
			JWKSURL: jwksServer.URL,
		},
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	tests := []struct {
		name    string
		token   string
		wantErr error
	}{
		{
			name:    "empty token",
			token:   "",
			wantErr: ErrMissingToken,
		},
		{
			name:    "malformed token",
			token:   "invalid.token.string",
			wantErr: ErrInvalidToken,
		},
		{
			name:    "expired token",
			token:   createTestJWT(t, privateKey, jwt.MapClaims{"exp": time.Now().Add(-1 * time.Hour).Unix()}),
			wantErr: ErrExpiredToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := auth.ValidateToken(context.Background(), tt.token)
			if err == nil {
				t.Error("Expected error, got nil")
			}
			if tt.wantErr != nil && err != tt.wantErr && !containsError(err, tt.wantErr) {
				t.Errorf("Expected error containing %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestAuthenticatePassword_WrongFlow(t *testing.T) {
	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Flow:         FlowClientCredentials,
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	_, err = auth.AuthenticatePassword(context.Background(), "testuser", "testpass")
	if err == nil {
		t.Error("Expected error for wrong flow")
	}
	if !containsError(err, ErrFlowNotSupported) {
		t.Errorf("Expected ErrFlowNotSupported, got %v", err)
	}
}

func TestAuthenticateClientCredentials_WrongFlow(t *testing.T) {
	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Flow:         FlowPassword,
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	_, err = auth.AuthenticateClientCredentials(context.Background())
	if err == nil {
		t.Error("Expected error for wrong flow")
	}
	if !containsError(err, ErrFlowNotSupported) {
		t.Errorf("Expected ErrFlowNotSupported, got %v", err)
	}
}

func TestExchangeAuthorizationCode_WrongFlow(t *testing.T) {
	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Flow:         FlowPassword,
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	_, err = auth.ExchangeAuthorizationCode(context.Background(), "code", "")
	if err == nil {
		t.Error("Expected error for wrong flow")
	}
	if !containsError(err, ErrFlowNotSupported) {
		t.Errorf("Expected ErrFlowNotSupported, got %v", err)
	}
}

func TestBuildAuthURL_WithPKCE(t *testing.T) {
	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Flow:         FlowAuthorizationCode,
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	authURL, codeVerifier, err := auth.BuildAuthURL("random-state", true, nil)
	if err != nil {
		t.Fatalf("BuildAuthURL() failed: %v", err)
	}

	if authURL == "" {
		t.Error("Expected non-empty auth URL")
	}

	if codeVerifier == "" {
		t.Error("Expected non-empty code verifier")
	}

	// Verify URL contains required parameters
	if !contains(authURL, "client_id=test-client") {
		t.Error("Auth URL missing client_id")
	}

	if !contains(authURL, "state=random-state") {
		t.Error("Auth URL missing state")
	}

	if !contains(authURL, "code_challenge=") {
		t.Error("Auth URL missing code_challenge")
	}

	if !contains(authURL, "code_challenge_method=S256") {
		t.Error("Auth URL missing code_challenge_method")
	}
}

func TestBuildAuthURL_WithoutPKCE(t *testing.T) {
	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Flow:         FlowAuthorizationCode,
		RedirectURL:  "http://localhost:8080/callback",
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	authURL, codeVerifier, err := auth.BuildAuthURL("random-state", false, nil)
	if err != nil {
		t.Fatalf("BuildAuthURL() failed: %v", err)
	}

	if authURL == "" {
		t.Error("Expected non-empty auth URL")
	}

	if codeVerifier != "" {
		t.Error("Expected empty code verifier without PKCE")
	}

	if contains(authURL, "code_challenge=") {
		t.Error("Auth URL should not have code_challenge without PKCE")
	}
}

func TestBuildAuthURL_WrongFlow(t *testing.T) {
	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Flow:         FlowPassword,
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	_, _, err = auth.BuildAuthURL("state", false, nil)
	if err == nil {
		t.Error("Expected error for wrong flow")
	}
	if !containsError(err, ErrFlowNotSupported) {
		t.Errorf("Expected ErrFlowNotSupported, got %v", err)
	}
}

func TestAuthenticate_DelegatesCorrectly(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()

	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Flow:         FlowTokenValidation,
		Validation: TokenValidationConfig{
			Method:   ValidationJWT,
			JWKSURL:  jwksServer.URL,
			Issuer:   "https://accounts.google.com",
			Audience: "test-client",
		},
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	token := createTestJWT(t, privateKey, jwt.MapClaims{
		"sub": "user123",
		"iss": "https://accounts.google.com",
		"aud": "test-client",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	// Username is ignored for token validation
	err = auth.Authenticate(context.Background(), "ignored", token)
	if err != nil {
		t.Errorf("Authenticate() failed: %v", err)
	}
}

func TestClearCache(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()

	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Flow:         FlowTokenValidation,
		Validation: TokenValidationConfig{
			Method:  ValidationJWT,
			JWKSURL: jwksServer.URL,
		},
		Cache: CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     5 * time.Minute,
		},
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	token := createTestJWT(t, privateKey, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	// Validate token to populate cache
	_, err = auth.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken() failed: %v", err)
	}

	// Clear cache
	auth.ClearCache()

	// Cache should be empty now - no way to verify directly without exposing internals
	// But calling again should work
	_, err = auth.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken() after cache clear failed: %v", err)
	}
}

func TestClose_CleansUpResources(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()

	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Flow:         FlowTokenValidation,
		Validation: TokenValidationConfig{
			Method:  ValidationJWT,
			JWKSURL: jwksServer.URL,
		},
		Cache: CacheConfig{
			Enabled: true,
		},
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	err = auth.Close()
	if err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// Calling Close again should be safe
	err = auth.Close()
	if err != nil {
		t.Errorf("Second Close() failed: %v", err)
	}
}

// Helper functions

func createTestJWT(t *testing.T, privateKey *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-id"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign JWT: %v", err)
	}

	return tokenString
}

func createMockJWKSServer(t *testing.T, publicKey *rsa.PublicKey) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create JWK representation of the public key
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"kid": "test-key-id",
					"use": "sig",
					"alg": "RS256",
					"n":   base64EncodeUint(publicKey.N.Bytes()),
					"e":   base64EncodeUint(bigIntToBytes(int64(publicKey.E))),
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func containsError(err, target error) bool {
	if err == nil || target == nil {
		return false
	}
	return contains(err.Error(), target.Error())
}

func base64EncodeUint(b []byte) string {
	return base64URLEncode(b)
}

func base64URLEncode(b []byte) string {
	// Remove padding
	encoded := ""
	const base64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	for len(b) > 0 {
		var chunk uint32
		chunkLen := len(b)
		if chunkLen > 3 {
			chunkLen = 3
		}

		for i := 0; i < chunkLen; i++ {
			chunk = (chunk << 8) | uint32(b[i])
		}

		if chunkLen < 3 {
			chunk <<= 8 * uint(3-chunkLen)
		}

		for i := 0; i < 4; i++ {
			if chunkLen*8 >= (i+1)*6 || i < 2 {
				encoded += string(base64URL[(chunk>>(18-6*uint(i)))&0x3F])
			}
		}

		b = b[chunkLen:]
	}

	return encoded
}

func bigIntToBytes(n int64) []byte {
	if n == 0 {
		return []byte{0}
	}

	var bytes []byte
	for n > 0 {
		bytes = append([]byte{byte(n & 0xFF)}, bytes...)
		n >>= 8
	}

	return bytes
}
