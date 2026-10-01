package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExchangeAuthorizationCode_Success(t *testing.T) {
	tokenResponse := map[string]interface{}{
		"access_token":  "test-access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "test-refresh-token",
		"id_token":      "test-id-token",
		"scope":         "openid profile email",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}

		if r.FormValue("grant_type") != "authorization_code" {
			t.Errorf("Expected grant_type 'authorization_code', got '%s'", r.FormValue("grant_type"))
		}

		if r.FormValue("code") != "test-code" {
			t.Errorf("Expected code 'test-code', got '%s'", r.FormValue("code"))
		}

		if r.FormValue("client_id") != "test-client" {
			t.Errorf("Expected client_id 'test-client', got '%s'", r.FormValue("client_id"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse)
	}))
	defer server.Close()

	config := &Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
		RedirectURL:  "http://localhost:8080/callback",
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	token, err := handler.exchangeAuthorizationCode(context.Background(), "test-code")
	if err != nil {
		t.Fatalf("exchangeAuthorizationCode() failed: %v", err)
	}

	if openedForTest(t, token.AccessToken()) != "test-access-token" {
		t.Errorf("Expected access token 'test-access-token', got '%s'", openedForTest(t, token.AccessToken()))
	}

	if openedForTest(t, token.RefreshToken()) != "test-refresh-token" {
		t.Errorf("Expected refresh token 'test-refresh-token', got '%s'", openedForTest(t, token.RefreshToken()))
	}

	if openedForTest(t, token.IDToken()) != "test-id-token" {
		t.Errorf("Expected ID token 'test-id-token', got '%s'", openedForTest(t, token.IDToken()))
	}

	if len(token.Scopes) != 3 {
		t.Errorf("Expected 3 scopes, got %d", len(token.Scopes))
	}
}

// testPKCEVerifier is a verifier of the shortest length RFC 7636 admits.
const testPKCEVerifier = "abcdefghijklmnopqrstuvwxyz0123456789-._~ABC"

func TestExchangeAuthorizationCode_WithPKCE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}

		if r.FormValue("code_verifier") != testPKCEVerifier {
			t.Errorf("Expected code_verifier %q, got '%s'", testPKCEVerifier, r.FormValue("code_verifier"))
		}

		response := map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := &Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
		RedirectURL:  "http://localhost:8080/callback",
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	verifier := sealedForTest(t, testPKCEVerifier)
	token, err := handler.exchangeAuthorizationCodePKCE(context.Background(), "test-code", verifier)
	if err != nil {
		t.Fatalf("exchangeAuthorizationCode() failed: %v", err)
	}

	if openedForTest(t, token.AccessToken()) != "test-token" {
		t.Errorf("Expected access token 'test-token', got '%s'", openedForTest(t, token.AccessToken()))
	}
}

func TestExchangeAuthorizationCode_InvalidCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid authorization code"}`))
	}))
	defer server.Close()

	config := &Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
		RedirectURL:  "http://localhost:8080/callback",
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	_, err := handler.exchangeAuthorizationCode(context.Background(), "invalid-code")
	if err == nil {
		t.Error("Expected error for invalid code")
	}

	if !containsError(err, ErrTokenExchangeFailed) {
		t.Errorf("Expected ErrTokenExchangeFailed, got %v", err)
	}
}

func TestExchangeAuthorizationCode_NetworkError(t *testing.T) {
	config := &Config{
		Provider:     newTestProvider("http://localhost:1/auth", "http://invalid-url.local/token"),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
		RedirectURL:  "http://localhost:8080/callback",
	}

	httpClient := newDefaultHTTPClient(1*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	_, err := handler.exchangeAuthorizationCode(context.Background(), "test-code")
	if err == nil {
		t.Error("Expected error for network failure")
	}
}

func TestExchangeAuthorizationCode_EmptyCode(t *testing.T) {
	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
		RedirectURL:  "http://localhost:8080/callback",
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	_, err := handler.exchangeAuthorizationCode(context.Background(), "")
	if err == nil {
		t.Error("Expected error for empty code")
	}
}

func TestAuthenticateClientCredentials_Success(t *testing.T) {
	tokenResponse := map[string]interface{}{
		"access_token": "client-access-token",
		"token_type":   "Bearer",
		"expires_in":   7200,
		"scope":        "api.read api.write",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}

		if r.FormValue("grant_type") != "client_credentials" {
			t.Errorf("Expected grant_type 'client_credentials', got '%s'", r.FormValue("grant_type"))
		}

		if r.FormValue("client_id") != "test-client" {
			t.Errorf("Expected client_id 'test-client', got '%s'", r.FormValue("client_id"))
		}

		if r.FormValue("client_secret") != "test-secret" {
			t.Errorf("Expected client_secret 'test-secret', got '%s'", r.FormValue("client_secret"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse)
	}))
	defer server.Close()

	config := &Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
		Scopes:       []string{"api.read", "api.write"},
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	token, err := handler.authenticateClientCredentials(context.Background())
	if err != nil {
		t.Fatalf("authenticateClientCredentials() failed: %v", err)
	}

	if openedForTest(t, token.AccessToken()) != "client-access-token" {
		t.Errorf("Expected access token 'client-access-token', got '%s'", openedForTest(t, token.AccessToken()))
	}

	if len(token.Scopes) != 2 {
		t.Errorf("Expected 2 scopes, got %d", len(token.Scopes))
	}
}

func TestAuthenticateClientCredentials_InvalidClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_client","error_description":"Invalid client credentials"}`))
	}))
	defer server.Close()

	config := &Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "invalid-client",
		ClientSecret: sealedForTest(t, "invalid-secret"),
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	_, err := handler.authenticateClientCredentials(context.Background())
	if err == nil {
		t.Error("Expected error for invalid client")
	}
}

func TestAuthenticatePassword_Success(t *testing.T) {
	tokenResponse := map[string]interface{}{
		"access_token":  "password-access-token",
		"token_type":    "Bearer",
		"expires_in":    1800,
		"refresh_token": "password-refresh-token",
		"scope":         "openid profile",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}

		if r.FormValue("grant_type") != "password" {
			t.Errorf("Expected grant_type 'password', got '%s'", r.FormValue("grant_type"))
		}

		if r.FormValue("username") != "testuser" {
			t.Errorf("Expected username 'testuser', got '%s'", r.FormValue("username"))
		}

		if r.FormValue("password") != "testpass" {
			t.Errorf("Expected password 'testpass', got '%s'", r.FormValue("password"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse)
	}))
	defer server.Close()

	config := &Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
		Scopes:       []string{"openid", "profile"},
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	token, err := handler.authenticatePassword(context.Background(), "testuser", sealedForTest(t, "testpass"))
	if err != nil {
		t.Fatalf("authenticatePassword() failed: %v", err)
	}

	if openedForTest(t, token.AccessToken()) != "password-access-token" {
		t.Errorf("Expected access token 'password-access-token', got '%s'", openedForTest(t, token.AccessToken()))
	}

	if openedForTest(t, token.RefreshToken()) != "password-refresh-token" {
		t.Errorf("Expected refresh token 'password-refresh-token', got '%s'", openedForTest(t, token.RefreshToken()))
	}
}

func TestAuthenticatePassword_InvalidCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid username or password"}`))
	}))
	defer server.Close()

	config := &Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	_, err := handler.authenticatePassword(context.Background(), "wronguser", sealedForTest(t, "wrongpass"))
	if err == nil {
		t.Error("Expected error for invalid credentials")
	}
}

func TestAuthenticatePassword_EmptyCredentials(t *testing.T) {
	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	tests := []struct {
		name     string
		username string
		password string
	}{
		{"empty username", "", "password"},
		{"empty password", "username", ""},
		{"both empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := handler.authenticatePassword(context.Background(), tt.username, sealedForTest(t, tt.password))
			if err == nil {
				t.Error("Expected error for empty credentials")
			}
		})
	}
}

func TestRefreshToken_Success(t *testing.T) {
	tokenResponse := map[string]interface{}{
		"access_token":  "new-access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "new-refresh-token",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}

		if r.FormValue("grant_type") != "refresh_token" {
			t.Errorf("Expected grant_type 'refresh_token', got '%s'", r.FormValue("grant_type"))
		}

		if r.FormValue("refresh_token") != "old-refresh-token" {
			t.Errorf("Expected refresh_token 'old-refresh-token', got '%s'", r.FormValue("refresh_token"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse)
	}))
	defer server.Close()

	config := &Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	token, err := handler.refreshToken(context.Background(), sealedForTest(t, "old-refresh-token"))
	if err != nil {
		t.Fatalf("refreshToken() failed: %v", err)
	}

	if openedForTest(t, token.AccessToken()) != "new-access-token" {
		t.Errorf("Expected access token 'new-access-token', got '%s'", openedForTest(t, token.AccessToken()))
	}
}

func TestRefreshToken_InvalidRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid refresh token"}`))
	}))
	defer server.Close()

	config := &Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	_, err := handler.refreshToken(context.Background(), sealedForTest(t, "invalid-refresh-token"))
	if err == nil {
		t.Error("Expected error for invalid refresh token")
	}
}

func TestRefreshToken_EmptyToken(t *testing.T) {
	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	_, err := handler.refreshToken(context.Background(), nil)
	if err == nil {
		t.Error("Expected error for empty refresh token")
	}
}

func TestExchangeToken_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"server_error","error_description":"Internal server error"}`))
	}))
	defer server.Close()

	config := &Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	_, err := handler.authenticateClientCredentials(context.Background())
	if err == nil {
		t.Error("Expected error for server error")
	}
}

func TestExchangeToken_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	config := &Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	_, err := handler.authenticateClientCredentials(context.Background())
	if err == nil {
		t.Error("Expected error for malformed JSON")
	}
}

func TestExchangeToken_NoAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"token_type": "Bearer",
			"expires_in": 3600,
			// Missing access_token
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := &Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	_, err := handler.authenticateClientCredentials(context.Background())
	if err == nil {
		t.Error("Expected error for missing access token")
	}
}

func TestBuildAuthURL_Complete(t *testing.T) {
	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	// Test with PKCE
	authURL, err := handler.buildAuthURL("random-state", "test-challenge", nil)
	if err != nil {
		t.Fatalf("buildAuthURL() failed: %v", err)
	}

	if !contains(authURL, "client_id=test-client") {
		t.Error("Auth URL missing client_id")
	}

	if !contains(authURL, "redirect_uri=") {
		t.Error("Auth URL missing redirect_uri")
	}

	if !contains(authURL, "response_type=code") {
		t.Error("Auth URL missing response_type")
	}

	if !contains(authURL, "state=random-state") {
		t.Error("Auth URL missing state")
	}

	if !contains(authURL, "code_challenge=test-challenge") {
		t.Error("Auth URL missing code_challenge")
	}

	if !contains(authURL, "code_challenge_method=S256") {
		t.Error("Auth URL missing code_challenge_method")
	}

	if !contains(authURL, "scope=") {
		t.Error("Auth URL missing scope")
	}
}

func TestBuildAuthURL_WithAdditionalParams(t *testing.T) {
	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
		RedirectURL:  "http://localhost:8080/callback",
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	additionalParams := map[string]string{
		"prompt":                 "consent",
		"access_type":            "offline",
		"include_granted_scopes": "true",
	}

	authURL, err := handler.buildAuthURL("random-state", "", additionalParams)
	if err != nil {
		t.Fatalf("buildAuthURL() failed: %v", err)
	}

	if !contains(authURL, "prompt=consent") {
		t.Error("Auth URL missing prompt parameter")
	}

	if !contains(authURL, "access_type=offline") {
		t.Error("Auth URL missing access_type parameter")
	}

	if !contains(authURL, "include_granted_scopes=true") {
		t.Error("Auth URL missing include_granted_scopes parameter")
	}
}

func TestFlowHandler_BuildAuthURL_WithoutPKCE(t *testing.T) {
	config := &Config{
		Provider:     Google(),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
		RedirectURL:  "http://localhost:8080/callback",
	}

	httpClient := newDefaultHTTPClient(30*time.Second, nil, false)
	handler := newFlowHandler(config, httpClient)

	authURL, err := handler.buildAuthURL("random-state", "", nil)
	if err != nil {
		t.Fatalf("buildAuthURL() failed: %v", err)
	}

	if contains(authURL, "code_challenge=") {
		t.Error("Auth URL should not have code_challenge without PKCE")
	}

	if contains(authURL, "code_challenge_method=") {
		t.Error("Auth URL should not have code_challenge_method without PKCE")
	}
}

// Helper function for creating test providers
func newTestProvider(authURL, tokenURL string) Provider {
	prov, _ := CustomProvider(ProviderConfig{
		ProviderName:  "test",
		AuthEndpoint:  authURL,
		TokenEndpoint: tokenURL,
	})
	return prov
}
