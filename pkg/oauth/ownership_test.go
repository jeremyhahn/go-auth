package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"
)

// newFormRecordingTokenEndpoint returns a token endpoint that records the last
// form it received and answers with response.
func newFormRecordingTokenEndpoint(t *testing.T, response string) (*httptest.Server, *url.Values) {
	t.Helper()

	form := &url.Values{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		*form = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)
	return server, form
}

func TestNewAuthenticatorOwnsTheClientSecret(t *testing.T) {
	server, _ := newFormRecordingTokenEndpoint(t, `{"access_token":"a"}`)
	clientSecret := sealedForTest(t, "client-secret")

	auth, err := NewAuthenticator(&Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "client",
		ClientSecret: clientSecret,
		Flow:         FlowClientCredentials,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	if !clientSecret.IsAlive() {
		t.Fatal("NewAuthenticator destroyed the client secret it is meant to hold")
	}

	if err := auth.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if clientSecret.IsAlive() {
		t.Error("Close did not destroy the client secret")
	}

	// After Close a request fails closed instead of going out without the
	// client secret.
	if _, err := auth.AuthenticateClientCredentials(context.Background()); !errors.Is(err, ErrCredentialUnavailable) {
		t.Errorf("AuthenticateClientCredentials() after Close = %v, want ErrCredentialUnavailable", err)
	}
}

func TestNewAuthenticatorDestroysTheClientSecretOnError(t *testing.T) {
	cases := map[string]*Config{
		"invalid config": {
			Provider: Google(),
			Flow:     "invalid",
			ClientID: "client",
		},
		"malformed jwks url": {
			Provider: Google(),
			Flow:     FlowTokenValidation,
			ClientID: "client",
			Validation: TokenValidationConfig{
				Method:  ValidationJWT,
				JWKSURL: "http://[::1",
			},
		},
	}

	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			clientSecret := sealedForTest(t, "client-secret")
			config.ClientSecret = clientSecret

			if _, err := NewAuthenticator(config); err == nil {
				t.Fatal("NewAuthenticator() succeeded on a config it should reject")
			}
			if clientSecret.IsAlive() {
				t.Error("NewAuthenticator returned an error but left the client secret alive")
			}
		})
	}
}

func TestConfigValidateRequiresALiveClientSecret(t *testing.T) {
	destroyed := sealedForTest(t, "client-secret")
	destroyed.Destroy()

	for _, flow := range []FlowType{FlowClientCredentials, FlowPassword} {
		config := &Config{
			Provider:     newTestProvider("https://idp.example/auth", "https://idp.example/token"),
			ClientID:     "client",
			ClientSecret: destroyed,
			Flow:         flow,
		}
		if err := config.Validate(); !errors.Is(err, ErrInvalidConfiguration) {
			t.Errorf("Validate(%s with a destroyed secret) = %v, want ErrInvalidConfiguration", flow, err)
		}
	}
}

func TestClientCredentialsSendsTheSecretFromItsEnclave(t *testing.T) {
	server, form := newFormRecordingTokenEndpoint(t, `{"access_token":"cc-token","expires_in":60}`)

	auth, err := NewAuthenticator(&Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "client",
		ClientSecret: sealedForTest(t, "s3cret+/= value"),
		Flow:         FlowClientCredentials,
		Scopes:       []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	token, err := auth.AuthenticateClientCredentials(context.Background())
	if err != nil {
		t.Fatalf("AuthenticateClientCredentials() failed: %v", err)
	}
	defer token.Destroy()

	if got := form.Get("client_secret"); got != "s3cret+/= value" {
		t.Errorf("client_secret = %q, want the configured secret", got)
	}
	if form.Get("grant_type") != "client_credentials" || form.Get("scope") != "read write" {
		t.Errorf("form = %v", *form)
	}
	if got := openedForTest(t, token.AccessToken()); got != "cc-token" {
		t.Errorf("AccessToken() = %q, want cc-token", got)
	}
}

func TestRefreshTokenBorrowsTheRefreshToken(t *testing.T) {
	server, form := newFormRecordingTokenEndpoint(t, `{"access_token":"new-access","refresh_token":"new-refresh"}`)

	auth, err := NewAuthenticator(&Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "client",
		ClientSecret: sealedForTest(t, "client-secret"),
		Flow:         FlowAuthorizationCode,
		RedirectURL:  "http://localhost/callback",
	})
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	old := &Token{accessToken: sealedForTest(t, "old-access"), refreshToken: sealedForTest(t, "old-refresh")}

	next, err := auth.RefreshToken(context.Background(), old.RefreshToken())
	if err != nil {
		t.Fatalf("RefreshToken() failed: %v", err)
	}
	defer next.Destroy()

	if !old.RefreshToken().IsAlive() {
		t.Error("RefreshToken destroyed the refresh token it borrowed")
	}
	if form.Get("refresh_token") != "old-refresh" || form.Get("client_secret") != "client-secret" {
		t.Errorf("form = %v, want the old refresh token and the client secret", *form)
	}
	if openedForTest(t, next.AccessToken()) != "new-access" || openedForTest(t, next.RefreshToken()) != "new-refresh" {
		t.Error("the refreshed Token does not hold the new credentials")
	}

	old.Destroy()
	if _, err := auth.RefreshToken(context.Background(), old.RefreshToken()); !errors.Is(err, ErrTokenExchangeFailed) {
		t.Errorf("RefreshToken(destroyed) = %v, want ErrTokenExchangeFailed", err)
	}
}

func TestAuthenticatePasswordBorrowsThePassword(t *testing.T) {
	server, form := newFormRecordingTokenEndpoint(t, `{"access_token":"pw-access"}`)

	auth, err := NewAuthenticator(&Config{
		Provider:     newTestProvider(server.URL+"/auth", server.URL+"/token"),
		ClientID:     "client",
		ClientSecret: sealedForTest(t, "client-secret"),
		Flow:         FlowPassword,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	password := sealedForTest(t, "p@ss word&")
	token, err := auth.AuthenticatePassword(context.Background(), "alice", password)
	if err != nil {
		t.Fatalf("AuthenticatePassword() failed: %v", err)
	}
	defer token.Destroy()

	if !password.IsAlive() {
		t.Error("AuthenticatePassword destroyed the password it borrowed")
	}
	if form.Get("password") != "p@ss word&" || form.Get("username") != "alice" {
		t.Errorf("form = %v", *form)
	}
}

func TestParseTokenResponse(t *testing.T) {
	token, err := parseTokenResponse([]byte(`{
		"access_token": "acc\/ess",
		"refresh_token": "refresh",
		"id_token": "id",
		"token_type": "",
		"expires_in": 60,
		"scope": "a b"
	}`))
	if err != nil {
		t.Fatalf("parseTokenResponse() failed: %v", err)
	}
	defer token.Destroy()

	if got := openedForTest(t, token.AccessToken()); got != "acc/ess" {
		t.Errorf("AccessToken() = %q", got)
	}
	if got := openedForTest(t, token.RefreshToken()); got != "refresh" {
		t.Errorf("RefreshToken() = %q", got)
	}
	if got := openedForTest(t, token.IDToken()); got != "id" {
		t.Errorf("IDToken() = %q", got)
	}
	if token.TokenType != "Bearer" || len(token.Scopes) != 2 || token.ExpiresIn() <= 0 || token.ExpiresIn() > time.Minute {
		t.Errorf("plain fields = %q %v %v", token.TokenType, token.Scopes, token.ExpiresIn())
	}

	// Optional credentials that are absent stay nil.
	bare, err := parseTokenResponse([]byte(`{"access_token":"only"}`))
	if err != nil {
		t.Fatalf("parseTokenResponse() failed: %v", err)
	}
	defer bare.Destroy()
	if bare.RefreshToken() != nil || bare.IDToken() != nil {
		t.Error("absent refresh and ID tokens were sealed")
	}
}

func TestParseTokenResponseRejects(t *testing.T) {
	cases := map[string]string{
		"no access token":         `{"refresh_token":"r"}`,
		"empty access token":      `{"access_token":""}`,
		"non-string access token": `{"access_token":42}`,
		"non-string id token":     `{"access_token":"a","id_token":{"x":1}}`,
		"not json":                `access_token=a`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if token, err := parseTokenResponse([]byte(body)); !errors.Is(err, ErrTokenExchangeFailed) {
				t.Errorf("parseTokenResponse(%s) = %v, %v; want ErrTokenExchangeFailed", body, token, err)
			}
		})
	}
}

func TestValidateTokenBorrowsTheToken(t *testing.T) {
	introspection := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		id, secret, ok := r.BasicAuth()
		active := ok && id == "client" && secret == "client-secret" && r.PostForm.Get("token") == "opaque token+/"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active": active, "sub": "user-1"})
	}))
	defer introspection.Close()

	auth, err := NewAuthenticator(&Config{
		Provider:     Google(),
		ClientID:     "client",
		ClientSecret: sealedForTest(t, "client-secret"),
		Flow:         FlowTokenValidation,
		Validation: TokenValidationConfig{
			Method:           ValidationIntrospection,
			IntrospectionURL: introspection.URL,
		},
		Cache: CacheConfig{Enabled: true, MaxSize: 10, TTL: time.Minute},
	})
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	bearer := sealedForTest(t, "opaque token+/")
	claims, err := auth.ValidateToken(context.Background(), bearer)
	if err != nil {
		t.Fatalf("ValidateToken() failed: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", claims.Subject)
	}
	if !bearer.IsAlive() {
		t.Error("ValidateToken destroyed the token it borrowed")
	}

	// The claims were cached in an enclave under the token's fingerprint.
	key, err := tokenFingerprint(bearer)
	if err != nil {
		t.Fatalf("tokenFingerprint() failed: %v", err)
	}
	cached := sealedEntry(auth.cache.(*lruCache), key)
	if !cached.IsAlive() {
		t.Fatal("validated claims were not cached in a live enclave")
	}

	if err := auth.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if cached.IsAlive() {
		t.Error("Close did not destroy the cached claims")
	}
}

func TestValidateTokenRejectsAMissingToken(t *testing.T) {
	auth := &Authenticator{config: &Config{}, cache: &noopCache{}}

	destroyed := sealedForTest(t, "gone")
	destroyed.Destroy()

	for name, token := range map[string]*enclave.MemoryEnclave{
		"nil":        nil,
		"destroyed":  destroyed,
		"whitespace": sealedForTest(t, " \t\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := auth.ValidateToken(context.Background(), token); !errors.Is(err, ErrMissingToken) {
				t.Errorf("ValidateToken(%s) = %v, want ErrMissingToken", name, err)
			}
		})
	}
}

func TestAuthenticateRefusesMissingToken(t *testing.T) {
	auth := &Authenticator{config: &Config{}, cache: &noopCache{}}
	destroyed := sealedForTest(t, "token")
	destroyed.Destroy()
	for name, token := range map[string]*enclave.MemoryEnclave{
		"nil":       nil,
		"destroyed": destroyed,
		"blank":     sealedForTest(t, "   "),
	} {
		if err := auth.Authenticate(context.Background(), "ignored", token); !errors.Is(err, ErrMissingToken) {
			t.Errorf("Authenticate(%s) = %v, want ErrMissingToken", name, err)
		}
	}
}
