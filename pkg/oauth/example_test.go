package oauth_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/oauth"
)

func ExampleNewAuthenticator_tokenValidation() {
	config := &oauth.Config{
		Provider: oauth.Google(),
		Flow:     oauth.FlowTokenValidation,
		ClientID: "your-client-id",
		Validation: oauth.TokenValidationConfig{
			Method:   oauth.ValidationJWT,
			JWKSURL:  "https://www.googleapis.com/oauth2/v3/certs",
			Issuer:   "https://accounts.google.com",
			Audience: "your-client-id",
		},
		Cache: oauth.CacheConfig{
			Enabled: true,
			MaxSize: 1000,
			TTL:     5 * time.Minute,
		},
	}

	auth, err := oauth.NewAuthenticator(config)
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	// Seal the bearer token from the inbound request as soon as it is read.
	// ValidateToken borrows it; destroy it once the request is done.
	bearer, err := enclave.NewMemoryEnclave([]byte("access-token"))
	if err != nil {
		log.Fatal(err)
	}
	defer bearer.Destroy()

	claims, err := auth.ValidateToken(context.Background(), bearer)
	if err != nil {
		log.Printf("Token validation failed: %v", err)
		return
	}

	fmt.Printf("User: %s\n", claims.Subject)
}

func ExampleNewAuthenticator_clientCredentials() {
	// NewMemoryEnclave wipes the slice it is given. NewAuthenticator then owns
	// the enclave and Close destroys it.
	clientSecret, err := enclave.NewMemoryEnclave([]byte("secret"))
	if err != nil {
		log.Fatal(err)
	}

	config := &oauth.Config{
		Provider:     oauth.Keycloak("https://keycloak.example.com", "master"),
		Flow:         oauth.FlowClientCredentials,
		ClientID:     "service-account",
		ClientSecret: clientSecret,
		Scopes:       []string{"api.read", "api.write"},
	}

	auth, err := oauth.NewAuthenticator(config)
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	token, err := auth.AuthenticateClientCredentials(context.Background())
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		return
	}
	defer token.Destroy()

	fmt.Printf("Token Type: %s\n", token.TokenType)
}

func ExampleNewAuthenticator_password() {
	clientSecret, err := enclave.NewMemoryEnclave([]byte("client-secret"))
	if err != nil {
		log.Fatal(err)
	}

	config := &oauth.Config{
		Provider:     oauth.Auth0("myapp.us.auth0.com"),
		Flow:         oauth.FlowPassword,
		ClientID:     "client-id",
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile", "email"},
	}

	auth, err := oauth.NewAuthenticator(config)
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	password, err := enclave.NewMemoryEnclave([]byte("password"))
	if err != nil {
		log.Fatal(err)
	}
	defer password.Destroy()

	token, err := auth.AuthenticatePassword(context.Background(), "user@example.com", password)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		return
	}
	defer token.Destroy()

	fmt.Printf("Access Token received: %v\n", token.AccessToken().IsAlive())
}

func ExampleNewAuthenticator_authorizationCode() {
	config := &oauth.Config{
		Provider:    oauth.Microsoft(),
		Flow:        oauth.FlowAuthorizationCode,
		ClientID:    "client-id",
		RedirectURL: "http://localhost:8080/callback",
		Scopes:      []string{"openid", "profile", "email"},
	}

	auth, err := oauth.NewAuthenticator(config)
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	// Generate authorization URL with PKCE. The verifier is generated in
	// locked memory; keep it in-process, keyed by state.
	state := "random-state-string"
	authURL, verifier, err := auth.BuildAuthURLPKCE(state, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer verifier.Destroy() // no-op once the exchange has consumed it

	fmt.Printf("Authorization URL generated: %v\n", authURL != "")
	fmt.Printf("Code verifier generated: %v\n", verifier.Size() > 0)

	// After receiving callback with code:
	// token, err := auth.ExchangeAuthorizationCodePKCE(ctx, code, verifier)
}

func ExampleAuthenticator_RefreshToken() {
	clientSecret, err := enclave.NewMemoryEnclave([]byte("client-secret"))
	if err != nil {
		log.Fatal(err)
	}

	auth, err := oauth.NewAuthenticator(&oauth.Config{
		Provider:     oauth.Google(),
		Flow:         oauth.FlowAuthorizationCode,
		ClientID:     "client-id",
		ClientSecret: clientSecret,
		RedirectURL:  "http://localhost:8080/callback",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	var current *oauth.Token // from an earlier exchange

	// RefreshToken borrows the old Token's refresh token, so the old Token is
	// destroyed only after the call returns.
	next, err := auth.RefreshToken(context.Background(), current.RefreshToken())
	current.Destroy()
	if err != nil {
		log.Printf("Refresh failed: %v", err)
		return
	}
	defer next.Destroy()

	// Use the access token inside a borrow, at the caller's own HTTP boundary.
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	_ = next.AccessToken().WithBytes(func(access []byte) error {
		req.Header.Set("Authorization", "Bearer "+string(access))
		return nil
	})
}

func ExampleGoogle() {
	provider := oauth.Google()
	fmt.Println(provider.Name())
	// Output: google
}

func ExampleMicrosoft() {
	provider := oauth.Microsoft()
	fmt.Println(provider.Name())
	// Output: microsoft
}

func ExampleGitHub() {
	provider := oauth.GitHub()
	fmt.Println(provider.Name())
	// Output: github
}

func ExampleOkta() {
	provider := oauth.Okta("dev-12345.okta.com")
	fmt.Println(provider.Name())
	// Output: okta
}

func ExampleAuth0() {
	provider := oauth.Auth0("myapp.us.auth0.com")
	fmt.Println(provider.Name())
	// Output: auth0
}

func ExampleKeycloak() {
	provider := oauth.Keycloak("https://keycloak.example.com", "master")
	fmt.Println(provider.Name())
	// Output: keycloak
}
