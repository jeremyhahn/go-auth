package oauth_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jhahn/go-auth/pkg/oauth"
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

	// Validate token
	claims, err := auth.ValidateToken(context.Background(), "access-token")
	if err != nil {
		log.Printf("Token validation failed: %v", err)
		return
	}

	fmt.Printf("User: %s\n", claims.Subject)
}

func ExampleNewAuthenticator_clientCredentials() {
	config := &oauth.Config{
		Provider:     oauth.Keycloak("https://keycloak.example.com", "master"),
		Flow:         oauth.FlowClientCredentials,
		ClientID:     "service-account",
		ClientSecret: "secret",
		Scopes:       []string{"api.read", "api.write"},
	}

	auth, err := oauth.NewAuthenticator(config)
	if err != nil {
		log.Fatal(err)
	}

	token, err := auth.AuthenticateClientCredentials(context.Background())
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		return
	}

	fmt.Printf("Token Type: %s\n", token.TokenType)
}

func ExampleNewAuthenticator_password() {
	config := &oauth.Config{
		Provider:     oauth.Auth0("myapp.us.auth0.com"),
		Flow:         oauth.FlowPassword,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Scopes:       []string{"openid", "profile", "email"},
	}

	auth, err := oauth.NewAuthenticator(config)
	if err != nil {
		log.Fatal(err)
	}

	token, err := auth.AuthenticatePassword(context.Background(), "user@example.com", "password")
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		return
	}

	fmt.Printf("Access Token received: %v\n", token.AccessToken != "")
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

	// Generate authorization URL with PKCE
	state := "random-state-string"
	authURL, codeVerifier, err := auth.BuildAuthURL(state, true, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Authorization URL generated: %v\n", authURL != "")
	fmt.Printf("Code verifier generated: %v\n", codeVerifier != "")

	// After receiving callback with code:
	// token, err := auth.ExchangeAuthorizationCode(context.Background(), code, codeVerifier)
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
