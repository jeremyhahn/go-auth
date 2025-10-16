// Package main demonstrates OAuth 2.0 client credentials flow.
//
// This example shows how to:
// - Configure OAuth for client credentials flow
// - Authenticate machine-to-machine (M2M) applications
// - Request access tokens with specific scopes
// - Handle token refresh
//
// Usage:
//   go run client_credentials_example.go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jhahn/go-auth/pkg/oauth"
)

func main() {
	fmt.Println("==> OAuth 2.0 Client Credentials Flow Example")
	fmt.Println()

	// Example 1: Keycloak client credentials
	keycloakExample()

	fmt.Println()

	// Example 2: Auth0 client credentials
	auth0Example()
}

func keycloakExample() {
	fmt.Println("--- Example 1: Keycloak Client Credentials ---")

	// Configure OAuth for Keycloak client credentials flow
	// This is used for service-to-service authentication
	// No user interaction is required
	config := &oauth.Config{
		Provider:     oauth.Keycloak("https://keycloak.example.com", "master"),
		Flow:         oauth.FlowClientCredentials,
		ClientID:     "service-account",
		ClientSecret: "your-client-secret",
		// Request specific scopes your service needs
		Scopes: []string{"api.read", "api.write"},
	}

	auth, err := oauth.NewAuthenticator(config)
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}
	defer auth.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("Requesting access token from Keycloak...")
	fmt.Printf("Client ID: %s\n", config.ClientID)
	fmt.Printf("Scopes: %v\n", config.Scopes)
	fmt.Println()

	// Authenticate and get access token
	// This makes a request to the token endpoint with client credentials
	token, err := auth.AuthenticateClientCredentials(ctx)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		fmt.Println()
		fmt.Println("Note: This example requires:")
		fmt.Println("  1. A Keycloak server configured and accessible")
		fmt.Println("  2. A service account (confidential client) created")
		fmt.Println("  3. Client ID and secret from Keycloak")
		fmt.Println()
		fmt.Println("To set up Keycloak:")
		fmt.Println("  1. Create a client with 'confidential' access type")
		fmt.Println("  2. Enable 'Service Accounts Enabled'")
		fmt.Println("  3. Configure service account roles")
		fmt.Println("  4. Get credentials from 'Credentials' tab")
		return
	}

	fmt.Println("✓ Access token obtained successfully!")
	fmt.Println()
	fmt.Printf("Access Token: %s...\n", token.AccessToken[:50]) // Show first 50 chars
	fmt.Printf("Token Type: %s\n", token.TokenType)
	fmt.Printf("Expires In: %v\n", time.Until(token.Expiry))
	if token.RefreshToken != "" {
		fmt.Printf("Refresh Token: %s...\n", token.RefreshToken[:30])
	}

	// Use the access token to call APIs
	fmt.Println()
	fmt.Println("You can now use this token to call protected APIs:")
	fmt.Println("  Authorization: Bearer <access_token>")
}

func auth0Example() {
	fmt.Println("--- Example 2: Auth0 Client Credentials ---")

	// Configure OAuth for Auth0 client credentials
	// Auth0 uses audience parameter to specify the target API
	config := &oauth.Config{
		Provider:     oauth.Auth0("myapp.us.auth0.com"),
		Flow:         oauth.FlowClientCredentials,
		ClientID:     "your-client-id",
		ClientSecret: "your-client-secret",
		// Audience identifies which API you're requesting access to
		// This is required for Auth0 client credentials flow
		Scopes: []string{"read:users", "write:users"},
	}

	auth, err := oauth.NewAuthenticator(config)
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}
	defer auth.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("Requesting access token from Auth0...")
	fmt.Printf("Domain: myapp.us.auth0.com\n")
	fmt.Printf("Client ID: %s\n", config.ClientID)
	fmt.Println()

	token, err := auth.AuthenticateClientCredentials(ctx)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		fmt.Println()
		fmt.Println("To set up Auth0:")
		fmt.Println("  1. Create a Machine to Machine Application")
		fmt.Println("  2. Authorize it for your API")
		fmt.Println("  3. Copy Client ID and Secret")
		fmt.Println("  4. Configure API identifier as audience")
		return
	}

	fmt.Println("✓ Access token obtained successfully!")
	fmt.Println()
	fmt.Printf("Access Token: %s...\n", token.AccessToken[:50])
	fmt.Printf("Token Type: %s\n", token.TokenType)
	fmt.Printf("Expires In: %v\n", time.Until(token.Expiry))
	fmt.Println()
	fmt.Println("Client credentials flow benefits:")
	fmt.Println("  - No user interaction required")
	fmt.Println("  - Suitable for backend services and APIs")
	fmt.Println("  - Automatic token management")
	fmt.Println("  - Scope-based access control")
	fmt.Println("  - Standard OAuth 2.0 flow")
}
