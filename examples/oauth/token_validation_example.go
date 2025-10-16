// Package main demonstrates OAuth 2.0 token validation.
//
// This example shows how to:
// - Configure OAuth for token validation
// - Validate JWT tokens using JWKS
// - Extract user claims from tokens
// - Use token caching for performance
//
// Usage:
//   go run token_validation_example.go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jhahn/go-auth/pkg/api"
	"github.com/jhahn/go-auth/pkg/oauth"
)

func main() {
	fmt.Println("==> OAuth 2.0 Token Validation Example")
	fmt.Println()

	// Example 1: Google token validation
	googleExample()

	fmt.Println()

	// Example 2: Integration with API package
	apiIntegrationExample()
}

func googleExample() {
	fmt.Println("--- Example 1: Google OAuth Token Validation ---")

	// Configure OAuth for Google token validation
	// This validates ID tokens issued by Google
	config := &oauth.Config{
		Provider: oauth.Google(),
		Flow:     oauth.FlowTokenValidation,
		ClientID: "your-google-client-id.apps.googleusercontent.com",
		Validation: oauth.TokenValidationConfig{
			Method:   oauth.ValidationJWT,
			JWKSURL:  "https://www.googleapis.com/oauth2/v3/certs",
			Issuer:   "https://accounts.google.com",
			Audience: "your-google-client-id.apps.googleusercontent.com",
		},
		// Enable caching to avoid repeated JWKS fetches
		Cache: oauth.CacheConfig{
			Enabled: true,
			MaxSize: 1000,
			TTL:     5 * time.Minute,
		},
	}

	auth, err := oauth.NewAuthenticator(config)
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	// Example token (this would be a real Google ID token from a client)
	// In a real application, you receive this from:
	//   1. Google Sign-In button on your frontend
	//   2. Mobile app Google authentication
	//   3. Server-to-server OAuth flow
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." // Truncated for example

	fmt.Println("Validating Google ID token...")

	// Validate the token
	// This will:
	//   1. Fetch the JWKS from Google (or use cached keys)
	//   2. Verify the token signature
	//   3. Validate issuer, audience, and expiration
	//   4. Extract claims
	claims, err := auth.ValidateToken(ctx, token)
	if err != nil {
		log.Printf("Token validation failed: %v", err)
		fmt.Println()
		fmt.Println("Note: This example requires:")
		fmt.Println("  1. A valid Google OAuth Client ID")
		fmt.Println("  2. A real ID token from Google Sign-In")
		fmt.Println()
		fmt.Println("To get started:")
		fmt.Println("  1. Create project: https://console.cloud.google.com")
		fmt.Println("  2. Enable Google Sign-In API")
		fmt.Println("  3. Create OAuth 2.0 credentials")
		fmt.Println("  4. Implement Google Sign-In on your frontend")
		fmt.Println("  5. Send the ID token to your backend for validation")
		return
	}

	// Access user information from claims
	fmt.Println("✓ Token validation successful!")
	fmt.Println()
	fmt.Printf("User ID: %s\n", claims.Subject)
	fmt.Printf("Email: %s\n", claims.Email)
	fmt.Printf("Name: %s\n", claims.Name)
	fmt.Printf("Email Verified: %v\n", claims.EmailVerified)
	fmt.Printf("Issued At: %s\n", claims.IssuedAt)
	fmt.Printf("Expires At: %s\n", claims.ExpiresAt)
}

func apiIntegrationExample() {
	fmt.Println("--- Example 2: Integration with API Package ---")

	// Create OAuth authenticator for token validation
	oauthConfig := &oauth.Config{
		Provider: oauth.Google(),
		Flow:     oauth.FlowTokenValidation,
		ClientID: "your-client-id",
		Validation: oauth.TokenValidationConfig{
			Method:  oauth.ValidationJWT,
			JWKSURL: "https://www.googleapis.com/oauth2/v3/certs",
		},
		Cache: oauth.CacheConfig{
			Enabled: true,
		},
	}

	oauthAuth, err := oauth.NewAuthenticator(oauthConfig)
	if err != nil {
		log.Fatalf("Failed to create OAuth authenticator: %v", err)
	}
	defer oauthAuth.Close()

	// Create API service with OAuth backend
	// This allows you to use OAuth validation in a multi-backend auth system
	service, err := api.NewService(api.Config{
		Backends: []api.Backend{
			{Name: api.BackendOAuth, Handler: api.OAuth(oauthAuth)},
		},
	})
	if err != nil {
		log.Fatalf("Failed to create service: %v", err)
	}

	ctx := context.Background()

	// Authenticate using the service
	// The token is passed in the Password field
	err = service.Login(ctx, api.LoginRequest{
		Backend:  api.BackendOAuth,
		Username: "",                   // Ignored for OAuth
		Password: "oauth-access-token", // Token passed as password
	})

	if err != nil {
		log.Printf("Authentication failed: %v", err)
		return
	}

	fmt.Println("✓ Authentication successful via API service!")
	fmt.Println()
	fmt.Println("Token validation features:")
	fmt.Println("  - No password storage required")
	fmt.Println("  - Cryptographic verification of token authenticity")
	fmt.Println("  - Claims-based access control")
	fmt.Println("  - Automatic key rotation via JWKS")
	fmt.Println("  - Performance optimization with caching")
}
