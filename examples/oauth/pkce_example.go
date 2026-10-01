//go:build ignore

// Package main demonstrates OAuth 2.0 authorization code flow with PKCE.
//
// This example shows how to:
// - Configure OAuth for authorization code flow
// - Generate PKCE challenge and verifier
// - Build authorization URL
// - Exchange authorization code for tokens
// - Handle the OAuth callback
//
// Usage:
//
//	go run pkce_example.go
package main

import (
	"fmt"
	"log"

	"github.com/jeremyhahn/go-auth/pkg/oauth"
)

func main() {
	fmt.Println("==> OAuth 2.0 Authorization Code with PKCE Example")
	fmt.Println()

	// PKCE (Proof Key for Code Exchange) is a security extension for OAuth 2.0
	// It's required for public clients (mobile apps, SPAs) and recommended for all clients
	// PKCE prevents authorization code interception attacks

	// Example 1: Microsoft authorization code with PKCE
	microsoftExample()

	fmt.Println()

	// Example 2: Google authorization code with PKCE
	googleExample()
}

func microsoftExample() {
	fmt.Println("--- Example 1: Microsoft OAuth with PKCE ---")

	// Configure OAuth for Microsoft (Azure AD)
	config := &oauth.Config{
		Provider:    oauth.Microsoft(),
		Flow:        oauth.FlowAuthorizationCode,
		ClientID:    "your-client-id",
		RedirectURL: "http://localhost:8080/callback",
		Scopes:      []string{"openid", "profile", "email", "User.Read"},
	}

	auth, err := oauth.NewAuthenticator(config)
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Generate CSRF state token
	// In production, store this in session and validate in callback
	state := "random-state-for-csrf-protection"

	// Build authorization URL with PKCE. The verifier comes back in protected
	// memory; keep it against the state until the callback arrives.
	// The second parameter allows additional query parameters.
	authURL, verifier, err := auth.BuildAuthURLPKCE(state, map[string]string{
		"prompt": "consent", // Force consent screen
	})
	if err != nil {
		log.Fatalf("Failed to build auth URL: %v", err)
	}
	defer verifier.Destroy() // no-op once the exchange has consumed it

	fmt.Println("Authorization URL generated with PKCE:")
	fmt.Printf("%s\n", authURL)
	fmt.Println()
	// The verifier is deliberately not printed: it is a bearer credential for
	// the length of the flow, and printing it undoes the point of holding it in
	// protected memory. %v renders it as a redaction anyway.
	fmt.Printf("Code verifier (held in protected memory): %v\n", verifier)
	fmt.Println()
	fmt.Println("OAuth Flow Steps:")
	fmt.Println("  1. Redirect user to the authorization URL")
	fmt.Println("  2. User authenticates with Microsoft")
	fmt.Println("  3. User grants consent to requested scopes")
	fmt.Println("  4. Microsoft redirects to your callback URL with code")
	fmt.Println("  5. Exchange code for tokens using ExchangeAuthorizationCodePKCE()")
	fmt.Println()

	// After user authenticates and you receive the callback:
	// The callback URL will be: http://localhost:8080/callback?code=...&state=...
	//
	// Example callback handler:
	//
	// func callbackHandler(w http.ResponseWriter, r *http.Request) {
	//     code := r.URL.Query().Get("code")
	//     receivedState := r.URL.Query().Get("state")
	//
	//     // Validate state to prevent CSRF
	//     if receivedState != state {
	//         http.Error(w, "Invalid state", http.StatusBadRequest)
	//         return
	//     }
	//
	//     ctx := context.Background()
	//     token, err := auth.ExchangeAuthorizationCodePKCE(ctx, code, verifier)
	//     if err != nil {
	//         http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
	//         return
	//     }
	//
	//     defer token.Destroy()
	//
	//     // token.AccessToken(), IDToken() and RefreshToken() lend enclaves;
	//     // read one only inside WithBytes, at the point you use it
	// }

	fmt.Println("Example code exchange (after receiving callback):")
	fmt.Println()
	fmt.Println("  ctx := context.Background()")
	fmt.Println("  code := \"authorization-code-from-callback\"")
	fmt.Println("  token, err := auth.ExchangeAuthorizationCodePKCE(ctx, code, verifier)")
	fmt.Println("  if err != nil {")
	fmt.Println("      log.Fatal(err)")
	fmt.Println("  }")
	fmt.Println("  defer token.Destroy()")
	fmt.Println("  // token.AccessToken(), token.IDToken(), token.RefreshToken() lend")
	fmt.Println("  // enclaves: read them only inside WithBytes")
}

func googleExample() {
	fmt.Println("--- Example 2: Google OAuth with PKCE ---")

	// Configure OAuth for Google
	config := &oauth.Config{
		Provider:    oauth.Google(),
		Flow:        oauth.FlowAuthorizationCode,
		ClientID:    "your-google-client-id.apps.googleusercontent.com",
		RedirectURL: "http://localhost:8080/callback",
		Scopes:      []string{"openid", "profile", "email"},
	}

	auth, err := oauth.NewAuthenticator(config)
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}
	defer auth.Close()

	state := "random-state-for-csrf-protection"

	// Build authorization URL with PKCE
	authURL, verifier, err := auth.BuildAuthURLPKCE(state, map[string]string{
		"access_type": "offline", // Request refresh token
		"prompt":      "consent", // Force consent to get refresh token
	})
	if err != nil {
		log.Fatalf("Failed to build auth URL: %v", err)
	}
	defer verifier.Destroy()

	fmt.Println("Google Sign-In URL with PKCE:")
	fmt.Printf("%s\n", authURL)
	fmt.Println()
	fmt.Printf("Code verifier (held in protected memory): %v\n", verifier)
	fmt.Println()
	fmt.Println("Additional Google-specific parameters:")
	fmt.Println("  - access_type=offline: Request refresh token")
	fmt.Println("  - prompt=consent: Force consent screen")
	fmt.Println("  - prompt=select_account: Allow account selection")
	fmt.Println()
	fmt.Println("PKCE security benefits:")
	fmt.Println("  - Prevents authorization code interception")
	fmt.Println("  - No client secret needed (safe for public clients)")
	fmt.Println("  - Cryptographic proof of code ownership")
	fmt.Println("  - Required for mobile apps and SPAs")
	fmt.Println("  - Recommended for all OAuth 2.0 clients")
	fmt.Println()
	fmt.Println("To implement full OAuth flow:")
	fmt.Println("  1. Generate the state, and hold the verifier in process against it")
	fmt.Println("  2. Redirect user to authURL")
	fmt.Println("  3. Implement callback handler at redirect URL")
	fmt.Println("  4. Validate state matches")
	fmt.Println("  5. Exchange code for tokens using the held verifier")
	fmt.Println("  6. Store tokens securely (encrypted, HTTP-only cookies)")
	fmt.Println("  7. Use refresh token to get new access tokens")
}
