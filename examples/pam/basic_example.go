// Package main demonstrates PAM authentication.
//
// This example shows how to:
// - Configure the PAM authenticator
// - Perform username/password authentication
// - Handle errors properly
//
// Usage:
//   go run basic_example.go
//
// Note: This example requires PAM libraries to be installed and the binary
// must be built with CGO enabled (CGO_ENABLED=1).
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jeremyhahn/go-auth/pkg/pam"
)

func main() {
	fmt.Println("==> PAM Authentication Example")
	fmt.Println()

	// Create PAM authenticator for the "login" service
	// Common PAM service names: "login", "passwd", "sshd", "sudo"
	// The service name determines which PAM configuration file is used
	// (typically in /etc/pam.d/)
	auth, err := pam.NewAuthenticator("login", nil)
	if err != nil {
		log.Fatalf("Failed to create PAM authenticator: %v", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Example credentials (replace with actual values for testing)
	username := "testuser"
	password := "testpass"

	fmt.Printf("Authenticating user: %s\n", username)

	// Perform authentication
	// PAM will check the credentials against the system's authentication stack
	err = auth.Authenticate(ctx, username, password)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		fmt.Println("\nNote: This example requires:")
		fmt.Println("  1. PAM libraries installed (libpam-dev on Debian/Ubuntu)")
		fmt.Println("  2. CGO enabled: CGO_ENABLED=1 go build")
		fmt.Println("  3. Valid system user credentials")
		fmt.Println("  4. Appropriate permissions to access PAM")
		return
	}

	fmt.Println("✓ Authentication successful!")
	fmt.Println()
	fmt.Println("The user has been validated against the system PAM stack.")
}
