//go:build ignore

// Package main demonstrates RADIUS PAP authentication.
//
// This example shows how to:
// - Configure the RADIUS authenticator
// - Perform PAP (Password Authentication Protocol) authentication
// - Handle errors properly
//
// Usage:
//
//	go run pap_example.go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/radius"
)

func main() {
	fmt.Println("==> RADIUS PAP Authentication Example")
	fmt.Println()

	// Create RADIUS authenticator
	// The address must include both host and port (typically 1812 for authentication)
	// The shared secret is used to encrypt the Access-Request packet
	// The shared secret travels in go-enclave locked memory. In production
	// build it with enclave.NewMemoryEnclave over a []byte read from a key
	// file or secrets manager, which wipes that slice.
	sharedSecret, err := enclave.NewMemoryEnclave([]byte("shared-secret"))
	if err != nil {
		log.Fatalf("Failed to seal the shared secret: %v", err)
	}
	// NewAuthenticator takes ownership of sharedSecret — it destroys it on
	// error — and auth.Close destroys it otherwise.
	auth, err := radius.NewAuthenticator(
		"radius.example.com:1812",
		sharedSecret,
		radius.WithDialTimeout(5*time.Second),
		radius.WithRetry(3*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create RADIUS authenticator: %v", err)
	}
	defer auth.Close()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Example credentials
	username := "testuser"
	password, err := enclave.NewMemoryEnclave([]byte("testpass"))
	if err != nil {
		log.Fatalf("Failed to seal the password: %v", err)
	}
	// Authenticate borrows the password; the caller destroys it.
	defer password.Destroy()

	fmt.Printf("Authenticating user: %s\n", username)
	fmt.Printf("RADIUS server: radius.example.com:1812\n")
	fmt.Println()

	// Perform authentication
	// The authenticator sends an Access-Request packet with the username and password
	// The RADIUS server responds with Access-Accept or Access-Reject
	err = auth.Authenticate(ctx, username, password)
	if err != nil {
		if errors.Is(err, radius.ErrRejected) {
			log.Printf("Access rejected by RADIUS server")
		} else {
			log.Printf("Authentication failed: %v", err)
		}
		fmt.Println()
		fmt.Println("Note: This example requires:")
		fmt.Println("  1. A RADIUS server configured and accessible")
		fmt.Println("  2. Shared secret matching the server configuration")
		fmt.Println("  3. Valid user credentials in the RADIUS database")
		return
	}

	fmt.Println("✓ Authentication successful!")
	fmt.Println()
	fmt.Println("The RADIUS server accepted the credentials.")
	fmt.Println()
	fmt.Println("Additional RADIUS options:")
	fmt.Println("  - Use WithNetwork() to specify UDP transport")
	fmt.Println("  - Use WithMaxPacketErrors() to handle malformed responses")
	fmt.Println("  - See eap_tls_example.go for EAP-TLS authentication")
}
