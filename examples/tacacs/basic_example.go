// Package main demonstrates TACACS+ authentication.
//
// This example shows how to:
// - Configure the TACACS+ authenticator
// - Perform username/password authentication
// - Handle privilege levels
// - Handle errors properly
//
// Usage:
//
//	go run basic_example.go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/tacacs"
)

func main() {
	fmt.Println("==> TACACS+ Authentication Example")
	fmt.Println()

	// Example 1: Basic TACACS+ authentication
	basicExample()

	fmt.Println()

	// Example 2: TACACS+ with custom privilege level
	privilegeLevelExample()
}

func basicExample() {
	fmt.Println("--- Example 1: Basic TACACS+ Authentication ---")

	// Create TACACS+ authenticator
	// The address must include both host and port (typically 49 for TACACS+)
	// The shared secret is used to encrypt communication with the server
	sharedSecret, err := enclave.NewMemoryEnclaveFromString("shared-secret")
	if err != nil {
		log.Fatalf("Failed to seal the shared secret: %v", err)
	}
	// NewAuthenticator takes ownership of sharedSecret — it destroys it on
	// error — and auth.Close destroys it otherwise.
	auth, err := tacacs.NewAuthenticator(
		"tacacs.example.com:49",
		sharedSecret,
		tacacs.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create TACACS+ authenticator: %v", err)
	}
	defer auth.Close()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Example credentials
	username := "admin"
	// The password travels in go-enclave locked memory. In production it
	// comes from enclave.NewMemoryEnclave over a []byte the reader fills,
	// which wipes that slice; a string literal is only for the example.
	password, err := enclave.NewMemoryEnclaveFromString("adminpass")
	if err != nil {
		log.Fatalf("Failed to seal the password: %v", err)
	}
	defer password.Destroy()

	fmt.Printf("Authenticating user: %s\n", username)
	fmt.Printf("TACACS+ server: tacacs.example.com:49\n")

	// Perform authentication
	err = auth.Authenticate(ctx, username, password)
	if err != nil {
		if errors.Is(err, tacacs.ErrAuthenticationFailed) {
			log.Printf("Access denied by TACACS+ server")
		} else {
			log.Printf("Authentication failed: %v", err)
		}
		fmt.Println()
		fmt.Println("Note: This example requires:")
		fmt.Println("  1. A TACACS+ server configured and accessible")
		fmt.Println("  2. Shared secret matching the server configuration")
		fmt.Println("  3. Valid user credentials in the TACACS+ database")
		return
	}

	fmt.Println("✓ Authentication successful!")
}

func privilegeLevelExample() {
	fmt.Println("--- Example 2: TACACS+ with Privilege Level ---")

	// Create TACACS+ authenticator with custom privilege level
	// Privilege levels typically range from 0 (least privileged) to 15 (most privileged)
	// Common levels: 1 (normal user), 15 (admin/enable)
	sharedSecret, err := enclave.NewMemoryEnclaveFromString("shared-secret")
	if err != nil {
		log.Fatalf("Failed to seal the shared secret: %v", err)
	}
	// NewAuthenticator takes ownership of sharedSecret — it destroys it on
	// error — and auth.Close destroys it otherwise.
	auth, err := tacacs.NewAuthenticator(
		"tacacs.example.com:49",
		sharedSecret,
		tacacs.WithPrivLevel(15), // Request admin privilege level
		tacacs.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create TACACS+ authenticator: %v", err)
	}
	defer auth.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	username := "admin"
	// The password travels in go-enclave locked memory. In production it
	// comes from enclave.NewMemoryEnclave over a []byte the reader fills,
	// which wipes that slice; a string literal is only for the example.
	password, err := enclave.NewMemoryEnclaveFromString("adminpass")
	if err != nil {
		log.Fatalf("Failed to seal the password: %v", err)
	}
	defer password.Destroy()

	fmt.Printf("Authenticating user: %s (privilege level 15)\n", username)

	err = auth.Authenticate(ctx, username, password)
	if err != nil {
		if errors.Is(err, tacacs.ErrAuthenticationFailed) {
			log.Printf("Access denied - user may not have required privilege level")
		} else {
			log.Printf("Authentication failed: %v", err)
		}
		return
	}

	fmt.Println("✓ Authentication successful with admin privileges!")
	fmt.Println()
	fmt.Println("TACACS+ features:")
	fmt.Println("  - Encrypted communication (entire packet)")
	fmt.Println("  - Separates Authentication, Authorization, and Accounting (AAA)")
	fmt.Println("  - Granular command authorization")
	fmt.Println("  - Commonly used in enterprise network equipment")
}
