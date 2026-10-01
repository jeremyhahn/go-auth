// Package main demonstrates LDAP authentication.
//
// This example shows how to:
// - Configure the LDAP authenticator
// - Perform bind authentication
// - Use TLS for secure connections
// - Handle errors properly
//
// Usage:
//
//	go run basic_example.go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"

	ldapauth "github.com/jeremyhahn/go-auth/pkg/ldap"
)

func main() {
	fmt.Println("==> LDAP Authentication Example")
	fmt.Println()

	// Example 1: Basic LDAP authentication with simple bind
	basicExample()

	fmt.Println()

	// Example 2: LDAP with StartTLS
	startTLSExample()
}

func basicExample() {
	fmt.Println("--- Example 1: Basic LDAP Bind ---")

	// Create LDAP authenticator
	// The user DN template is used to construct the full DN from the username
	// %s is replaced with the username during authentication
	auth, err := ldapauth.NewAuthenticator(
		"ldap://ldap.example.com:389",
		ldapauth.WithUserDNTemplate("uid=%s,ou=users,dc=example,dc=com"),
		ldapauth.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create LDAP authenticator: %v", err)
	}
	defer auth.Close()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Example credentials
	username := "john.doe"
	// The password travels in go-enclave locked memory. In production it
	// comes from enclave.NewMemoryEnclave over a []byte the reader fills,
	// which wipes that slice; a string literal is only for the example.
	password, err := enclave.NewMemoryEnclaveFromString("secret123")
	if err != nil {
		log.Fatalf("Failed to seal the password: %v", err)
	}
	// Authenticate borrows it; the caller destroys it.
	defer password.Destroy()

	fmt.Printf("Authenticating user: %s\n", username)
	fmt.Printf("Full DN will be: uid=%s,ou=users,dc=example,dc=com\n", username)

	// Perform authentication
	err = auth.Authenticate(ctx, username, password)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		fmt.Println("Note: Update the LDAP server URL and DN template for your environment")
		return
	}

	fmt.Println("✓ Authentication successful!")
}

func startTLSExample() {
	fmt.Println("--- Example 2: LDAP with StartTLS ---")

	// Create LDAP authenticator with StartTLS enabled
	// StartTLS upgrades a plain LDAP connection to TLS
	auth, err := ldapauth.NewAuthenticator(
		"ldap://ldap.example.com:389",
		ldapauth.WithUserDNTemplate("uid=%s,ou=users,dc=example,dc=com"),
		ldapauth.WithStartTLS(),
		ldapauth.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create LDAP authenticator: %v", err)
	}
	defer auth.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	username := "jane.smith"
	// The password travels in go-enclave locked memory. In production it
	// comes from enclave.NewMemoryEnclave over a []byte the reader fills,
	// which wipes that slice; a string literal is only for the example.
	password, err := enclave.NewMemoryEnclaveFromString("secret456")
	if err != nil {
		log.Fatalf("Failed to seal the password: %v", err)
	}
	// Authenticate borrows it; the caller destroys it.
	defer password.Destroy()

	fmt.Printf("Authenticating user: %s with StartTLS\n", username)

	err = auth.Authenticate(ctx, username, password)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		fmt.Println("Note: Update the LDAP server URL and DN template for your environment")
		return
	}

	fmt.Println("✓ Authentication successful with StartTLS!")
	fmt.Println()
	fmt.Println("Additional LDAP options:")
	fmt.Println("  - Use ldaps:// URL for implicit TLS (port 636)")
	fmt.Println("  - Use WithServiceAccount(dn, password) for binding as a service account first;")
	fmt.Println("    the authenticator owns that password enclave and Close destroys it")
	fmt.Println("  - Use WithTLSConfig() to customize TLS settings")
}
