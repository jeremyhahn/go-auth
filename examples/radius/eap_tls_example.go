//go:build ignore

// Package main demonstrates RADIUS EAP-TLS authentication.
//
// This example shows how to:
// - Configure RADIUS for EAP-TLS authentication
// - Use client certificates for authentication
// - Handle TLS configuration
// - Handle errors properly
//
// Usage:
//
//	go run eap_tls_example.go
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/radius"
)

func main() {
	fmt.Println("==> RADIUS EAP-TLS Authentication Example")
	fmt.Println()

	// Load client certificate and key for EAP-TLS
	cert, err := tls.LoadX509KeyPair(
		"/path/to/client-cert.pem",
		"/path/to/client-key.pem",
	)
	if err != nil {
		log.Printf("Failed to load client certificate: %v", err)
		fmt.Println()
		fmt.Println("Note: Update the paths to your client certificate and key files")
		fmt.Println("To generate test certificates, you can use:")
		fmt.Println("  openssl req -new -x509 -days 365 -nodes \\")
		fmt.Println("    -out client-cert.pem -keyout client-key.pem")
		return
	}

	// Configure EAP-TLS
	eapTLSConfig := &radius.EAPTLSConfig{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			// For production, configure proper CA validation:
			// RootCAs:      caCertPool,
			// For testing only:
			InsecureSkipVerify: true,
		},
		Identity: "user@example.com",
	}

	// Create RADIUS authenticator with EAP-TLS
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
		radius.WithEAPTLS(eapTLSConfig),
		radius.WithDialTimeout(5*time.Second),
		radius.WithRetry(3*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create RADIUS authenticator: %v", err)
	}
	defer auth.Close()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("Authenticating with EAP-TLS\n")
	fmt.Printf("Identity: %s\n", eapTLSConfig.Identity)
	fmt.Printf("RADIUS server: radius.example.com:1812\n")
	fmt.Println()

	// Perform EAP-TLS authentication
	// The username parameter is used as the EAP identity
	// The certificate is the credential, so the password is nil
	err = auth.Authenticate(ctx, eapTLSConfig.Identity, nil)
	if err != nil {
		if errors.Is(err, radius.ErrRejected) {
			log.Printf("Access rejected by RADIUS server")
		} else {
			log.Printf("Authentication failed: %v", err)
		}
		fmt.Println()
		fmt.Println("Note: This example requires:")
		fmt.Println("  1. A RADIUS server with EAP-TLS support")
		fmt.Println("  2. Valid client certificate trusted by the RADIUS server")
		fmt.Println("  3. Proper TLS configuration on both sides")
		return
	}

	fmt.Println("✓ Authentication successful!")
	fmt.Println()
	fmt.Println("EAP-TLS authentication completed using client certificate.")
	fmt.Println()
	fmt.Println("Benefits of EAP-TLS:")
	fmt.Println("  - Mutual authentication (server and client)")
	fmt.Println("  - No password transmission")
	fmt.Println("  - Strong cryptographic security")
	fmt.Println("  - Suitable for enterprise Wi-Fi (802.1X)")
}
