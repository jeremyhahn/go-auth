// Package main demonstrates PKCS#11 smart card/HSM authentication.
//
// This example shows how to:
// - Configure the PKCS#11 authenticator
// - Authenticate with a PIN
// - Access hardware security modules or smart cards
// - Handle errors properly
//
// Usage:
//
//	go run basic_example.go
//
// Note: This example requires PKCS#11 libraries and a connected token/HSM.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jeremyhahn/go-auth/pkg/pkcs11"
)

func main() {
	fmt.Println("==> PKCS#11 Smart Card/HSM Authentication Example")
	fmt.Println()

	// Example 1: Authenticate using token label
	tokenLabelExample()

	fmt.Println()

	// Example 2: Authenticate using slot number
	slotExample()
}

func tokenLabelExample() {
	fmt.Println("--- Example 1: Authenticate by Token Label ---")

	// Create PKCS#11 authenticator
	// ModulePath points to the PKCS#11 shared library (.so/.dll)
	// Common paths:
	//   - SoftHSM: /usr/lib/softhsm/libsofthsm2.so
	//   - OpenSC: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
	//   - YubiKey: /usr/local/lib/libykcs11.so
	cfg := pkcs11.Config{
		ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel: "MyToken",
	}

	auth, err := pkcs11.NewAuthenticator(cfg, nil)
	if err != nil {
		log.Fatalf("Failed to create PKCS#11 authenticator: %v", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// PIN for the token
	pin := "1234"

	fmt.Printf("Authenticating to token: %s\n", cfg.TokenLabel)
	fmt.Printf("Module path: %s\n", cfg.ModulePath)

	// Perform authentication
	err = auth.Authenticate(ctx, pin)
	if err != nil {
		if err == pkcs11.ErrInvalidPIN {
			log.Printf("Invalid PIN")
		} else {
			log.Printf("Authentication failed: %v", err)
		}
		fmt.Println()
		fmt.Println("Note: This example requires:")
		fmt.Println("  1. PKCS#11 library installed (e.g., SoftHSM, OpenSC)")
		fmt.Println("  2. A configured token/smart card")
		fmt.Println("  3. Correct module path for your PKCS#11 provider")
		fmt.Println("  4. Valid PIN for the token")
		fmt.Println()
		fmt.Println("To set up SoftHSM for testing:")
		fmt.Println("  1. Install: apt-get install softhsm2")
		fmt.Println("  2. Initialize: softhsm2-util --init-token --slot 0 --label MyToken")
		fmt.Println("  3. Set SO-PIN and user PIN when prompted")
		return
	}

	fmt.Println("✓ Authentication successful!")
	fmt.Println("PIN validated and logged into token.")
}

func slotExample() {
	fmt.Println("--- Example 2: Authenticate by Slot Number ---")

	// Authenticate using slot number instead of token label
	// Useful when you know the specific slot to use
	cfg := pkcs11.Config{
		ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
		Slot:       "0", // Slot ID as a string
	}

	auth, err := pkcs11.NewAuthenticator(cfg, nil)
	if err != nil {
		log.Fatalf("Failed to create PKCS#11 authenticator: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pin := "1234"

	fmt.Printf("Authenticating to slot: %s\n", cfg.Slot)

	err = auth.Authenticate(ctx, pin)
	if err != nil {
		if err == pkcs11.ErrInvalidPIN {
			log.Printf("Invalid PIN")
		} else {
			log.Printf("Authentication failed: %v", err)
		}
		return
	}

	fmt.Println("✓ Authentication successful!")
	fmt.Println()
	fmt.Println("PKCS#11 use cases:")
	fmt.Println("  - Hardware Security Modules (HSMs)")
	fmt.Println("  - Smart cards and USB tokens")
	fmt.Println("  - YubiKey PIV")
	fmt.Println("  - Certificate-based authentication")
	fmt.Println("  - Cryptographic key storage")
}
