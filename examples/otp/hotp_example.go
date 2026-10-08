//go:build ignore

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/otp"
)

func main() {
	// Example: HOTP (Counter-based OTP)
	fmt.Println("HOTP Example - Counter-based OTP")
	fmt.Print("=================================\n\n")

	// Generate a seed straight into locked memory
	seed, err := otp.GenerateProtectedSecret()
	if err != nil {
		log.Fatalf("Failed to generate seed: %v", err)
	}

	// Setup HOTP authenticator. It takes ownership of the seed; Close
	// destroys it.
	auth, err := otp.NewAuthenticator(otp.Config{
		Type:        otp.TypeHOTP,
		Seed:        seed,
		Issuer:      "ExampleApp",
		AccountName: "user@example.com",
		Counter:     0,
		Digits:      6,
		Algorithm:   otp.AlgorithmSHA1, // use SHA256/SHA512 under FIPS 140-only mode
	})
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Get provisioning URI. It carries the seed; render it and drop it.
	uri, err := auth.ProvisioningURI()
	if err != nil {
		log.Fatalf("Failed to build provisioning URI: %v", err)
	}
	fmt.Printf("Provisioning URI:\n%s\n\n", uri)

	ctx := context.Background()
	currentCounter := uint64(0)

	// Simulate multiple authentications
	for i := 0; i < 5; i++ {
		fmt.Printf("Authentication attempt %d (counter=%d)\n", i+1, currentCounter)

		// Generate code for current counter
		code, err := auth.Generate(currentCounter)
		if err != nil {
			log.Fatalf("Failed to generate code: %v", err)
		}
		fmt.Printf("  Generated code: %s\n", code)

		// Validate and get new counter
		submitted := sealCode(code)
		newCounter, err := auth.ValidateCounter(ctx, submitted, currentCounter)
		submitted.Destroy()
		if err != nil {
			log.Fatalf("  Authentication failed: %v", err)
		}
		fmt.Printf("  Authentication successful! New counter: %d\n\n", newCounter)

		// Update counter for next iteration
		currentCounter = newCounter
	}

	// Demonstrate that old codes don't work
	fmt.Println("Testing old code (should fail):")
	oldCode, _ := auth.Generate(0)
	fmt.Printf("  Code for counter=0: %s\n", oldCode)

	submitted := sealCode(oldCode)
	_, err = auth.ValidateCounter(ctx, submitted, currentCounter)
	submitted.Destroy()
	if err != nil {
		fmt.Printf("  ✓ Old code correctly rejected: %v\n", err)
	} else {
		fmt.Println("  ✗ Old code should have been rejected!")
	}

	// Demonstrate future counter works
	fmt.Println("\nTesting current counter (should work):")
	currentCode, _ := auth.Generate(currentCounter)
	fmt.Printf("  Code for counter=%d: %s\n", currentCounter, currentCode)

	submitted = sealCode(currentCode)
	newCounter, err := auth.ValidateCounter(ctx, submitted, currentCounter)
	submitted.Destroy()
	if err != nil {
		log.Fatalf("  Current code authentication failed: %v", err)
	}
	fmt.Printf("  ✓ Current code authenticated! New counter: %d\n", newCounter)
}

// sealCode puts a submitted code into locked memory, the way a server would
// on receipt. Authenticate and ValidateCounter only borrow it; the caller
// destroys it once it has been checked.
func sealCode(code string) *enclave.MemoryEnclave {
	e, err := enclave.NewMemoryEnclave([]byte(code))
	if err != nil {
		log.Fatalf("Failed to seal code: %v", err)
	}
	return e
}
