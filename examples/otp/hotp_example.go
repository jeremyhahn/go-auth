package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jhahn/go-auth/pkg/otp"
)

func main() {
	// Example: HOTP (Counter-based OTP)
	fmt.Println("HOTP Example - Counter-based OTP")
	fmt.Println("=================================\n")

	// Generate a secret
	secret, err := otp.GenerateSecret()
	if err != nil {
		log.Fatalf("Failed to generate secret: %v", err)
	}
	fmt.Printf("Generated secret: %s\n\n", secret)

	// Setup HOTP authenticator
	config := otp.Config{
		Type:        otp.TypeHOTP,
		Secret:      secret,
		Issuer:      "ExampleApp",
		AccountName: "user@example.com",
		Counter:     0,
		Digits:      6,
		Algorithm:   otp.AlgorithmSHA1,
	}

	auth, err := otp.NewAuthenticator(config)
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}

	// Get provisioning URI
	uri := auth.GetProvisioningURI()
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
		newCounter, err := auth.ValidateCounter(ctx, code, currentCounter)
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

	_, err = auth.ValidateCounter(ctx, oldCode, currentCounter)
	if err != nil {
		fmt.Printf("  ✓ Old code correctly rejected: %v\n", err)
	} else {
		fmt.Println("  ✗ Old code should have been rejected!")
	}

	// Demonstrate future counter works
	fmt.Println("\nTesting current counter (should work):")
	currentCode, _ := auth.Generate(currentCounter)
	fmt.Printf("  Code for counter=%d: %s\n", currentCounter, currentCode)

	newCounter, err := auth.ValidateCounter(ctx, currentCode, currentCounter)
	if err != nil {
		log.Fatalf("  Current code authentication failed: %v", err)
	}
	fmt.Printf("  ✓ Current code authenticated! New counter: %d\n", newCounter)
}
