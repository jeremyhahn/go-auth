package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jhahn/go-auth/pkg/otp"
)

func main() {
	// Example 1: Generate a new secret
	secret, err := otp.GenerateSecret()
	if err != nil {
		log.Fatalf("Failed to generate secret: %v", err)
	}
	fmt.Printf("Generated secret: %s\n\n", secret)

	// Example 2: Setup TOTP authenticator
	config := otp.Config{
		Type:        otp.TypeTOTP,
		Secret:      secret,
		Issuer:      "ExampleApp",
		AccountName: "user@example.com",
		Digits:      6,
		Period:      30,
		Algorithm:   otp.AlgorithmSHA1,
		Skew:        1, // Allow 1 period of clock skew
	}

	auth, err := otp.NewAuthenticator(config)
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}

	// Example 3: Get provisioning URI for QR code
	uri := auth.GetProvisioningURI()
	fmt.Printf("Provisioning URI (scan with authenticator app):\n%s\n\n", uri)

	// Example 4: Generate current OTP code
	code, err := auth.Generate()
	if err != nil {
		log.Fatalf("Failed to generate code: %v", err)
	}
	fmt.Printf("Current TOTP code: %s\n", code)

	// Example 5: Validate the code
	ctx := context.Background()
	if err := auth.Authenticate(ctx, code); err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}
	fmt.Println("Authentication successful!")

	// Example 6: Show code expiration
	fmt.Println("\nWaiting for code to expire...")
	time.Sleep(2 * time.Second)

	// Generate new code
	newCode, err := auth.Generate()
	if err != nil {
		log.Fatalf("Failed to generate new code: %v", err)
	}
	fmt.Printf("New TOTP code: %s\n", newCode)

	// Old code might still work due to skew tolerance
	if err := auth.Authenticate(ctx, code); err != nil {
		fmt.Printf("Old code rejected: %v\n", err)
	} else {
		fmt.Println("Old code still accepted (within skew tolerance)")
	}

	// New code should definitely work
	if err := auth.Authenticate(ctx, newCode); err != nil {
		log.Fatalf("New code authentication failed: %v", err)
	}
	fmt.Println("New code authenticated successfully!")
}
