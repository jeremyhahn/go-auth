//go:build ignore

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jeremyhahn/go-auth/pkg/otp"
)

func main() {
	// Example 1: Generate a new seed straight into locked memory. It never
	// exists as a Go string or an ordinary []byte.
	seed, err := otp.GenerateProtectedSecret()
	if err != nil {
		log.Fatalf("Failed to generate seed: %v", err)
	}

	// Example 2: Setup TOTP authenticator. NewAuthenticator takes ownership
	// of the seed — on success Close destroys it, on failure it is destroyed
	// before NewAuthenticator returns — so there is no seed.Destroy here.
	auth, err := otp.NewAuthenticator(otp.Config{
		Type:        otp.TypeTOTP,
		Seed:        seed,
		Issuer:      "ExampleApp",
		AccountName: "user@example.com",
		Digits:      6,
		Period:      30,
		Algorithm:   otp.AlgorithmSHA1, // use SHA256/SHA512 under FIPS 140-only mode
		Skew:        1,                 // Allow 1 period of clock skew
	})
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Example 3: Get provisioning URI for QR code. It carries the seed — that
	// is what enrollment is — so render it and drop it; never log it in a
	// real application.
	uri, err := auth.ProvisioningURI()
	if err != nil {
		log.Fatalf("Failed to build provisioning URI: %v", err)
	}
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

	// Example 6: A wrong code is rejected
	if err := auth.Authenticate(ctx, "000000"); err != nil {
		fmt.Printf("Wrong code rejected: %v\n", err)
	}
}
