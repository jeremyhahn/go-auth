// Package main demonstrates YubiKey OTP validation through YubiCloud; run with go run basic_example.go.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/yubikey"
)

func main() {
	fmt.Println("==> YubiKey OTP Authentication Example")
	fmt.Println()

	// YubiCloud credentials come from https://upgrade.yubico.com/getapikey/; the API key is an enclave.
	apiKey, err := enclave.NewMemoryEnclave([]byte("your-base64-encoded-api-key="))
	if err != nil {
		log.Fatalf("Failed to seal the API key: %v", err)
	}
	cfg := yubikey.Config{
		ClientID: "12345", // Your YubiCloud Client ID
		APIKey:   apiKey,  // NewAuthenticator takes ownership; auth.Close destroys it
	}

	// Create authenticator with YubiCloud validator
	// Note: This example uses YubiCloud. For self-hosted validation servers,
	// you would implement a custom OTPValidator.
	auth, err := yubikey.NewAuthenticator(cfg, nil)
	if err != nil {
		log.Fatalf("Failed to create YubiKey authenticator: %v", err)
	}
	defer auth.Close()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// A real OTP is 44 characters from a key press; it is a credential, so it travels in an enclave Authenticate borrows.
	otp, err := enclave.NewMemoryEnclave([]byte("ccccccbcgujhingjrdejhgfnuetrgigvejhhgbkugded"))
	if err != nil {
		log.Fatalf("Failed to seal the OTP: %v", err)
	}
	defer otp.Destroy()

	fmt.Println("Validating YubiKey OTP...")
	fmt.Println()

	// The validation service checks the OTP, replay and signature.
	err = auth.Authenticate(ctx, otp)
	if err != nil {
		if errors.Is(err, yubikey.ErrInvalidOTP) {
			log.Printf("Invalid OTP - rejected by validation service")
		} else {
			log.Printf("Authentication failed: %v", err)
		}
		fmt.Println()
		fmt.Println("Note: This example requires:")
		fmt.Println("  1. YubiCloud API credentials (or self-hosted validator)")
		fmt.Println("  2. A physical YubiKey to generate OTPs")
		fmt.Println("  3. Network connectivity to api.yubico.com")
		fmt.Println()
		fmt.Println("To get started:")
		fmt.Println("  1. Visit: https://upgrade.yubico.com/getapikey/")
		fmt.Println("  2. Enter your email and generate an OTP with your YubiKey")
		fmt.Println("  3. Save your Client ID and API Key")
		fmt.Println("  4. Update the cfg.ClientID and cfg.APIKey in this example")
		fmt.Println("  5. Press your YubiKey to generate a fresh OTP and run again")
		return
	}

	fmt.Println("✓ Authentication successful!")
	fmt.Println()
	fmt.Println("The YubiKey OTP has been validated by YubiCloud.")
	fmt.Println()
	fmt.Println("YubiKey OTP features:")
	fmt.Println("  - One-time passwords (cannot be reused)")
	fmt.Println("  - Strong replay protection")
	fmt.Println("  - No driver installation required")
	fmt.Println("  - Works as a USB keyboard")
	fmt.Println("  - Suitable for two-factor authentication")
	fmt.Println()
	fmt.Println("For self-hosted validation:")
	fmt.Println("  - Deploy YubiKey Validation Server")
	fmt.Println("  - Implement custom OTPValidator interface")
	fmt.Println("  - Pass to NewAuthenticator() instead of nil")
}
