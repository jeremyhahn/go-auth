// Package main demonstrates integrating multiple authentication backends
// with the go-auth API service.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/api"
	"github.com/jeremyhahn/go-auth/pkg/oauth"
	"github.com/jeremyhahn/go-auth/pkg/otp"
)

func main() {
	ctx := context.Background()

	// Example 1: Single OTP backend
	fmt.Println("=== Example 1: OTP Backend ===")
	otpExample(ctx)

	// Example 2: Multiple backends with fallback
	fmt.Println("\n=== Example 2: Multiple Backends with Fallback ===")
	multiBackendExample(ctx)

	// Example 3: Targeting specific backend
	fmt.Println("\n=== Example 3: Targeting Specific Backend ===")
	targetedBackendExample(ctx)
}

func otpExample(ctx context.Context) {
	// Create OTP authenticator for TOTP
	otpAuth, err := otp.NewAuthenticator(otp.Config{
		Type:        otp.TypeTOTP,
		Seed:        mustDecodeSeed("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
		Issuer:      "MyApp",
		AccountName: "user@example.com",
		Digits:      6,
		Period:      30,
		Algorithm:   otp.AlgorithmSHA1,
		Skew:        1,
	})
	if err != nil {
		log.Printf("Failed to create OTP authenticator: %v", err)
		return
	}
	defer otpAuth.Close()

	// Create API service with OTP backend
	service, err := api.NewService(api.Config{
		Backends: []api.Backend{
			{Name: api.BackendOTP, Handler: api.OTP(otpAuth)},
		},
	})
	if err != nil {
		log.Printf("Failed to create service: %v", err)
		return
	}

	// Generate a valid OTP code for demonstration
	validCode, err := otpAuth.Generate()
	if err != nil {
		log.Printf("Failed to generate OTP code: %v", err)
		return
	}

	fmt.Printf("Generated OTP Code: %s\n", validCode)

	// Authenticate with OTP code in the OTP field
	err = service.Login(ctx, api.LoginRequest{
		Username: "user@example.com",      // Ignored for OTP
		Password: sealCredential("dummy"), // Required by API but ignored for OTP
		OTP:      sealCredential(validCode),
	})

	if err != nil {
		log.Printf("Authentication failed: %v", err)
		return
	}

	fmt.Println("Authentication successful!")

	// Alternative: OTP code can be passed in Password field
	err = service.Login(ctx, api.LoginRequest{
		Username: "user@example.com",
		Password: sealCredential(validCode), // OTP code in password field
	})

	if err != nil {
		log.Printf("Authentication with code in password field failed: %v", err)
		return
	}

	fmt.Println("Authentication with code in password field successful!")
}

func multiBackendExample(ctx context.Context) {
	// Create OTP authenticator
	otpAuth, err := otp.NewAuthenticator(otp.Config{
		Type:        otp.TypeTOTP,
		Seed:        mustDecodeSeed("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
		Issuer:      "MyApp",
		AccountName: "user@example.com",
	})
	if err != nil {
		log.Printf("Failed to create OTP authenticator: %v", err)
		return
	}
	defer otpAuth.Close()

	// Create OAuth authenticator
	oauthAuth, err := oauth.NewAuthenticator(&oauth.Config{
		Provider: oauth.Google(),
		Flow:     oauth.FlowTokenValidation,
		ClientID: "your-client-id",
		Validation: oauth.TokenValidationConfig{
			Method:  oauth.ValidationJWT,
			JWKSURL: "https://www.googleapis.com/oauth2/v3/certs",
		},
	})
	if err != nil {
		log.Printf("Failed to create OAuth authenticator: %v", err)
		return
	}
	defer oauthAuth.Close()

	// Create service with multiple backends
	// The service will try each backend in order until one succeeds
	service, err := api.NewService(api.Config{
		Backends: []api.Backend{
			{Name: api.BackendOAuth, Handler: api.OAuth(oauthAuth)},
			{Name: api.BackendOTP, Handler: api.OTP(otpAuth)},
		},
	})
	if err != nil {
		log.Printf("Failed to create service: %v", err)
		return
	}

	// Generate valid OTP code
	validCode, err := otpAuth.Generate()
	if err != nil {
		log.Printf("Failed to generate OTP code: %v", err)
		return
	}

	// Try to authenticate - OAuth will fail, but OTP will succeed
	err = service.Login(ctx, api.LoginRequest{
		Username: "user@example.com",
		Password: sealCredential(validCode),
	})

	if err != nil {
		log.Printf("Authentication failed: %v", err)
		return
	}

	fmt.Println("Authentication successful via fallback!")
}

func targetedBackendExample(ctx context.Context) {
	// Create HOTP authenticator (counter-based)
	hotpAuth, err := otp.NewAuthenticator(otp.Config{
		Type:        otp.TypeHOTP,
		Seed:        mustDecodeSeed("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
		Issuer:      "MyApp",
		AccountName: "user@example.com",
		Counter:     0, // Initial counter value
		Digits:      6,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		log.Printf("Failed to create HOTP authenticator: %v", err)
		return
	}
	defer hotpAuth.Close()

	// Create TOTP authenticator (time-based)
	totpAuth, err := otp.NewAuthenticator(otp.Config{
		Type:        otp.TypeTOTP,
		Seed:        mustDecodeSeed("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"),
		Issuer:      "MyApp",
		AccountName: "user@example.com",
	})
	if err != nil {
		log.Printf("Failed to create TOTP authenticator: %v", err)
		return
	}
	defer totpAuth.Close()

	// Create service with both HOTP and TOTP as separate OTP backends
	// Note: In practice, you'd use different backend names or custom naming
	service, err := api.NewService(api.Config{
		Backends: []api.Backend{
			{Name: "hotp", Handler: api.OTP(hotpAuth)},
			{Name: "totp", Handler: api.OTP(totpAuth)},
		},
	})
	if err != nil {
		log.Printf("Failed to create service: %v", err)
		return
	}

	// Generate valid TOTP code
	totpCode, err := totpAuth.Generate()
	if err != nil {
		log.Printf("Failed to generate TOTP code: %v", err)
		return
	}

	fmt.Printf("Generated TOTP Code: %s\n", totpCode)

	// Explicitly target the TOTP backend
	err = service.Login(ctx, api.LoginRequest{
		Backend:  "totp",
		Username: "user@example.com",
		Password: sealCredential(totpCode),
	})

	if err != nil {
		log.Printf("TOTP authentication failed: %v", err)
		return
	}

	fmt.Println("TOTP authentication successful!")

	// Generate valid HOTP code (counter 0)
	hotpCode, err := hotpAuth.Generate(0)
	if err != nil {
		log.Printf("Failed to generate HOTP code: %v", err)
		return
	}

	fmt.Printf("Generated HOTP Code: %s\n", hotpCode)

	// Explicitly target the HOTP backend
	err = service.Login(ctx, api.LoginRequest{
		Backend:  "hotp",
		Username: "user@example.com",
		Password: sealCredential(hotpCode),
	})

	if err != nil {
		log.Printf("HOTP authentication failed: %v", err)
		return
	}

	fmt.Println("HOTP authentication successful!")
}

// mustDecodeSeed decodes a stored base32 OTP seed into locked memory. The
// literal seeds here are demonstration values; a real application reads them
// from its credential store. NewAuthenticator takes ownership of the result.
func mustDecodeSeed(encoded string) *enclave.MemoryEnclave {
	seed, err := otp.DecodeSeed(encoded)
	if err != nil {
		log.Fatalf("Failed to decode OTP seed: %v", err)
	}
	return seed
}

// sealCredential puts a credential into locked memory for a LoginRequest.
// Service.Login takes ownership of the request's enclaves and destroys them
// when the attempt completes, so each request gets fresh ones and nothing
// here destroys them. A real application builds them with
// enclave.NewMemoryEnclave over the bytes it read, which wipes that slice; the
// generated codes in this example are strings only because Generate returns
// one.
func sealCredential(value string) *enclave.MemoryEnclave {
	e, err := enclave.NewMemoryEnclaveFromString(value)
	if err != nil {
		log.Fatalf("Failed to seal credential: %v", err)
	}
	return e
}
