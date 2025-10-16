// Package otp provides TOTP (RFC 6238) and HOTP (RFC 4226) authentication.
//
// TOTP (Time-based One-Time Password) generates codes that change every 30 seconds,
// commonly used with authenticator apps like Google Authenticator, Authy, etc.
//
// HOTP (HMAC-based One-Time Password) generates codes based on a counter value,
// used in hardware tokens and some mobile apps.
//
// # TOTP Example
//
// Time-based OTP for use with authenticator apps:
//
//	config := otp.Config{
//	    Type:        otp.TypeTOTP,
//	    Secret:      "JBSWY3DPEHPK3PXP",
//	    Issuer:      "MyApp",
//	    AccountName: "user@example.com",
//	    Digits:      6,
//	    Period:      30,
//	    Algorithm:   otp.AlgorithmSHA1,
//	    Skew:        1, // Allow 1 period of clock skew
//	}
//
//	auth, err := otp.NewAuthenticator(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Validate a code from user's authenticator app
//	err = auth.Authenticate(ctx, "123456")
//	if err != nil {
//	    log.Printf("Authentication failed: %v", err)
//	}
//
//	// Generate provisioning URI for QR code
//	uri := auth.GetProvisioningURI()
//	// Display uri as QR code for user to scan
//
// # HOTP Example
//
// Counter-based OTP for hardware tokens:
//
//	config := otp.Config{
//	    Type:        otp.TypeHOTP,
//	    Secret:      "JBSWY3DPEHPK3PXP",
//	    Issuer:      "MyApp",
//	    AccountName: "user@example.com",
//	    Counter:     0,
//	}
//
//	auth, err := otp.NewAuthenticator(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Validate code and get new counter value
//	newCounter, err := auth.ValidateCounter(ctx, "123456", currentCounter)
//	if err != nil {
//	    log.Printf("Authentication failed: %v", err)
//	} else {
//	    // Store newCounter for next validation
//	    currentCounter = newCounter
//	}
//
// # Secret Generation
//
// Generate a cryptographically random secret:
//
//	secret, err := otp.GenerateSecret()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Use secret in Config.Secret
//
// # Hash Algorithms
//
// The package supports multiple hash algorithms:
//   - AlgorithmSHA1 (default, widely supported)
//   - AlgorithmSHA256 (more secure)
//   - AlgorithmSHA512 (most secure)
//
// Note that not all authenticator apps support SHA256 and SHA512.
//
// # Thread Safety
//
// The Authenticator type is safe for concurrent use. Multiple goroutines
// can call its methods simultaneously.
//
// # Context Support
//
// All authentication methods accept a context.Context for cancellation
// and timeout support:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	err := auth.Authenticate(ctx, code)
package otp
