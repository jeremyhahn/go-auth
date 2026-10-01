// Package otp provides TOTP (RFC 6238) and HOTP (RFC 4226) authentication.
//
// TOTP (Time-based One-Time Password) generates codes that change every 30 seconds,
// commonly used with authenticator apps like Google Authenticator, Authy, etc.
//
// HOTP (HMAC-based One-Time Password) generates codes based on a counter value,
// used in hardware tokens and some mobile apps.
//
// Both are implemented in this package over the seed's raw bytes, borrowed
// from a go-enclave MemoryEnclave for the duration of one HMAC; there is no
// third-party OTP dependency and no plaintext copy of the seed outside locked
// memory.
//
// # Seeds and ownership
//
// The shared key ("seed") lives only in a *enclave.MemoryEnclave. Generate a
// new one straight into locked memory, or decode a stored base32 one into it:
//
//	seed, err := otp.GenerateProtectedSecret() // or otp.DecodeSeed(stored)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// NewAuthenticator takes ownership of Config.Seed on every return path —
// it destroys the seed itself if the configuration is refused — and Close
// destroys it otherwise:
//
//	auth, err := otp.NewAuthenticator(otp.Config{
//	    Type:        otp.TypeTOTP,
//	    Seed:        seed,
//	    Issuer:      "MyApp",
//	    AccountName: "user@example.com",
//	    Digits:      6,
//	    Period:      30,
//	    Algorithm:   otp.AlgorithmSHA1,
//	    Skew:        1, // Allow 1 period of clock skew
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer auth.Close()
//
//	// Validate a code from user's authenticator app
//	if err := auth.Authenticate(ctx, "123456"); err != nil {
//	    log.Printf("Authentication failed: %v", err)
//	}
//
// # Enrollment
//
// ProvisioningURI returns the otpauth:// URI (Google Authenticator Key URI
// Format) to render as a QR code, and EncodeSecret returns the bare base32
// seed for storage. Both necessarily produce an unwipeable string copy of the
// key; that is the documented residue of enrollment. Render or store it and
// drop it.
//
//	uri, err := auth.ProvisioningURI()
//	if err != nil {
//	    log.Fatal(err) // the seed could not be read — never show a seed-less URI
//	}
//
// # HOTP Example
//
// Counter-based OTP for hardware tokens:
//
//	auth, err := otp.NewAuthenticator(otp.Config{
//	    Type:    otp.TypeHOTP,
//	    Seed:    seed,
//	    Counter: 0,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer auth.Close()
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
// # Hash Algorithms and FIPS 140-3
//
// The package supports multiple hash algorithms:
//   - AlgorithmSHA1 (default, widely supported)
//   - AlgorithmSHA256
//   - AlgorithmSHA512
//
// Note that not all authenticator apps support SHA256 and SHA512.
//
// Under GODEBUG=fips140=only, crypto/hmac panics on SHA-1 and on keys shorter
// than 112 bits. When the process runs in that mode, NewAuthenticator refuses
// both with ErrFIPSUnsupported, refuses an omitted Algorithm too — set SHA256
// or SHA512 explicitly — and the derivation re-checks before every HMAC, so no
// configuration reaches that panic. There is no build tag: the same binary
// serves both deployments. See docs/fips.md.
//
// # Thread Safety
//
// The Authenticator type is safe for concurrent use. Multiple goroutines
// can call its methods simultaneously, and Close waits for in-flight calls
// to finish with the seed before wiping it.
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
