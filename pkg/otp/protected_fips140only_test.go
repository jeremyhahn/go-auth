// The FIPS-140-only counterpart to protected_test.go.
//
// Under GODEBUG=fips140=only, crypto/hmac refuses SHA-1 and refuses keys
// shorter than 112 bits, so the RFC 4226 vectors and this package's default
// digest are unavailable. What has to hold here is that the protected-secret
// path itself works in a FIPS build: a key generated into an enclave, opened
// per call, and keyed into HMAC-SHA-256 without ever becoming a string.

//go:build fips140only

package otp

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestProtectedPathUnderFIPS drives generation and validation with the key in
// protected memory and SHA-256 as the digest.
func TestProtectedPathUnderFIPS(t *testing.T) {
	key, err := GenerateProtectedSecret()
	if err != nil {
		t.Fatalf("GenerateProtectedSecret: %v", err)
	}
	defer key.Destroy()

	// 160 bits, comfortably above the 112-bit minimum fips140=only imposes on
	// an HMAC key.
	if key.Size() != 20 {
		t.Fatalf("Size = %d, want 20", key.Size())
	}

	totpAuth, err := NewAuthenticator(Config{
		Type:      TypeTOTP,
		SecretKey: key,
		Algorithm: AlgorithmSHA256,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	code, err := totpAuth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := totpAuth.Authenticate(context.Background(), code); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := totpAuth.Authenticate(context.Background(), "000000"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("Authenticate with a wrong code = %v, want ErrInvalidCode", err)
	}

	hotpAuth, err := NewAuthenticator(Config{
		Type:      TypeHOTP,
		SecretKey: key,
		Algorithm: AlgorithmSHA256,
		Counter:   4,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	code, err = hotpAuth.Generate(4)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	next, err := hotpAuth.ValidateCounter(context.Background(), code, 4)
	if err != nil {
		t.Fatalf("ValidateCounter: %v", err)
	}
	if next != 5 {
		t.Fatalf("ValidateCounter returned %d, want 5", next)
	}
}

// TestDeriveCodeRFC6238SHA256VectorsUnderFIPS checks the derivation against
// the RFC 6238 Appendix B values for SHA-256, the strongest statement of
// correctness available in a build that cannot execute SHA-1.
func TestDeriveCodeRFC6238SHA256VectorsUnderFIPS(t *testing.T) {
	const key = "12345678901234567890123456789012" // 256 bits

	cases := []struct {
		unix int64
		want string
	}{
		{59, "46119246"},
		{1111111109, "68084774"},
		{1111111111, "67062674"},
		{1234567890, "91819424"},
		{2000000000, "90698825"},
		{20000000000, "77737706"},
	}

	for _, tc := range cases {
		counter := totpCounter(time.Unix(tc.unix, 0).UTC(), 30)
		got, err := deriveCode([]byte(key), counter, 8, AlgorithmSHA256)
		if err != nil {
			t.Fatalf("at %d: %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("at %d = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

// TestKeyStaysSealedUnderFIPS is the fips140only half of the verification the
// issue asks for: after use, nothing in the authenticator can derive a code
// once the caller releases the secret.
func TestKeyStaysSealedUnderFIPS(t *testing.T) {
	key, err := GenerateProtectedSecret()
	if err != nil {
		t.Fatalf("GenerateProtectedSecret: %v", err)
	}

	auth, err := NewAuthenticator(Config{
		Type:      TypeHOTP,
		SecretKey: key,
		Algorithm: AlgorithmSHA256,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if _, err := auth.Generate(1); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	key.Destroy()

	if _, err := auth.Generate(1); err == nil {
		t.Fatal("Generate still produced a code after the secret was destroyed")
	}
}
