//go:build fips140only

package otp

import (
	"context"
	"errors"
	"testing"
)

// The FIPS-140-only counterparts of the constants in algorithm_default_test.go.
//
// SHA-1 is dropped, not because HOTP/TOTP over SHA-1 is broken — HMAC-SHA-1 has
// no practical break — but because Go's fips140=only mode admits HMAC over
// SHA-2 and SHA-3 only. RFC 6238 §1.2 permits SHA-256 and SHA-512, and this
// package supports both, so the suite still covers every code path in the FIPS
// job; only the digest differs. No test is excluded — TestDefaults comes along
// too, because defaultAlgorithm (algorithm_fips140only.go) resolves to SHA-256
// in this build, so "the default" is something it can execute.
const testAlgorithm = AlgorithmSHA256

var testAlgorithms = []Algorithm{AlgorithmSHA256, AlgorithmSHA512}

// TestSHA1RejectedUnderFIPS proves the SHA-1 path fails closed at
// construction.
//
// Under GODEBUG=fips140=only, crypto/hmac panics on SHA-1 rather than
// returning an error. If the configuration were accepted, that panic would be
// reached from Generate, Authenticate and ValidateCounter — so an ordinary
// authentication request, which is attacker-reachable traffic, would crash the
// process instead of failing a login. NewAuthenticator must refuse first.
func TestSHA1RejectedUnderFIPS(t *testing.T) {
	for _, otpType := range []Type{TypeTOTP, TypeHOTP} {
		t.Run(string(otpType), func(t *testing.T) {
			auth, err := NewAuthenticator(Config{
				Type:        otpType,
				Secret:      testSecret,
				Issuer:      "TestApp",
				AccountName: "user@example.com",
				Algorithm:   AlgorithmSHA1,
			})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected ErrInvalidConfig for SHA-1, got auth=%v err=%v", auth, err)
			}
			if auth != nil {
				t.Errorf("expected no authenticator alongside the error, got %v", auth)
			}
		})
	}
}

// TestOmittedAlgorithmIsApprovedUnderFIPS covers the other half: a config that
// names no algorithm must not silently fall back to RFC 6238's SHA-1 default,
// because that default is exactly what panics here. It resolves to SHA-256,
// and the full generate/validate round trip runs — reaching HMAC at all is
// what proves the digest is an approved one.
func TestOmittedAlgorithmIsApprovedUnderFIPS(t *testing.T) {
	auth, err := NewAuthenticator(Config{
		Type:        TypeTOTP,
		Secret:      testSecret,
		Issuer:      "TestApp",
		AccountName: "user@example.com",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	if auth.cfg.Algorithm != AlgorithmSHA256 {
		t.Errorf("expected the omitted algorithm to default to SHA256, got %q", auth.cfg.Algorithm)
	}

	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}
	if err := auth.Authenticate(context.Background(), code); err != nil {
		t.Errorf("failed to authenticate: %v", err)
	}

	// Enrollment has to advertise the digest validation will actually use.
	if uri := auth.GetProvisioningURI(); !contains(uri, "algorithm=SHA256") {
		t.Errorf("provisioning URI %q does not advertise SHA256", uri)
	}
}

// Secrets either side of the FIPS 140-3 HMAC key floor. crypto/hmac panics
// below 112 bits, so 13 bytes must be refused and 14 must be accepted; the
// boundary was measured against the toolchain, not assumed.
const (
	secret80Bits  = "AEBAGBAFAYDQQCIK"         // 10 bytes — the length of the JBSWY3DPEHPK3PXP example
	secret104Bits = "AEBAGBAFAYDQQCIKBMGA2===" // 13 bytes — one below the floor
	secret112Bits = "AEBAGBAFAYDQQCIKBMGA2DQ=" // 14 bytes — the floor exactly
)

// TestShortSecretRejectedUnderFIPS proves a secret too short to key HMAC fails
// closed at construction.
//
// This is the same failure shape as TestSHA1RejectedUnderFIPS: crypto/hmac
// panics on a sub-112-bit key rather than returning an error, so accepting the
// config would put a process crash behind Generate, Authenticate and
// ValidateCounter — reachable by ordinary authentication traffic. Applications
// holding secrets enrolled from the widely copied 80-bit example are exactly
// the ones affected, and they need to see that at startup, not at a login.
func TestShortSecretRejectedUnderFIPS(t *testing.T) {
	for _, otpType := range []Type{TypeTOTP, TypeHOTP} {
		for _, tc := range []struct {
			name   string
			secret string
		}{
			{"80 bits", secret80Bits},
			{"104 bits, one byte below the floor", secret104Bits},
		} {
			t.Run(string(otpType)+"/"+tc.name, func(t *testing.T) {
				auth, err := NewAuthenticator(Config{
					Type:        otpType,
					Secret:      tc.secret,
					Issuer:      "TestApp",
					AccountName: "user@example.com",
				})
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("expected ErrInvalidConfig for a short secret, got auth=%v err=%v", auth, err)
				}
				if auth != nil {
					t.Errorf("expected no authenticator alongside the error, got %v", auth)
				}
			})
		}
	}
}

// TestSecretAtFIPSFloorAccepted is the other side of the boundary: 112 bits
// exactly must be usable, and must reach HMAC without panicking. A check that
// rejected this would be quietly over-strict, refusing compliant secrets.
func TestSecretAtFIPSFloorAccepted(t *testing.T) {
	auth, err := NewAuthenticator(Config{
		Type:        TypeTOTP,
		Secret:      secret112Bits,
		Issuer:      "TestApp",
		AccountName: "user@example.com",
	})
	if err != nil {
		t.Fatalf("a 112-bit secret is at the FIPS floor and must be accepted: %v", err)
	}

	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}
	if err := auth.Authenticate(context.Background(), code); err != nil {
		t.Errorf("failed to authenticate: %v", err)
	}
}
