//go:build integration

package otp_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- probes whether the runtime refuses HMAC-SHA-1; never protects anything
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/otp"
)

// fips140OnlyActive reports whether this process refuses HMAC-SHA-1, by
// executing it — the same probe pkg/otp gates on (see pkg/otp/fips.go), which
// this external test package cannot call.
var fips140OnlyActive = sync.OnceValue(func() (unavailable bool) {
	defer func() {
		if recover() != nil {
			unavailable = true
		}
	}()
	hmac.New(sha1.New, make([]byte, 32)).Sum(nil)
	return false
})

// defaultAlgorithm is the digest these tests use where the choice is
// incidental: RFC 6238's SHA-1 normally, SHA-256 where the process runs under
// FIPS 140-only mode and HMAC-SHA-1 is refused.
func defaultAlgorithm() otp.Algorithm {
	if fips140OnlyActive() {
		return otp.AlgorithmSHA256
	}
	return otp.AlgorithmSHA1
}

// newSeed generates a fresh seed straight into locked memory.
func newSeed(t *testing.T) *enclave.MemoryEnclave {
	t.Helper()
	seed, err := otp.GenerateProtectedSecret()
	if err != nil {
		t.Fatalf("GenerateProtectedSecret: %v", err)
	}
	t.Cleanup(seed.Destroy)
	return seed
}

// seedCopies returns n independent enclaves over one generated key, the way an
// application holds the same enrolled seed in several authenticators: each
// authenticator owns its own enclave.
func seedCopies(t *testing.T, n int) []*enclave.MemoryEnclave {
	t.Helper()
	encoded, err := otp.EncodeSecret(newSeed(t))
	if err != nil {
		t.Fatalf("EncodeSecret: %v", err)
	}
	seeds := make([]*enclave.MemoryEnclave, n)
	for i := range seeds {
		seeds[i], err = otp.DecodeSeed(encoded)
		if err != nil {
			t.Fatalf("DecodeSeed: %v", err)
		}
		t.Cleanup(seeds[i].Destroy)
	}
	return seeds
}

func newAuthenticator(t *testing.T, cfg otp.Config) *otp.Authenticator {
	t.Helper()
	auth, err := otp.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })
	return auth
}

func TestIntegration_TOTP_EndToEnd(t *testing.T) {
	// Complete TOTP workflow: seed generation → provisioning URI → code validation
	tests := []struct {
		name      string
		algorithm otp.Algorithm
		digits    uint
	}{
		{"default_6digits", defaultAlgorithm(), 6},
		{"SHA256_6digits", otp.AlgorithmSHA256, 6},
		{"SHA512_6digits", otp.AlgorithmSHA512, 6},
		{"default_7digits", defaultAlgorithm(), 7},
		{"default_8digits", defaultAlgorithm(), 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := newAuthenticator(t, otp.Config{
				Type:        otp.TypeTOTP,
				Seed:        newSeed(t),
				Issuer:      "IntegrationTest",
				AccountName: "test@example.com",
				Algorithm:   tt.algorithm,
				Digits:      tt.digits,
				Period:      30,
				Skew:        1,
			})

			uri, err := auth.ProvisioningURI()
			if err != nil {
				t.Fatalf("ProvisioningURI: %v", err)
			}
			if len(uri) < 15 || uri[:15] != "otpauth://totp/" {
				t.Errorf("Invalid URI scheme, expected otpauth://totp/, got: %s", uri)
			}

			code, err := auth.Generate()
			if err != nil {
				t.Fatalf("Failed to generate code: %v", err)
			}
			if len(code) != int(tt.digits) {
				t.Errorf("Expected %d digit code, got %d digits: %s", tt.digits, len(code), code)
			}
			if err := auth.Authenticate(context.Background(), code); err != nil {
				t.Errorf("Failed to validate generated code: %v", err)
			}
		})
	}
}

// TestIntegration_TOTP_TimeSkew drives the skew window without waiting on the
// clock: RFC 6238 §4 defines TOTP as HOTP over the time step, so an HOTP
// authenticator over the same seed derives the codes for neighboring steps.
func TestIntegration_TOTP_TimeSkew(t *testing.T) {
	const period = 30
	seeds := seedCopies(t, 2)

	totp := newAuthenticator(t, otp.Config{
		Type: otp.TypeTOTP, Seed: seeds[0], Algorithm: defaultAlgorithm(),
		Period: period, Skew: 2, Digits: 8,
	})
	hotp := newAuthenticator(t, otp.Config{
		Type: otp.TypeHOTP, Seed: seeds[1], Algorithm: defaultAlgorithm(), Digits: 8,
	})

	step := time.Now().Unix() / period
	// ±1 stays inside a skew of 2 even if the step rolls over mid-test, and ±5
	// stays outside it.
	for _, tc := range []struct {
		offset int64
		accept bool
	}{{-1, true}, {0, true}, {1, true}, {-5, false}, {5, false}} {
		code, err := hotp.Generate(uint64(step + tc.offset))
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		err = totp.Authenticate(context.Background(), code)
		if tc.accept && err != nil {
			t.Errorf("step %+d should be inside the skew window: %v", tc.offset, err)
		}
		if !tc.accept && !errors.Is(err, otp.ErrInvalidCode) {
			t.Errorf("step %+d should be outside the skew window, got %v", tc.offset, err)
		}
	}
}

func TestIntegration_HOTP_EndToEnd(t *testing.T) {
	// Complete HOTP workflow with counter management
	auth := newAuthenticator(t, otp.Config{
		Type:        otp.TypeHOTP,
		Seed:        newSeed(t),
		Issuer:      "HOTPTest",
		AccountName: "hotp@example.com",
		Algorithm:   defaultAlgorithm(),
		Counter:     0,
	})

	ctx := context.Background()

	for counter := uint64(0); counter < 5; counter++ {
		t.Run(fmt.Sprintf("counter_%d", counter), func(t *testing.T) {
			code, err := auth.Generate(counter)
			if err != nil {
				t.Fatalf("Failed to generate code for counter %d: %v", counter, err)
			}

			newCounter, err := auth.ValidateCounter(ctx, code, counter)
			if err != nil {
				t.Errorf("Failed to validate code for counter %d: %v", counter, err)
			}
			if newCounter != counter+1 {
				t.Errorf("Expected counter %d, got %d", counter+1, newCounter)
			}

			// The code is still mathematically valid for its counter; replay
			// prevention is the application's, by persisting the counter.
			if _, err := auth.ValidateCounter(ctx, code, counter); err != nil {
				t.Errorf("Code should still be valid for counter %d: %v", counter, err)
			}

			if _, err := auth.ValidateCounter(ctx, code, counter+2); err == nil {
				t.Error("Code should not be valid for wrong counter")
			}
		})
	}
}

func TestIntegration_MultiUser(t *testing.T) {
	// Multiple users with different seeds
	ctx := context.Background()
	user1Seeds := seedCopies(t, 2)
	user2Seeds := seedCopies(t, 2)

	user1Auth := newAuthenticator(t, otp.Config{
		Type: otp.TypeTOTP, Seed: user1Seeds[0], Algorithm: defaultAlgorithm(),
		Issuer: "MultiUser", AccountName: "user1@example.com",
	})
	user2Auth := newAuthenticator(t, otp.Config{
		Type: otp.TypeTOTP, Seed: user2Seeds[0], Algorithm: defaultAlgorithm(),
		Issuer: "MultiUser", AccountName: "user2@example.com",
	})

	code1, err := user1Auth.Generate()
	if err != nil {
		t.Fatalf("Failed to generate code for user1: %v", err)
	}
	code2, err := user2Auth.Generate()
	if err != nil {
		t.Fatalf("Failed to generate code for user2: %v", err)
	}

	if err := user1Auth.Authenticate(ctx, code1); err != nil {
		t.Errorf("User1 code should validate for user1: %v", err)
	}
	if err := user2Auth.Authenticate(ctx, code2); err != nil {
		t.Errorf("User2 code should validate for user2: %v", err)
	}
	if code1 != code2 {
		if err := user1Auth.Authenticate(ctx, code2); err == nil {
			t.Error("User2 code should not validate for user1")
		}
		if err := user2Auth.Authenticate(ctx, code1); err == nil {
			t.Error("User1 code should not validate for user2")
		}
	}

	// HOTP counter independence
	hotpUser1 := newAuthenticator(t, otp.Config{
		Type: otp.TypeHOTP, Seed: user1Seeds[1], Algorithm: defaultAlgorithm(),
		Issuer: "MultiUser", AccountName: "hotp1@example.com",
	})
	hotpUser2 := newAuthenticator(t, otp.Config{
		Type: otp.TypeHOTP, Seed: user2Seeds[1], Algorithm: defaultAlgorithm(),
		Issuer: "MultiUser", AccountName: "hotp2@example.com",
	})

	hotpCode1, err := hotpUser1.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	hotpCode2, err := hotpUser2.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if _, err := hotpUser1.ValidateCounter(ctx, hotpCode1, 0); err != nil {
		t.Errorf("HOTP user1 should validate: %v", err)
	}
	if _, err := hotpUser2.ValidateCounter(ctx, hotpCode2, 0); err != nil {
		t.Errorf("HOTP user2 should validate: %v", err)
	}
}

func TestIntegration_ConcurrentAuthentication(t *testing.T) {
	auth := newAuthenticator(t, otp.Config{
		Type: otp.TypeTOTP, Seed: newSeed(t), Algorithm: defaultAlgorithm(),
		Issuer: "ConcurrentTest", AccountName: "concurrent@example.com",
	})

	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount, failCount atomic.Int32

	for range numGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := auth.Authenticate(context.Background(), code); err != nil {
				failCount.Add(1)
			} else {
				successCount.Add(1)
			}
		}()
	}
	wg.Wait()

	// All validations should succeed (TOTP is stateless)
	if successCount.Load() != numGoroutines {
		t.Errorf("Expected %d successes, got %d (failures: %d)", numGoroutines, successCount.Load(), failCount.Load())
	}
}

func TestIntegration_ConcurrentHOTP(t *testing.T) {
	auth := newAuthenticator(t, otp.Config{
		Type: otp.TypeHOTP, Seed: newSeed(t), Algorithm: defaultAlgorithm(),
		Issuer: "ConcurrentHOTP", AccountName: "hotp@example.com",
	})

	const numGoroutines = 20
	ctx := context.Background()

	code, err := auth.Generate(0)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	var wg sync.WaitGroup
	var successCount, failCount atomic.Int32
	for range numGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := auth.ValidateCounter(ctx, code, 0); err != nil {
				failCount.Add(1)
			} else {
				successCount.Add(1)
			}
		}()
	}
	wg.Wait()

	if successCount.Load() != numGoroutines {
		t.Errorf("Expected %d successes, got %d (failures: %d)",
			numGoroutines, successCount.Load(), failCount.Load())
	}
}

// TestIntegration_CloseWipesSeed proves the ownership contract end to end:
// the authenticator owns its seed, and Close wipes it.
func TestIntegration_CloseWipesSeed(t *testing.T) {
	seed := newSeed(t)
	auth, err := otp.NewAuthenticator(otp.Config{Type: otp.TypeTOTP, Seed: seed, Algorithm: defaultAlgorithm()})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if err := auth.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if seed.IsAlive() {
		t.Fatal("seed still alive after Close")
	}
	if _, err := auth.Generate(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("Generate after Close = %v, want ErrEnclaveDestroyed", err)
	}
}

func TestIntegration_ProvisioningURI(t *testing.T) {
	tests := []struct {
		name     string
		cfg      otp.Config
		expected string
	}{
		{
			name: "TOTP",
			cfg: otp.Config{
				Type: otp.TypeTOTP, Issuer: "TestApp", AccountName: "user@test.com",
				Algorithm: otp.AlgorithmSHA256, Digits: 8, Period: 60,
			},
			expected: "otpauth://totp/",
		},
		{
			name: "HOTP",
			cfg: otp.Config{
				Type: otp.TypeHOTP, Issuer: "TestApp", AccountName: "user@test.com",
				Algorithm: otp.AlgorithmSHA512, Digits: 7, Counter: 100,
			},
			expected: "otpauth://hotp/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := newSeed(t)
			want, err := otp.EncodeSecret(seed)
			if err != nil {
				t.Fatalf("EncodeSecret: %v", err)
			}
			tt.cfg.Seed = seed
			auth := newAuthenticator(t, tt.cfg)

			uri, err := auth.ProvisioningURI()
			if err != nil {
				t.Fatalf("ProvisioningURI: %v", err)
			}
			if len(uri) < len(tt.expected) || uri[:len(tt.expected)] != tt.expected {
				t.Fatalf("Expected URI to start with %s, got %s", tt.expected, uri)
			}

			parsed, err := url.Parse(uri)
			if err != nil {
				t.Fatalf("parse URI: %v", err)
			}
			q := parsed.Query()
			if q.Get("secret") != want {
				t.Error("URI secret does not match the seed")
			}
			if q.Get("issuer") != "TestApp" {
				t.Errorf("issuer = %q", q.Get("issuer"))
			}
			if q.Get("algorithm") != string(tt.cfg.Algorithm) {
				t.Errorf("algorithm = %q, want %q", q.Get("algorithm"), tt.cfg.Algorithm)
			}
			if q.Get("digits") != fmt.Sprint(tt.cfg.Digits) {
				t.Errorf("digits = %q, want %d", q.Get("digits"), tt.cfg.Digits)
			}
			typeParam := map[otp.Type]string{otp.TypeTOTP: "period", otp.TypeHOTP: "counter"}[tt.cfg.Type]
			if q.Get(typeParam) == "" {
				t.Errorf("%s URI missing %s parameter", tt.cfg.Type, typeParam)
			}
		})
	}
}

func TestIntegration_ErrorHandling(t *testing.T) {
	auth := newAuthenticator(t, otp.Config{
		Type: otp.TypeTOTP, Seed: newSeed(t), Algorithm: defaultAlgorithm(),
		Issuer: "ErrorTest", AccountName: "error@test.com",
	})

	tests := []struct {
		name string
		code string
	}{
		{"empty_code", ""},
		{"too_short", "123"},
		{"too_long", "1234567890"},
		{"invalid_chars", "abcdef"},
		{"special_chars", "12@#$%"},
		{"spaces", "12 34 56"},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := auth.Authenticate(ctx, tt.code); err == nil {
				t.Errorf("Expected error for invalid code %q", tt.code)
			}
		})
	}

	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	t.Run("context_cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := auth.Authenticate(ctx, code); !errors.Is(err, context.Canceled) {
			t.Errorf("Expected context.Canceled, got %v", err)
		}
	})

	t.Run("context_timeout", func(t *testing.T) {
		// A deadline in the past has expired by construction; no waiting.
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		if err := auth.Authenticate(ctx, code); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Expected context.DeadlineExceeded, got %v", err)
		}
	})
}

func TestIntegration_SeedGeneration(t *testing.T) {
	// Generate many seeds and ensure they're unique and usable
	seen := make(map[string]bool)
	const count = 100

	for i := range count {
		seed := newSeed(t)
		encoded, err := otp.EncodeSecret(seed)
		if err != nil {
			t.Fatalf("EncodeSecret %d: %v", i, err)
		}
		if seen[encoded] {
			t.Fatalf("Duplicate seed generated at %d", i)
		}
		seen[encoded] = true

		auth, err := otp.NewAuthenticator(otp.Config{
			Type: otp.TypeTOTP, Seed: seed, Algorithm: defaultAlgorithm(),
			Issuer: "SeedTest", AccountName: fmt.Sprintf("test%d@example.com", i),
		})
		if err != nil {
			t.Fatalf("Failed to create authenticator with generated seed: %v", err)
		}
		if err := auth.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	if len(seen) != count {
		t.Errorf("Expected %d unique seeds, got %d", count, len(seen))
	}
}
