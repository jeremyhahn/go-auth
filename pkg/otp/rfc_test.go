package otp

import (
	"errors"
	"math"
	"testing"
	"time"
)

// TestDeriveCodeRFC4226Vectors checks the HOTP core against the reference
// values in RFC 4226 Appendix D. This is what says the in-repo derivation is
// the standard one and not merely self-consistent.
//
// The vectors are defined over HMAC-SHA-1 only. Under fips140=only the same
// call must come back as a typed refusal instead — reaching crypto/hmac there
// would panic.
func TestDeriveCodeRFC4226Vectors(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}

	for counter, code := range want {
		got, err := deriveCode([]byte(rfcKeySHA1), uint64(counter), 6, AlgorithmSHA1)
		if fips140OnlyActive() {
			if !errors.Is(err, ErrFIPSUnsupported) {
				t.Fatalf("counter %d under fips140=only = %q, %v; want ErrFIPSUnsupported", counter, got, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("counter %d: %v", counter, err)
		}
		if got != code {
			t.Errorf("counter %d = %s, want %s", counter, got, code)
		}
	}
}

// TestDeriveCodeRFC6238Vectors checks the TOTP core against RFC 6238
// Appendix B, which covers all three digests at 8 digits. SHA-256 and SHA-512
// run in every mode; SHA-1 is refused, typed, under fips140=only.
func TestDeriveCodeRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		sha1 string
		s256 string
		s512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}

	for _, tc := range cases {
		counter := totpCounter(time.Unix(tc.unix, 0).UTC(), 30)

		for _, sub := range []struct {
			name string
			key  string
			algo Algorithm
			want string
		}{
			{"SHA1", rfcKeySHA1, AlgorithmSHA1, tc.sha1},
			{"SHA256", rfcKeySHA256, AlgorithmSHA256, tc.s256},
			{"SHA512", rfcKeySHA512, AlgorithmSHA512, tc.s512},
		} {
			got, err := deriveCode([]byte(sub.key), counter, 8, sub.algo)
			if fips140OnlyActive() && sub.algo == AlgorithmSHA1 {
				if !errors.Is(err, ErrFIPSUnsupported) {
					t.Errorf("%s at %d under fips140=only = %q, %v; want ErrFIPSUnsupported", sub.name, tc.unix, got, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s at %d: %v", sub.name, tc.unix, err)
			}
			if got != sub.want {
				t.Errorf("%s at %d = %s, want %s", sub.name, tc.unix, got, sub.want)
			}
		}
	}
}

// TestRFC6238VectorsThroughAuthenticator drives the Appendix B values through
// the public enclave path rather than deriveCode, so the seed handling — the
// enclave borrow, the time-step conversion, the constant-time comparison — is
// held to the standard too, not just the HMAC core.
func TestRFC6238VectorsThroughAuthenticator(t *testing.T) {
	for _, sub := range []struct {
		algo Algorithm
		key  string
		at   int64
		want string
	}{
		{AlgorithmSHA1, rfcKeySHA1, 1111111109, "07081804"},
		{AlgorithmSHA256, rfcKeySHA256, 1111111109, "68084774"},
		{AlgorithmSHA512, rfcKeySHA512, 1111111109, "25091201"},
	} {
		t.Run(string(sub.algo), func(t *testing.T) {
			if fips140OnlyActive() && sub.algo == AlgorithmSHA1 {
				t.Skip("FIPS 140-only mode is active: HMAC-SHA-1 is refused; see TestFIPSActivation")
			}
			auth, err := NewAuthenticator(Config{Type: TypeHOTP, Seed: newSeed(t, sub.key), Algorithm: sub.algo, Digits: 8})
			if err != nil {
				t.Fatalf("NewAuthenticator: %v", err)
			}
			t.Cleanup(func() { _ = auth.Close() })

			got, err := auth.Generate(totpCounter(time.Unix(sub.at, 0), 30))
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if got != sub.want {
				t.Errorf("Generate = %s, want %s", got, sub.want)
			}
		})
	}
}

func TestDeriveCodeRejectsBadInput(t *testing.T) {
	algo := testAlgorithm()
	if _, err := deriveCode(nil, 0, 6, algo); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("empty key = %v, want ErrInvalidConfig", err)
	}
	if _, err := deriveCode([]byte(rfcKeySHA1), 0, 9, algo); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("9 digits = %v, want ErrInvalidConfig", err)
	}
	if _, err := deriveCode([]byte(rfcKeySHA1), 0, 6, Algorithm("MD5")); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("unknown algorithm = %v, want ErrInvalidConfig", err)
	}
}

func TestCodesMatch(t *testing.T) {
	for _, tc := range []struct {
		derived, submitted string
		want               bool
	}{
		{"123456", "123456", true},
		{"123456", "123457", false},
		{"123456", "12345", false},
		{"123456", "1234567", false},
		{"123456", "", false},
	} {
		if got := codesMatch(tc.derived, tc.submitted); got != tc.want {
			t.Errorf("codesMatch(%q, %q) = %v, want %v", tc.derived, tc.submitted, got, tc.want)
		}
	}
}

func TestValidateTOTPSkewWindow(t *testing.T) {
	algo := testAlgorithm()
	key := []byte(rfcKeySHA1)
	now := time.Unix(1111111109, 0).UTC()

	// A code from the step before and the step after must both validate at
	// skew 1, and neither at skew 0.
	for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		code, err := deriveCode(key, totpCounter(now.Add(offset), 30), 8, algo)
		if err != nil {
			t.Fatalf("derive: %v", err)
		}

		valid, err := validateTOTP(key, code, now, 30, 1, 8, algo)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if !valid {
			t.Errorf("code at offset %s rejected inside the skew window", offset)
		}

		valid, err = validateTOTP(key, code, now, 30, 0, 8, algo)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if valid != (offset == 0) {
			t.Errorf("code at offset %s with skew 0: valid = %v, want %v", offset, valid, offset == 0)
		}
	}

	// Two steps out is outside a skew of 1.
	code, err := deriveCode(key, totpCounter(now.Add(60*time.Second), 30), 8, algo)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	valid, err := validateTOTP(key, code, now, 30, 1, 8, algo)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if valid {
		t.Error("code two steps out was accepted at skew 1")
	}
}

// TestSkewIsBounded covers both halves of the guard: a configuration asking
// for a window this package will not honor is rejected at construction, and
// the derivation itself cannot be made to iterate an unbounded number of
// steps — including at the very top of the counter range, where an unchecked
// `c <= last` loop would never terminate.
func TestSkewIsBounded(t *testing.T) {
	algo := testAlgorithm()

	auth, err := NewAuthenticator(Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: algo, Skew: maxSkew})
	if err != nil {
		t.Fatalf("skew of %d rejected: %v", maxSkew, err)
	}
	_ = auth.Close()
	if _, err := NewAuthenticator(Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: algo, Skew: maxSkew + 1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("skew of %d = %v, want ErrInvalidConfig", maxSkew+1, err)
	}
	if _, err := NewAuthenticator(Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: algo, Skew: 1 << 40}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("huge skew = %v, want ErrInvalidConfig", err)
	}

	// Directly, with a skew no configuration could get past validate and a
	// time at the top of what a counter can represent. Any wrap in the loop
	// bounds would hang this test rather than fail it, so it runs against a
	// bound instead of trusting it.
	done := make(chan struct{})
	go func() {
		defer close(done)

		raw := []byte(rfcKeySHA1)
		now := time.Unix(1111111109, 0).UTC()
		code, err := deriveCode(raw, totpCounter(now, 30), 6, algo)
		if err != nil {
			t.Errorf("derive: %v", err)
			return
		}
		valid, err := validateTOTP(raw, code, now, 30, math.MaxUint32, 6, algo)
		if err != nil {
			t.Errorf("validate: %v", err)
			return
		}
		if !valid {
			t.Error("clamped skew dropped the current time step")
		}

		// A time step near the top of the range: first+i must not wrap.
		if _, err := validateTOTP(raw, code, time.Unix(math.MaxInt64/int64(time.Second), 0).UTC(), 1, maxSkew, 6, algo); err != nil {
			t.Errorf("validate at the top of the counter range: %v", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("validateTOTP did not terminate")
	}
}

func TestValidateTOTPNearEpoch(t *testing.T) {
	// The skew window is clamped at zero: subtracting past the epoch would
	// wrap a uint64 and check the top of the counter range.
	algo := testAlgorithm()
	key := []byte(rfcKeySHA1)
	now := time.Unix(0, 0).UTC()

	code, err := deriveCode(key, 0, 6, algo)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	valid, err := validateTOTP(key, code, now, 30, 5, 6, algo)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !valid {
		t.Error("code at the epoch was rejected")
	}

	// Before the epoch there is no time step; it must not wrap either.
	if got := totpCounter(time.Unix(-1, 0), 30); got != 0 {
		t.Errorf("totpCounter before the epoch = %d, want 0", got)
	}
}
