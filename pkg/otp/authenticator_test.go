package otp

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"
)

// TestNewAuthenticator tests authenticator construction
func TestNewAuthenticator(t *testing.T) {
	tests := []struct {
		name    string
		cfg     func(t *testing.T) Config
		wantErr error
	}{
		{
			name: "valid TOTP config",
			cfg: func(t *testing.T) Config {
				return Config{
					Type: TypeTOTP, Seed: testSeed(t), Issuer: "TestApp", AccountName: "user@example.com",
					Digits: 6, Period: 30, Algorithm: testAlgorithm(), Skew: 1,
				}
			},
		},
		{
			name: "valid HOTP config",
			cfg: func(t *testing.T) Config {
				return Config{
					Type: TypeHOTP, Seed: testSeed(t), Issuer: "TestApp", AccountName: "user@example.com",
					Digits: 6, Counter: 0, Algorithm: testAlgorithm(),
				}
			},
		},
		{
			name: "valid SHA256 config",
			cfg: func(t *testing.T) Config {
				return Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: AlgorithmSHA256}
			},
		},
		{
			name: "valid SHA512 config",
			cfg: func(t *testing.T) Config {
				return Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: AlgorithmSHA512}
			},
		},
		{
			name: "valid 7 digit config",
			cfg: func(t *testing.T) Config {
				return Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: testAlgorithm(), Digits: 7}
			},
		},
		{
			name: "valid 8 digit config",
			cfg: func(t *testing.T) Config {
				return Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: testAlgorithm(), Digits: 8}
			},
		},
		{
			name: "missing seed",
			cfg: func(t *testing.T) Config {
				return Config{Type: TypeTOTP, Algorithm: testAlgorithm()}
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "destroyed seed",
			cfg: func(t *testing.T) Config {
				seed := testSeed(t)
				seed.Destroy()
				return Config{Type: TypeTOTP, Seed: seed, Algorithm: testAlgorithm()}
			},
			wantErr: enclave.ErrEnclaveDestroyed,
		},
		{
			name: "invalid type",
			cfg: func(t *testing.T) Config {
				return Config{Type: "invalid", Seed: testSeed(t), Algorithm: testAlgorithm()}
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "invalid digits",
			cfg: func(t *testing.T) Config {
				return Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: testAlgorithm(), Digits: 5}
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "invalid algorithm",
			cfg: func(t *testing.T) Config {
				return Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: "MD5"}
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "skew above the bound",
			cfg: func(t *testing.T) Config {
				return Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: testAlgorithm(), Skew: maxSkew + 1}
			},
			wantErr: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewAuthenticator(tt.cfg(t))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				if auth != nil {
					t.Errorf("expected no authenticator alongside the error, got %v", auth)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if auth == nil {
				t.Fatal("expected authenticator, got nil")
			}
			if err := auth.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
}

// TestNewAuthenticatorTakesOwnership pins the ownership contract: the seed
// passes to the authenticator on every return path. A caller that has handed
// a seed to NewAuthenticator never has to work out whether it is still theirs
// to destroy — it never is.
func TestNewAuthenticatorTakesOwnership(t *testing.T) {
	t.Run("success, then Close destroys the seed", func(t *testing.T) {
		seed := testSeed(t)
		auth, err := NewAuthenticator(Config{Type: TypeTOTP, Seed: seed, Algorithm: testAlgorithm()})
		if err != nil {
			t.Fatalf("NewAuthenticator: %v", err)
		}
		if !seed.IsAlive() {
			t.Fatal("seed destroyed by a successful construction")
		}
		if err := auth.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if seed.IsAlive() {
			t.Fatal("seed still alive after Close: the authenticator owns it and must wipe it")
		}
		// Close is idempotent, so it can be deferred alongside an explicit call.
		if err := auth.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
	})

	t.Run("rejected configuration destroys the seed", func(t *testing.T) {
		seed := testSeed(t)
		if _, err := NewAuthenticator(Config{Type: "invalid", Seed: seed}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("NewAuthenticator = %v, want ErrInvalidConfig", err)
		}
		if seed.IsAlive() {
			t.Fatal("seed survived a rejected configuration: ownership passes on every path")
		}
	})

	t.Run("nil authenticator", func(t *testing.T) {
		var auth *Authenticator
		if err := auth.Close(); !errors.Is(err, ErrNilAuthenticator) {
			t.Fatalf("nil Close = %v, want ErrNilAuthenticator", err)
		}
	})
}

// TestClosedAuthenticatorFailsClosed proves nothing in the authenticator can
// derive a code once its seed is gone. A cached plaintext copy anywhere in the
// type — a decoded []byte, a string field, a memoised HMAC state — would let
// these calls keep succeeding.
func TestClosedAuthenticatorFailsClosed(t *testing.T) {
	auth, err := NewAuthenticator(Config{
		Type: TypeHOTP, Seed: testSeed(t), Algorithm: testAlgorithm(), Counter: 1,
		Issuer: "TestApp", AccountName: "user@example.com",
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	code, err := auth.Generate(1)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := auth.Authenticate(context.Background(), code); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// The rendered authenticator must not carry the seed in any form.
	rendered := fmt.Sprintf("%#v %+v %v", auth, auth, auth)
	for _, form := range []string{rfcKeySHA1, testSeedBase32} {
		if strings.Contains(rendered, form) {
			t.Errorf("authenticator rendered the seed %q: %s", form, rendered)
		}
	}

	if err := auth.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := auth.Generate(1); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Errorf("Generate after Close = %v, want ErrEnclaveDestroyed", err)
	}
	err = auth.Authenticate(context.Background(), code)
	if !errors.Is(err, ErrInvalidCode) || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Errorf("Authenticate after Close = %v, want ErrInvalidCode and ErrEnclaveDestroyed", err)
	}
	if _, err := auth.ValidateCounter(context.Background(), code, 1); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("ValidateCounter after Close = %v, want ErrInvalidCode", err)
	}
	if uri, err := auth.ProvisioningURI(); !errors.Is(err, enclave.ErrEnclaveDestroyed) || uri != "" {
		t.Errorf("ProvisioningURI after Close = %q, %v; want empty and ErrEnclaveDestroyed", uri, err)
	}
}

// TestCloseDuringAuthentication runs Close against in-flight validations. The
// enclave's read lock makes Close wait out every borrow, so each validation
// either completes against the live seed or fails cleanly against a destroyed
// one — never reads unmapped pages. Run under -race by the root test-race
// target.
func TestCloseDuringAuthentication(t *testing.T) {
	auth, err := NewAuthenticator(Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: testAlgorithm()})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	const workers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := auth.Authenticate(context.Background(), code)
			if err != nil && !errors.Is(err, enclave.ErrEnclaveDestroyed) {
				errs <- err
			}
		}()
	}

	close(start)
	if err := auth.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("validation racing Close failed for a reason other than the closed seed: %v", err)
	}
}

// TestAuthenticateTOTP tests TOTP validation
func TestAuthenticateTOTP(t *testing.T) {
	auth, err := NewAuthenticator(Config{
		Type: TypeTOTP, Seed: testSeed(t), Issuer: "TestApp", AccountName: "user@example.com",
		Digits: 6, Period: 30, Algorithm: testAlgorithm(), Skew: 1,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	tests := []struct {
		name    string
		ctx     context.Context
		code    string
		wantErr error
	}{
		{name: "valid code", ctx: context.Background(), code: code},
		{name: "nil context", ctx: nil, code: code},
		{name: "invalid code", ctx: context.Background(), code: wrongCode(code), wantErr: ErrInvalidCode},
		{name: "empty code", ctx: context.Background(), code: "", wantErr: ErrInvalidCode},
		{name: "blank code", ctx: context.Background(), code: "   ", wantErr: ErrInvalidCode},
		{name: "wrong length code", ctx: context.Background(), code: "12345", wantErr: ErrInvalidCode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.Authenticate(tt.ctx, tt.code) //nolint:staticcheck // nil context is part of the contract under test
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// wrongCode returns a code of the same length that differs from code in every
// digit, so the test cannot be satisfied by the one-in-a-million chance that a
// fixed "000000" happens to be current.
func wrongCode(code string) string {
	b := []byte(code)
	for i := range b {
		b[i] = '0' + (b[i]-'0'+1)%10
	}
	return string(b)
}

// TestAuthenticateHOTP tests HOTP validation
func TestAuthenticateHOTP(t *testing.T) {
	auth, err := NewAuthenticator(Config{
		Type: TypeHOTP, Seed: testSeed(t), Digits: 6, Counter: 0, Algorithm: testAlgorithm(),
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	code, err := auth.Generate(0)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	if err := auth.Authenticate(context.Background(), code); err != nil {
		t.Errorf("Authenticate at the configured counter: %v", err)
	}

	newCounter, err := auth.ValidateCounter(context.Background(), code, 0)
	if err != nil {
		t.Errorf("failed to validate counter: %v", err)
	}
	if newCounter != 1 {
		t.Errorf("expected new counter 1, got %d", newCounter)
	}

	if _, err = auth.ValidateCounter(context.Background(), code, 5); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("ValidateCounter at the wrong counter = %v, want ErrInvalidCode", err)
	}
}

// TestValidateCounter tests HOTP counter validation
func TestValidateCounter(t *testing.T) {
	auth, err := NewAuthenticator(Config{Type: TypeHOTP, Seed: testSeed(t), Algorithm: testAlgorithm()})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	for _, counter := range []uint64{0, 5, 100} {
		t.Run(fmt.Sprintf("counter %d", counter), func(t *testing.T) {
			code, err := auth.Generate(counter)
			if err != nil {
				t.Fatalf("failed to generate code: %v", err)
			}
			next, err := auth.ValidateCounter(context.Background(), code, counter)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if next != counter+1 {
				t.Errorf("expected counter %d, got %d", counter+1, next)
			}
		})
	}

	t.Run("empty code", func(t *testing.T) {
		if _, err := auth.ValidateCounter(context.Background(), "", 0); !errors.Is(err, ErrInvalidCode) {
			t.Errorf("expected ErrInvalidCode, got %v", err)
		}
	})

	t.Run("nil context", func(t *testing.T) {
		code, err := auth.Generate(0)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		//nolint:staticcheck // nil context is part of the contract under test
		if next, err := auth.ValidateCounter(nil, code, 0); err != nil || next != 1 {
			t.Errorf("ValidateCounter(nil ctx) = %d, %v; want 1, nil", next, err)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := auth.ValidateCounter(ctx, "123456", 0); !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})
}

// TestTOTPValidateCounterError tests TOTP ValidateCounter returns error
func TestTOTPValidateCounterError(t *testing.T) {
	auth, err := NewAuthenticator(Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: testAlgorithm()})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	if _, err := auth.ValidateCounter(context.Background(), "123456", 0); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

// TestGenerate tests code generation lengths
func TestGenerate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		typ    Type
		digits uint
	}{
		{"TOTP", TypeTOTP, 6},
		{"HOTP", TypeHOTP, 6},
		{"7 digits", TypeTOTP, 7},
		{"8 digits", TypeTOTP, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth, err := NewAuthenticator(Config{
				Type: tc.typ, Seed: testSeed(t), Algorithm: testAlgorithm(), Digits: tc.digits,
			})
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}
			t.Cleanup(func() { _ = auth.Close() })

			code, err := auth.Generate(0)
			if err != nil {
				t.Fatalf("failed to generate code: %v", err)
			}
			if uint(len(code)) != tc.digits {
				t.Errorf("expected %d digit code, got %q", tc.digits, code)
			}
		})
	}
}

// TestHOTPWithoutCounter tests HOTP generate without counter
func TestHOTPWithoutCounter(t *testing.T) {
	auth, err := NewAuthenticator(Config{Type: TypeHOTP, Seed: testSeed(t), Algorithm: testAlgorithm()})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	if _, err := auth.Generate(); !errors.Is(err, ErrCounterRequired) {
		t.Fatalf("Generate without a counter = %v, want ErrCounterRequired", err)
	}
}

// TestProvisioningURI checks the Key URI Format output field by field.
func TestProvisioningURI(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		wantPath string
		want     map[string]string
	}{
		{
			name:     "TOTP",
			cfg:      Config{Type: TypeTOTP, Issuer: "TestApp", AccountName: "user@example.com", Algorithm: AlgorithmSHA256},
			wantPath: "/TestApp:user@example.com",
			want: map[string]string{
				"secret": testSeedBase32, "issuer": "TestApp", "algorithm": "SHA256",
				"digits": "6", "period": "30",
			},
		},
		{
			name:     "HOTP",
			cfg:      Config{Type: TypeHOTP, Issuer: "TestApp", AccountName: "user@example.com", Algorithm: AlgorithmSHA512, Counter: 42, Digits: 8},
			wantPath: "/TestApp:user@example.com",
			want: map[string]string{
				"secret": testSeedBase32, "issuer": "TestApp", "algorithm": "SHA512",
				"digits": "8", "counter": "42",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.Seed = testSeed(t)
			auth, err := NewAuthenticator(tt.cfg)
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}
			t.Cleanup(func() { _ = auth.Close() })

			uri, err := auth.ProvisioningURI()
			if err != nil {
				t.Fatalf("ProvisioningURI: %v", err)
			}
			parsed, err := url.Parse(uri)
			if err != nil {
				t.Fatalf("parse %q: %v", uri, err)
			}
			if parsed.Scheme != "otpauth" || parsed.Host != string(tt.cfg.Type) {
				t.Errorf("URI %q: scheme/type = %s/%s, want otpauth/%s", uri, parsed.Scheme, parsed.Host, tt.cfg.Type)
			}
			if parsed.Path != tt.wantPath {
				t.Errorf("URI label = %q, want %q", parsed.Path, tt.wantPath)
			}
			q := parsed.Query()
			for k, v := range tt.want {
				if got := q.Get(k); got != v {
					t.Errorf("URI parameter %s = %q, want %q", k, got, v)
				}
			}
		})
	}

	var nilAuth *Authenticator
	if _, err := nilAuth.ProvisioningURI(); !errors.Is(err, ErrNilAuthenticator) {
		t.Fatalf("nil ProvisioningURI = %v, want ErrNilAuthenticator", err)
	}
}

// TestContextCancellation tests context cancellation and expiry
func TestContextCancellation(t *testing.T) {
	auth, err := NewAuthenticator(Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: testAlgorithm()})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := auth.Authenticate(canceled, code); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	// A deadline already in the past has expired by construction; no waiting.
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if err := auth.Authenticate(expired, code); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

// TestNilAuthenticator tests operations on nil authenticator
func TestNilAuthenticator(t *testing.T) {
	var auth *Authenticator

	if err := auth.Authenticate(context.Background(), "123456"); !errors.Is(err, ErrNilAuthenticator) {
		t.Errorf("Authenticate: expected ErrNilAuthenticator, got %v", err)
	}
	if _, err := auth.ValidateCounter(context.Background(), "123456", 0); !errors.Is(err, ErrNilAuthenticator) {
		t.Errorf("ValidateCounter: expected ErrNilAuthenticator, got %v", err)
	}
	if _, err := auth.Generate(); !errors.Is(err, ErrNilAuthenticator) {
		t.Errorf("Generate: expected ErrNilAuthenticator, got %v", err)
	}
}

// TestAlgorithms round-trips every digest this process can execute.
func TestAlgorithms(t *testing.T) {
	for _, algo := range testAlgorithms() {
		t.Run(string(algo), func(t *testing.T) {
			auth, err := NewAuthenticator(Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: algo})
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}
			t.Cleanup(func() { _ = auth.Close() })

			code, err := auth.Generate()
			if err != nil {
				t.Fatalf("failed to generate code: %v", err)
			}
			if err := auth.Authenticate(context.Background(), code); err != nil {
				t.Errorf("failed to authenticate: %v", err)
			}
		})
	}
}

// TestHOTPRoundTripHonoursConfig is the regression test for HOTP validation
// ignoring the configured algorithm and digit count: every combination must
// validate the codes it generates, through both validation entry points.
func TestHOTPRoundTripHonoursConfig(t *testing.T) {
	const counter = 7

	for _, algo := range testAlgorithms() {
		for _, digits := range []uint{6, 7, 8} {
			t.Run(fmt.Sprintf("%s/%d", algo, digits), func(t *testing.T) {
				auth, err := NewAuthenticator(Config{
					Type: TypeHOTP, Seed: testSeed(t), Algorithm: algo, Digits: digits, Counter: counter,
				})
				if err != nil {
					t.Fatalf("failed to create authenticator: %v", err)
				}
				t.Cleanup(func() { _ = auth.Close() })

				code, err := auth.Generate(counter)
				if err != nil {
					t.Fatalf("failed to generate code: %v", err)
				}
				if uint(len(code)) != digits {
					t.Fatalf("expected %d digit code, got %d", digits, len(code))
				}
				if err := auth.Authenticate(context.Background(), code); err != nil {
					t.Errorf("Authenticate rejected a code it generated: %v", err)
				}
				next, err := auth.ValidateCounter(context.Background(), code, counter)
				if err != nil {
					t.Errorf("ValidateCounter rejected a code it generated: %v", err)
				}
				if next != counter+1 {
					t.Errorf("expected counter %d, got %d", counter+1, next)
				}
			})
		}
	}
}

// TestDefaults tests default configuration values. The omitted algorithm
// resolves to RFC 6238's SHA-1 default; under FIPS 140-only mode it is refused
// instead, which TestOmittedAlgorithmRefusedUnderFIPS and TestFIPSActivation
// cover.
func TestDefaults(t *testing.T) {
	if fips140OnlyActive() {
		t.Skip("FIPS 140-only mode is active: an omitted algorithm is refused (TestFIPSActivation)")
	}

	auth, err := NewAuthenticator(Config{Type: TypeTOTP, Seed: testSeed(t)})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	if auth.cfg.Algorithm != AlgorithmSHA1 || auth.cfg.Digits != 6 || auth.cfg.Period != 30 || auth.cfg.Skew != 1 {
		t.Errorf("defaults = %s/%d digits/%ds/skew %d; want SHA1/6/30/1",
			auth.cfg.Algorithm, auth.cfg.Digits, auth.cfg.Period, auth.cfg.Skew)
	}

	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}
	if err := auth.Authenticate(context.Background(), code); err != nil {
		t.Errorf("failed to authenticate with defaults: %v", err)
	}
}

// TestTOTPSkewThroughAuthenticator drives the skew window through the public
// path, deriving neighboring time steps with an HOTP authenticator over the
// same seed — RFC 6238 §4 defines TOTP as HOTP over the time step, so this
// needs no clock control.
func TestTOTPSkewThroughAuthenticator(t *testing.T) {
	const period = 30
	totp, err := NewAuthenticator(Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: testAlgorithm(), Period: period, Skew: 2, Digits: 8})
	if err != nil {
		t.Fatalf("NewAuthenticator(TOTP): %v", err)
	}
	t.Cleanup(func() { _ = totp.Close() })
	hotp, err := NewAuthenticator(Config{Type: TypeHOTP, Seed: testSeed(t), Algorithm: testAlgorithm(), Digits: 8})
	if err != nil {
		t.Fatalf("NewAuthenticator(HOTP): %v", err)
	}
	t.Cleanup(func() { _ = hotp.Close() })

	now := totpCounter(time.Now(), period)
	// ±1 stays inside a skew of 2 even if the step rolls over mid-test; ±5 stays
	// outside it for the same reason. Eight digits make a chance collision
	// between an outside code and one inside the window negligible.
	for _, tc := range []struct {
		offset int64
		accept bool
	}{{-1, true}, {0, true}, {1, true}, {-5, false}, {5, false}} {
		code, err := hotp.Generate(uint64(int64(now) + tc.offset))
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		err = totp.Authenticate(context.Background(), code)
		if tc.accept && err != nil {
			t.Errorf("step %+d rejected inside skew 2: %v", tc.offset, err)
		}
		if !tc.accept && !errors.Is(err, ErrInvalidCode) {
			t.Errorf("step %+d = %v outside skew 2, want ErrInvalidCode", tc.offset, err)
		}
	}
}
