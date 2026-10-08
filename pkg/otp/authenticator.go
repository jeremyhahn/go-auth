package otp

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
)

// Type represents the OTP algorithm type.
type Type string

const (
	// TypeTOTP represents Time-based OTP (RFC 6238).
	TypeTOTP Type = "totp"
	// TypeHOTP represents Counter-based OTP (RFC 4226).
	TypeHOTP Type = "hotp"
)

// validTypes is the set of OTP types the package accepts.
var validTypes = map[Type]bool{TypeTOTP: true, TypeHOTP: true}

// Algorithm represents the hash algorithm used for OTP generation.
type Algorithm string

const (
	// AlgorithmSHA1 uses SHA1 hash algorithm. It is RFC 6238's default and
	// what mainstream authenticator apps enroll with, and it is refused under
	// FIPS 140-only mode; see ErrFIPSUnsupported.
	AlgorithmSHA1 Algorithm = "SHA1"
	// AlgorithmSHA256 uses SHA256 hash algorithm.
	AlgorithmSHA256 Algorithm = "SHA256"
	// AlgorithmSHA512 uses SHA512 hash algorithm.
	AlgorithmSHA512 Algorithm = "SHA512"
)

// Defaults applied by NewAuthenticator to zero-valued Config fields.
const (
	defaultDigits = 6
	defaultPeriod = 30
	defaultSkew   = 1
)

// defaultAlgorithm is the digest an omitted Config.Algorithm resolves to
// outside FIPS 140-only mode: HMAC-SHA-1, RFC 6238 §1.2's TOTP default and RFC
// 4226 §5.1's HOTP digest, and what mainstream authenticator apps enroll with.
// Under FIPS 140-only mode an omitted algorithm is refused instead; see
// checkFIPSAlgorithmNamed.
const defaultAlgorithm = AlgorithmSHA1

// Common errors returned by the OTP authenticator.
var (
	// ErrInvalidCode indicates the provided OTP code is invalid.
	ErrInvalidCode = errors.New("otp: invalid code")
	// ErrInvalidConfig indicates the configuration is invalid.
	ErrInvalidConfig = errors.New("otp: invalid configuration")
	// ErrExpiredCode indicates the OTP code has expired (TOTP only).
	ErrExpiredCode = errors.New("otp: code expired")
	// ErrNilAuthenticator indicates a nil authenticator was used.
	ErrNilAuthenticator = errors.New("otp: authenticator is nil")
	// ErrCounterRequired indicates Generate was called on an HOTP
	// authenticator without a counter.
	ErrCounterRequired = errors.New("otp: counter required for HOTP generation")
	// ErrMissingCode indicates Authenticate or ValidateCounter was called
	// without a live code enclave. It always comes joined with
	// ErrInvalidCode, and a destroyed code also matches
	// enclave.ErrEnclaveDestroyed.
	ErrMissingCode = errors.New("otp: code must not be empty")
)

// Config holds OTP authenticator configuration.
type Config struct {
	// Type specifies the OTP type (TOTP or HOTP).
	Type Type
	// Seed is the shared HMAC key — RFC 4226's K — held in locked memory.
	// Build one with GenerateProtectedSecret for a new enrollment, or with
	// DecodeSeed from a stored base32 seed.
	//
	// NewAuthenticator TAKES OWNERSHIP of the seed on every return path,
	// success or failure, the same contract enclave.NewMemoryEnclave has for
	// its input: on success the authenticator destroys it in Close, and on
	// failure NewAuthenticator destroys it before returning. Two authenticators
	// over the same key therefore need two enclaves.
	Seed *enclave.MemoryEnclave
	// Issuer is the name of the issuing organization (e.g., "MyApp").
	Issuer string
	// AccountName is the account identifier (e.g., "user@example.com").
	AccountName string
	// Digits specifies the number of digits in the OTP code (6, 7, or 8).
	// Default: 6
	Digits uint
	// Period specifies the time step in seconds for TOTP.
	// Default: 30
	Period uint
	// Counter specifies the initial counter value for HOTP.
	// Default: 0
	Counter uint64
	// Algorithm specifies the hash algorithm to use.
	// Default: SHA1 (RFC 6238 §1.2). Under FIPS 140-only mode it must be set
	// explicitly to SHA256 or SHA512: SHA1 and an omitted algorithm are both
	// refused with ErrFIPSUnsupported.
	Algorithm Algorithm
	// Skew specifies the number of time periods to check before and after
	// the current time for TOTP validation (tolerance for clock skew).
	// It may not exceed 10: a wider window keeps every code valid for longer,
	// and costs an HMAC per step. RFC 6238 §5.2 asks for the smallest window a
	// deployment can tolerate.
	// Default: 1
	Skew uint
}

// withDefaults returns c with every zero-valued tunable replaced by its
// default.
func (c Config) withDefaults() Config {
	if c.Digits == 0 {
		c.Digits = defaultDigits
	}
	if c.Period == 0 {
		c.Period = defaultPeriod
	}
	if c.Algorithm == "" {
		c.Algorithm = defaultAlgorithm
	}
	if c.Skew == 0 {
		c.Skew = defaultSkew
	}
	return c
}

// validate checks that a defaulted configuration is valid. It reads the seed's
// size and liveness, never its contents.
func (c Config) validate() error {
	if !validTypes[c.Type] {
		return fmt.Errorf("%w: type must be 'totp' or 'hotp'", ErrInvalidConfig)
	}

	if c.Seed == nil {
		return fmt.Errorf("%w: seed must not be nil", ErrInvalidConfig)
	}
	if !c.Seed.IsAlive() {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, enclave.ErrEnclaveDestroyed)
	}

	if _, ok := digitsModulus[c.Digits]; !ok {
		return fmt.Errorf("%w: digits must be 6, 7, or 8", ErrInvalidConfig)
	}

	// An unbounded window is both a security choice made by accident — every
	// extra step keeps a code valid for another period — and an amount of HMAC
	// work proportional to it; see maxSkew.
	if c.Skew > maxSkew {
		return fmt.Errorf("%w: skew must be at most %d time steps (got %d); "+
			"clock drift beyond that is a clock problem, not a validation window",
			ErrInvalidConfig, maxSkew, c.Skew)
	}

	if _, ok := hashes[c.Algorithm]; !ok {
		return fmt.Errorf("%w: algorithm must be SHA1, SHA256, or SHA512", ErrInvalidConfig)
	}

	// Refuse what would panic crypto/hmac in this process, now rather than at
	// the first login. Runs after defaults, so it judges the digest that will
	// actually be used.
	if err := checkFIPS(c.Algorithm, c.Seed.Size()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	return nil
}

// Authenticator validates OTP codes.
// It is safe for concurrent use, including Close against in-flight calls:
// Close waits for every borrow of the seed to end before wiping it.
type Authenticator struct {
	cfg Config
	// seed is the shared key, owned by the authenticator. Every derivation
	// borrows it through WithBytes for exactly as long as one HMAC takes; no
	// plaintext copy is held anywhere in the type.
	seed *enclave.MemoryEnclave
}

// NewAuthenticator creates a new OTP authenticator.
// The configuration is validated and an error is returned if invalid.
//
// It takes ownership of cfg.Seed on every return path: the seed is destroyed
// here if the configuration is refused, and by Close otherwise. The caller
// must not use or destroy it after this call.
func NewAuthenticator(cfg Config) (auth *Authenticator, err error) {
	seed := cfg.Seed
	defer func() {
		if err != nil {
			err = credential.DestroyAll(err, seed)
		}
	}()

	// Judged before defaults are applied, while an omitted algorithm can still
	// be told apart from an explicit one.
	if err := checkFIPSAlgorithmNamed(cfg.Algorithm); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// The authenticator's copy of the configuration does not carry the seed:
	// there is one reference to it, and it is the one Close destroys.
	cfg.Seed = nil
	return &Authenticator{cfg: cfg, seed: seed}, nil
}

// Close destroys the seed the authenticator owns: the locked pages are wiped
// and released, and every later Generate, Authenticate, ValidateCounter and
// ProvisioningURI fails with an error matching enclave.ErrEnclaveDestroyed.
// It waits for in-flight calls to finish with the seed, and is idempotent.
//
// The error is go-enclave's teardown report: nil for an ordinary release, or
// enclave.ErrReleasedWithoutWipe when a sandbox denied the mprotect the wipe
// needs and the pages had to be unmapped without it.
func (a *Authenticator) Close() error {
	if a == nil {
		return ErrNilAuthenticator
	}
	return a.seed.Destroy()
}

// Authenticate validates an OTP code.
// For TOTP, it validates against the current time with skew tolerance.
// For HOTP, it validates against the configured counter value.
//
// The code is a credential for its validity window, so it arrives in an
// enclave like every other credential. It is BORROWED: compared in constant
// time from inside WithBytes, and never destroyed here.
func (a *Authenticator) Authenticate(ctx context.Context, code *enclave.MemoryEnclave) error {
	if a == nil {
		return ErrNilAuthenticator
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := credential.Require(code, ErrMissingCode); err != nil {
		return errors.Join(ErrInvalidCode, err)
	}

	if a.cfg.Type == TypeTOTP {
		return a.authenticateTOTP(code, time.Now().UTC())
	}
	return a.authenticateHOTP(code, a.cfg.Counter)
}

// ValidateCounter validates an HOTP code and returns the new counter value.
// This method is only valid for HOTP authenticators.
// The returned counter should be stored and used for the next validation.
// The code is BORROWED, as in Authenticate.
func (a *Authenticator) ValidateCounter(ctx context.Context, code *enclave.MemoryEnclave, counter uint64) (uint64, error) {
	if a == nil {
		return 0, ErrNilAuthenticator
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	if a.cfg.Type != TypeHOTP {
		return 0, fmt.Errorf("%w: ValidateCounter is only valid for HOTP", ErrInvalidConfig)
	}

	if err := credential.Require(code, ErrMissingCode); err != nil {
		return 0, errors.Join(ErrInvalidCode, err)
	}

	if err := a.authenticateHOTP(code, counter); err != nil {
		return 0, err
	}
	return counter + 1, nil
}

// Generate generates an OTP code.
// For TOTP, it generates the code for the current time.
// For HOTP, a counter value must be provided.
func (a *Authenticator) Generate(counter ...uint64) (string, error) {
	if a == nil {
		return "", ErrNilAuthenticator
	}

	if a.cfg.Type == TypeTOTP {
		return a.derive(totpCounter(time.Now().UTC(), a.cfg.Period))
	}

	if len(counter) == 0 {
		return "", ErrCounterRequired
	}
	return a.derive(counter[0])
}

// derive computes the code at counter from the borrowed seed.
func (a *Authenticator) derive(counter uint64) (string, error) {
	var code string
	err := a.seed.WithBytes(func(key []byte) error {
		derived, err := deriveCode(key, counter, a.cfg.Digits, a.cfg.Algorithm)
		code = derived
		return err
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// authenticateTOTP validates a TOTP code at now against the borrowed seed.
// Both the submitted code and the seed are read only inside their borrows.
func (a *Authenticator) authenticateTOTP(code *enclave.MemoryEnclave, now time.Time) error {
	var valid bool
	err := code.WithBytes(func(submitted []byte) error {
		return a.seed.WithBytes(func(key []byte) error {
			var err error
			valid, err = validateTOTP(key, submitted, now, a.cfg.Period, a.cfg.Skew, a.cfg.Digits, a.cfg.Algorithm)
			return err
		})
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCode, err)
	}
	if !valid {
		return ErrInvalidCode
	}
	return nil
}

// authenticateHOTP validates an HOTP code at counter against the borrowed
// seed, comparing in constant time.
func (a *Authenticator) authenticateHOTP(code *enclave.MemoryEnclave, counter uint64) error {
	derived, err := a.derive(counter)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCode, err)
	}
	var valid bool
	if err := code.WithBytes(func(submitted []byte) error {
		valid = codesMatch(derived, submitted)
		return nil
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCode, err)
	}
	if !valid {
		return ErrInvalidCode
	}
	return nil
}

// ProvisioningURI returns the otpauth:// URI for QR code generation, in the
// Google Authenticator Key URI Format:
//
//	otpauth://TYPE/ISSUER:ACCOUNT?secret=BASE32&issuer=ISSUER&algorithm=…&digits=…&period=…|counter=…
//
// The URI necessarily carries the seed — that is what enrollment is — so it
// is built from EncodeSecret and inherits its residue: the returned string is
// an unwipeable copy of the key. Render it and drop it; do not log or store it.
//
// It reports an error rather than a seed-less URI when the seed cannot be
// read, because a URI without a usable seed still looks like an enrollment.
func (a *Authenticator) ProvisioningURI() (string, error) {
	if a == nil {
		return "", ErrNilAuthenticator
	}

	encoded, err := EncodeSecret(a.seed)
	if err != nil {
		return "", err
	}

	v := url.Values{}
	// Residue: the URI carries the seed as text, because enrollment is
	// handing the seed to the user's authenticator app.
	v.Set("secret", encoded)
	v.Set("issuer", a.cfg.Issuer)
	v.Set("algorithm", string(a.cfg.Algorithm))
	v.Set("digits", strconv.FormatUint(uint64(a.cfg.Digits), 10))
	provisioningCounter[a.cfg.Type](a.cfg, v)

	label := url.PathEscape(a.cfg.Issuer + ":" + a.cfg.AccountName)
	return "otpauth://" + string(a.cfg.Type) + "/" + label + "?" + v.Encode(), nil
}

// provisioningCounter sets the type-specific Key URI parameter: the time step
// for TOTP, the initial counter for HOTP.
var provisioningCounter = map[Type]func(Config, url.Values){
	TypeTOTP: func(c Config, v url.Values) { v.Set("period", strconv.FormatUint(uint64(c.Period), 10)) },
	TypeHOTP: func(c Config, v url.Values) { v.Set("counter", strconv.FormatUint(c.Counter, 10)) },
}
