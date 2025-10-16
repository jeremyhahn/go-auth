package otp

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

// Type represents the OTP algorithm type.
type Type string

const (
	// TypeTOTP represents Time-based OTP (RFC 6238).
	TypeTOTP Type = "totp"
	// TypeHOTP represents Counter-based OTP (RFC 4226).
	TypeHOTP Type = "hotp"
)

// Algorithm represents the hash algorithm used for OTP generation.
type Algorithm string

const (
	// AlgorithmSHA1 uses SHA1 hash algorithm.
	AlgorithmSHA1 Algorithm = "SHA1"
	// AlgorithmSHA256 uses SHA256 hash algorithm.
	AlgorithmSHA256 Algorithm = "SHA256"
	// AlgorithmSHA512 uses SHA512 hash algorithm.
	AlgorithmSHA512 Algorithm = "SHA512"
)

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
)

// Config holds OTP authenticator configuration.
type Config struct {
	// Type specifies the OTP type (TOTP or HOTP).
	Type Type
	// Secret is the base32-encoded shared secret key (required).
	Secret string
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
	// Default: SHA1
	Algorithm Algorithm
	// Skew specifies the number of time periods to check before and after
	// the current time for TOTP validation (tolerance for clock skew).
	// Default: 1
	Skew uint
}

// validate checks that the configuration is valid.
func (c Config) validate() error {
	// Validate type
	if c.Type != TypeTOTP && c.Type != TypeHOTP {
		return fmt.Errorf("%w: type must be 'totp' or 'hotp'", ErrInvalidConfig)
	}

	// Validate secret
	if strings.TrimSpace(c.Secret) == "" {
		return fmt.Errorf("%w: secret must not be empty", ErrInvalidConfig)
	}

	// Validate secret is valid base32
	if _, err := base32.StdEncoding.DecodeString(strings.ToUpper(c.Secret)); err != nil {
		return fmt.Errorf("%w: secret must be valid base32: %v", ErrInvalidConfig, err)
	}

	// Validate digits (if specified)
	if c.Digits != 0 && c.Digits != 6 && c.Digits != 7 && c.Digits != 8 {
		return fmt.Errorf("%w: digits must be 6, 7, or 8", ErrInvalidConfig)
	}

	// Validate algorithm (if specified)
	if c.Algorithm != "" && c.Algorithm != AlgorithmSHA1 &&
		c.Algorithm != AlgorithmSHA256 && c.Algorithm != AlgorithmSHA512 {
		return fmt.Errorf("%w: algorithm must be SHA1, SHA256, or SHA512", ErrInvalidConfig)
	}

	return nil
}

// Authenticator validates OTP codes.
// It is safe for concurrent use.
type Authenticator struct {
	cfg       Config
	otpAlgo   otp.Algorithm
	otpDigits otp.Digits
}

// NewAuthenticator creates a new OTP authenticator.
// The configuration is validated and an error is returned if invalid.
func NewAuthenticator(cfg Config) (*Authenticator, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// Apply defaults
	if cfg.Digits == 0 {
		cfg.Digits = 6
	}
	if cfg.Period == 0 {
		cfg.Period = 30
	}
	if cfg.Algorithm == "" {
		cfg.Algorithm = AlgorithmSHA1
	}
	if cfg.Skew == 0 {
		cfg.Skew = 1
	}

	// Convert algorithm to otp.Algorithm
	var otpAlgo otp.Algorithm
	switch cfg.Algorithm {
	case AlgorithmSHA1:
		otpAlgo = otp.AlgorithmSHA1
	case AlgorithmSHA256:
		otpAlgo = otp.AlgorithmSHA256
	case AlgorithmSHA512:
		otpAlgo = otp.AlgorithmSHA512
	}

	return &Authenticator{
		cfg:       cfg,
		otpAlgo:   otpAlgo,
		otpDigits: otp.Digits(cfg.Digits),
	}, nil
}

// Authenticate validates an OTP code.
// For TOTP, it validates against the current time with skew tolerance.
// For HOTP, it validates against the configured counter value.
func (a *Authenticator) Authenticate(ctx context.Context, code string) error {
	if a == nil {
		return ErrNilAuthenticator
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("%w: code must not be empty", ErrInvalidCode)
	}

	if a.cfg.Type == TypeTOTP {
		valid, err := totp.ValidateCustom(code, a.cfg.Secret, time.Now().UTC(),
			totp.ValidateOpts{
				Period:    a.cfg.Period,
				Skew:      a.cfg.Skew,
				Digits:    a.otpDigits,
				Algorithm: a.otpAlgo,
			})
		if err != nil {
			return fmt.Errorf("%w: validation failed: %v", ErrInvalidCode, err)
		}
		if !valid {
			return ErrInvalidCode
		}
		return nil
	}

	// HOTP validation using configured counter
	valid := hotp.Validate(code, a.cfg.Counter, a.cfg.Secret)
	if !valid {
		return ErrInvalidCode
	}

	return nil
}

// ValidateCounter validates an HOTP code and returns the new counter value.
// This method is only valid for HOTP authenticators.
// The returned counter should be stored and used for the next validation.
func (a *Authenticator) ValidateCounter(ctx context.Context, code string, counter uint64) (uint64, error) {
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

	if strings.TrimSpace(code) == "" {
		return 0, fmt.Errorf("%w: code must not be empty", ErrInvalidCode)
	}

	valid := hotp.Validate(code, counter, a.cfg.Secret)
	if !valid {
		return 0, ErrInvalidCode
	}

	// Return incremented counter
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
		code, err := totp.GenerateCodeCustom(a.cfg.Secret, time.Now().UTC(),
			totp.ValidateOpts{
				Period:    a.cfg.Period,
				Skew:      0,
				Digits:    a.otpDigits,
				Algorithm: a.otpAlgo,
			})
		if err != nil {
			return "", fmt.Errorf("otp: failed to generate TOTP code: %w", err)
		}
		return code, nil
	}

	// HOTP requires counter
	if len(counter) == 0 {
		return "", fmt.Errorf("otp: counter required for HOTP generation")
	}

	code, err := hotp.GenerateCodeCustom(a.cfg.Secret, counter[0],
		hotp.ValidateOpts{
			Digits:    a.otpDigits,
			Algorithm: a.otpAlgo,
		})
	if err != nil {
		return "", fmt.Errorf("otp: failed to generate HOTP code: %w", err)
	}

	return code, nil
}

// GetProvisioningURI returns the otpauth:// URI for QR code generation.
// This URI can be encoded as a QR code and scanned by authenticator apps.
func (a *Authenticator) GetProvisioningURI() string {
	if a == nil {
		return ""
	}

	// Build otpauth:// URI manually to ensure correct secret
	v := url.Values{}
	v.Set("secret", a.cfg.Secret)
	v.Set("issuer", a.cfg.Issuer)
	v.Set("algorithm", string(a.cfg.Algorithm))
	v.Set("digits", fmt.Sprintf("%d", a.cfg.Digits))

	if a.cfg.Type == TypeTOTP {
		v.Set("period", fmt.Sprintf("%d", a.cfg.Period))
		label := url.PathEscape(fmt.Sprintf("%s:%s", a.cfg.Issuer, a.cfg.AccountName))
		return fmt.Sprintf("otpauth://totp/%s?%s", label, v.Encode())
	}

	v.Set("counter", fmt.Sprintf("%d", a.cfg.Counter))
	label := url.PathEscape(fmt.Sprintf("%s:%s", a.cfg.Issuer, a.cfg.AccountName))
	return fmt.Sprintf("otpauth://hotp/%s?%s", label, v.Encode())
}

// GenerateSecret generates a cryptographically random secret key.
// The secret is returned as a base32-encoded string suitable for use
// in the Config.Secret field.
func GenerateSecret() (string, error) {
	// Generate 20 bytes (160 bits) of random data
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("otp: failed to generate random secret: %w", err)
	}

	// Encode as base32 without padding
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	return encoded, nil
}
