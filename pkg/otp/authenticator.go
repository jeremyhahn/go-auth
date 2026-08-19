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

	"github.com/jeremyhahn/go-auth/pkg/secret"
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
	// Secret is the base32-encoded shared secret key.
	//
	// Deprecated: a Go string cannot be wiped, so a secret set here stays
	// resident for the lifetime of the process that read it, and
	// github.com/pquerna/otp — which this field is passed to — decodes it into
	// a fresh plaintext key on every Generate and Authenticate. Use SecretKey
	// with NewProtectedSecret or GenerateProtectedSecret instead, which keeps
	// the key in protected memory and decrypts it only for the moment a code
	// is derived. Still honored, and still the default when SecretKey is
	// unset, but it will be removed in the coordinated breaking release.
	Secret string
	// SecretKey is the shared secret held in protected memory. It is the
	// replacement for Secret: build one with NewProtectedSecret from an
	// existing base32 secret, or GenerateProtectedSecret for a new key.
	//
	// Exactly one of Secret and SecretKey may be set. When SecretKey is used
	// the authenticator derives codes from the sealed key directly (RFC 4226
	// §5.3, RFC 6238 §4.2) rather than handing the secret to a dependency that
	// takes it as a string.
	//
	// The authenticator borrows the secret and does not take ownership of it:
	// destroy it when the last component using it is done.
	SecretKey *secret.Secret
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
	// It may not exceed 10: a wider window keeps every code valid for longer,
	// and costs an HMAC per step. RFC 6238 §5.2 asks for the smallest window a
	// deployment can tolerate.
	// Default: 1
	Skew uint
}

// validate checks that the configuration is valid.
func (c Config) validate() error {
	// Validate type
	if c.Type != TypeTOTP && c.Type != TypeHOTP {
		return fmt.Errorf("%w: type must be 'totp' or 'hotp'", ErrInvalidConfig)
	}

	// Validate the secret and measure its strength. The protected path has
	// already decoded and sealed its key, so its size is known without touching
	// the key at all; the string path still has to prove the secret is
	// well-formed base32, and decodes into protected memory to do it.
	var secretBits int
	if c.SecretKey != nil {
		if strings.TrimSpace(c.Secret) != "" {
			return fmt.Errorf("%w: set either Secret or SecretKey, not both", ErrInvalidConfig)
		}
		if c.SecretKey.Size() == 0 {
			return fmt.Errorf("%w: secret key must not be empty", ErrInvalidConfig)
		}
		secretBits = c.SecretKey.Size() * 8
	} else {
		if strings.TrimSpace(c.Secret) == "" {
			return fmt.Errorf("%w: secret must not be empty", ErrInvalidConfig)
		}

		// Prove the secret is well-formed base32 and measure its strength.
		// decodedSecretBits does both without putting the decoded key on the
		// heap; it also accepts the unpadded form, matching what the protected
		// path and provisioning tools use.
		bits, err := decodedSecretBits(c.Secret)
		if err != nil {
			return err
		}
		secretBits = bits
	}

	// Reject a key this build cannot use to key HMAC.
	if err := checkSecretSupported(secretBits); err != nil {
		return err
	}

	// Validate digits (if specified)
	if c.Digits != 0 && c.Digits != 6 && c.Digits != 7 && c.Digits != 8 {
		return fmt.Errorf("%w: digits must be 6, 7, or 8", ErrInvalidConfig)
	}

	// Validate skew. An unbounded window is both a security choice made by
	// accident — every extra step keeps a code valid for another period — and
	// an amount of HMAC work proportional to it; see maxSkew.
	if c.Skew > maxSkew {
		return fmt.Errorf("%w: skew must be at most %d time steps (got %d); "+
			"clock drift beyond that is a clock problem, not a validation window",
			ErrInvalidConfig, maxSkew, c.Skew)
	}

	// Validate algorithm (if specified)
	if c.Algorithm != "" && c.Algorithm != AlgorithmSHA1 &&
		c.Algorithm != AlgorithmSHA256 && c.Algorithm != AlgorithmSHA512 {
		return fmt.Errorf("%w: algorithm must be SHA1, SHA256, or SHA512", ErrInvalidConfig)
	}

	// Reject a digest this build cannot execute. Runs before defaults are
	// applied, so it only ever sees an explicit choice.
	if err := checkAlgorithmSupported(c.Algorithm); err != nil {
		return err
	}

	return nil
}

// decodedSecretBits reports the strength, in bits, of a base32-encoded shared
// secret, and reports an error if the encoding is malformed.
//
// The decoded bytes are the key itself, so they never reach ordinary memory:
// NewProtectedSecret decodes straight into a memguard-backed enclave, the
// length is read from there, and the enclave is destroyed on every exit path.
// Only a count leaves this function. base32.DecodeString, which this replaces,
// would instead hand back a plaintext key for the collector to keep.
//
// This narrows the deprecated string path; it does not close it.
// Config.Secret is a Go string, resident and unzeroable for the
// Authenticator's lifetime, and github.com/pquerna/otp decodes it again
// internally on every operation. Config.SecretKey is the path that has neither
// property, and is what a caller handling key material should use.
func decodedSecretBits(base32Secret string) (int, error) {
	// Go's unpadded decoder discards a trailing group too short to encode a
	// whole byte rather than rejecting it, so "<secret>A" decodes to exactly
	// the key "<secret>" does. A secret carrying a stray character would then
	// be accepted here and produce codes the enrolled authenticator never
	// agrees with — a failure at every login rather than at startup. The
	// padded decoding this replaces rejected it; keep rejecting it.
	if n := len(trimBase32(base32Secret)) % 8; n == 1 || n == 3 || n == 6 {
		return 0, fmt.Errorf("%w: secret must be valid base32: it ends in %d "+
			"characters that do not encode a whole byte", ErrInvalidConfig, n)
	}

	key, err := NewProtectedSecret(base32Secret)
	if err != nil {
		return 0, err
	}
	defer key.Destroy()

	return key.Size() * 8, nil
}

// Authenticator validates OTP codes.
// It is safe for concurrent use.
type Authenticator struct {
	cfg       Config
	otpAlgo   otp.Algorithm
	otpDigits otp.Digits
	// key is the sealed shared secret when the authenticator was built from
	// Config.SecretKey, and nil when it was built from the deprecated
	// Config.Secret string. It is what every method branches on: with a key
	// the code is derived here from the opened enclave, without one the
	// secret string is handed to github.com/pquerna/otp as before.
	key *secret.Secret
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
		cfg.Algorithm = defaultAlgorithm
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
		key:       cfg.SecretKey,
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
		if a.key != nil {
			return a.authenticateProtectedTOTP(code, time.Now().UTC())
		}
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

	// HOTP validation using configured counter.
	if a.key != nil {
		return a.authenticateProtectedHOTP(code, a.cfg.Counter)
	}

	// hotp.Validate hardcodes 6 digits and SHA-1 regardless of how the
	// authenticator was built, so a SHA-256/SHA-512 or 7/8-digit HOTP secret
	// would never validate the codes Generate produced for it. Pass the
	// configured options explicitly.
	valid, err := hotp.ValidateCustom(code, a.cfg.Counter, a.cfg.Secret,
		hotp.ValidateOpts{
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

	if a.key != nil {
		if err := a.authenticateProtectedHOTP(code, counter); err != nil {
			return 0, err
		}
		return counter + 1, nil
	}

	// Same as Authenticate: hotp.Validate would pin this to 6-digit SHA-1.
	valid, err := hotp.ValidateCustom(code, counter, a.cfg.Secret,
		hotp.ValidateOpts{
			Digits:    a.otpDigits,
			Algorithm: a.otpAlgo,
		})
	if err != nil {
		return 0, fmt.Errorf("%w: validation failed: %v", ErrInvalidCode, err)
	}
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
		if a.key != nil {
			return a.generateProtected(totpCounter(time.Now().UTC(), a.cfg.Period))
		}
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

	if a.key != nil {
		return a.generateProtected(counter[0])
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

// ProvisioningURI returns the otpauth:// URI for QR code generation.
// This URI can be encoded as a QR code and scanned by authenticator apps.
//
// It reports an error when the secret cannot be read: with Config.SecretKey
// the key has to be opened to be encoded, and that fails if the caller has
// destroyed it or memguard's session has been purged. A URI carrying no secret
// would still look like an enrollment, which is the one thing it must not do.
func (a *Authenticator) ProvisioningURI() (string, error) {
	if a == nil {
		return "", ErrNilAuthenticator
	}

	provisioningSecret, err := a.provisioningSecret()
	if err != nil {
		return "", err
	}

	// Build otpauth:// URI manually to ensure correct secret
	v := url.Values{}
	v.Set("secret", provisioningSecret)
	v.Set("issuer", a.cfg.Issuer)
	v.Set("algorithm", string(a.cfg.Algorithm))
	v.Set("digits", fmt.Sprintf("%d", a.cfg.Digits))

	if a.cfg.Type == TypeTOTP {
		v.Set("period", fmt.Sprintf("%d", a.cfg.Period))
		label := url.PathEscape(fmt.Sprintf("%s:%s", a.cfg.Issuer, a.cfg.AccountName))
		return fmt.Sprintf("otpauth://totp/%s?%s", label, v.Encode()), nil
	}

	v.Set("counter", fmt.Sprintf("%d", a.cfg.Counter))
	label := url.PathEscape(fmt.Sprintf("%s:%s", a.cfg.Issuer, a.cfg.AccountName))
	return fmt.Sprintf("otpauth://hotp/%s?%s", label, v.Encode()), nil
}

// GetProvisioningURI returns the otpauth:// URI for QR code generation.
// This URI can be encoded as a QR code and scanned by authenticator apps.
//
// It returns an empty string when the URI cannot be built — including when a
// protected secret cannot be opened — because it has no way to say why.
//
// Deprecated: use ProvisioningURI, which reports the reason. This method is
// still supported and will be removed in the coordinated breaking release.
func (a *Authenticator) GetProvisioningURI() string {
	uri, err := a.ProvisioningURI()
	if err != nil {
		return ""
	}
	return uri
}

// GenerateSecret generates a cryptographically random secret key.
// The secret is returned as a base32-encoded string suitable for use
// in the Config.Secret field.
//
// Deprecated: the generated key exists as a Go string, which cannot be wiped.
// Use GenerateProtectedSecret, which writes the key straight into protected
// memory, and EncodeSecret when the base32 form is genuinely needed for
// enrollment or storage. This function is still supported and will be removed
// in the coordinated breaking release.
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
