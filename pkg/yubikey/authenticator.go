package yubikey

import (
	"context"
	"errors"
	"sync"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
)

// OTPValidator describes a component capable of validating a YubiKey OTP.
//
// Both credentials are BORROWED for the length of the call: apiKey is the
// authenticator's Yubico API key and otp is the caller's one-time password.
// An implementation reads them through WithBytes, must not retain the bytes,
// and must not destroy either enclave.
type OTPValidator interface {
	Validate(ctx context.Context, clientID string, apiKey, otp *enclave.MemoryEnclave) error
}

var (
	errSystemValidatorUnavailable = errors.New("yubikey: system validator unavailable; configure a validator implementation")
	// ErrInvalidOTP indicates the OTP was syntactically valid but rejected by the validation service.
	ErrInvalidOTP = errors.New("yubikey: invalid OTP")
	// ErrNilAuthenticator indicates a method was called on a nil authenticator.
	ErrNilAuthenticator = errors.New("yubikey: authenticator is nil")
	// ErrMissingClientID indicates the configuration has no Yubico client id.
	ErrMissingClientID = errors.New("yubikey: client id must not be empty")
	// ErrMissingAPIKey indicates the configuration has no live API key
	// enclave. A destroyed one also matches enclave.ErrEnclaveDestroyed.
	ErrMissingAPIKey = errors.New("yubikey: api key must not be empty")
	// ErrMissingOTP indicates Authenticate was called without a live OTP
	// enclave. A destroyed one also matches enclave.ErrEnclaveDestroyed.
	ErrMissingOTP = errors.New("yubikey: otp must not be empty")
	// ErrClosed indicates the authenticator has been closed and its API key
	// destroyed.
	ErrClosed = errors.New("yubikey: authenticator is closed")
)

// Config contains the inputs required to talk to a YubiKey validation service.
type Config struct {
	ClientID string
	// APIKey is the base64 API key issued by Yubico, in locked memory. Build
	// it with enclave.NewMemoryEnclave (which wipes the caller's slice) or,
	// from a configuration string, enclave.NewMemoryEnclaveFromString.
	//
	// NewAuthenticator TAKES OWNERSHIP of it on every return path, and Close
	// destroys it. Do not use or destroy it afterwards.
	APIKey *enclave.MemoryEnclave
}

func (c Config) validate() error {
	if c.ClientID == "" {
		return ErrMissingClientID
	}
	return credential.Require(c.APIKey, ErrMissingAPIKey)
}

var systemValidator OTPValidator

// SetSystemValidator installs the package-level validator used when callers pass
// nil to NewAuthenticator. Useful for tests or dependency injection.
func SetSystemValidator(v OTPValidator) {
	systemValidator = v
}

// Authenticator validates YubiKey generated OTPs using a configured validator.
type Authenticator struct {
	cfg       Config
	validator OTPValidator
	// lifecycle orders Close against in-flight calls: every call holds the
	// read lock for its whole length and Close takes the write lock, so the
	// credential is destroyed only once no call can still need it.
	lifecycle sync.RWMutex
	closed    bool // guarded by lifecycle
}

// NewAuthenticator constructs a YubiKey authenticator. If validator is nil the
// package-level system validator is used — the YubiCloud HTTPValidator unless
// SetSystemValidator replaced it.
//
// It owns cfg.APIKey on every return path: when it returns an error the key
// has already been destroyed, and otherwise Close destroys it.
//
// Under FIPS activation it returns ErrFIPSUnsupported, ahead of the
// configuration checks, when the validator it would use is the YubiCloud one.
// Any other validator is accepted as usual.
func NewAuthenticator(cfg Config, validator OTPValidator) (*Authenticator, error) {
	if validator == nil {
		validator = systemValidator
	}
	if err := checkConstruction(cfg, validator); err != nil {
		cfg.APIKey.Destroy()
		return nil, err
	}
	return &Authenticator{cfg: cfg, validator: validator}, nil
}

func checkConstruction(cfg Config, validator OTPValidator) error {
	if refusedUnderFIPS(validator) {
		return ErrFIPSUnsupported
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	if validator == nil {
		return errSystemValidatorUnavailable
	}
	return nil
}

// Close destroys the API key the authenticator owns. It waits for every
// in-flight Authenticate to finish — including a YubiCloud exchange whose
// response signature still has to be verified with the key — and it is
// idempotent.
// Authenticate fails with ErrClosed afterwards.
func (a *Authenticator) Close() error {
	if a == nil {
		return nil
	}
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	a.closed = true
	return a.cfg.APIKey.DestroyErr()
}

// Authenticate validates the provided OTP.
//
// A YubiKey OTP is a credential for as long as the validation service would
// accept it, so it travels in an enclave like every other credential. It is
// BORROWED: the caller still owns it and destroys it.
func (a *Authenticator) Authenticate(ctx context.Context, otp *enclave.MemoryEnclave) error {
	if a == nil {
		return ErrNilAuthenticator
	}
	a.lifecycle.RLock()
	defer a.lifecycle.RUnlock()
	if a.closed {
		return ErrClosed
	}
	if err := credential.Require(otp, ErrMissingOTP); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.validator.Validate(ctx, a.cfg.ClientID, a.cfg.APIKey, otp)
}
