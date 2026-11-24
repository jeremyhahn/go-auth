package yubikey

import (
	"context"
	"errors"
	"sync"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
)

// OTPValidator validates a YubiKey OTP; apiKey and otp are borrowed and must not be retained or destroyed.
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
	// APIKey is the base64 Yubico API key in locked memory; NewAuthenticator takes ownership of it.
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

// NewAuthenticator constructs a YubiKey authenticator, using the system validator when validator is nil; it owns cfg.APIKey and refuses YubiCloud under FIPS activation.
func NewAuthenticator(cfg Config, validator OTPValidator) (*Authenticator, error) {
	if validator == nil {
		validator = systemValidator
	}
	if err := checkConstruction(cfg, validator); err != nil {
		return nil, credential.DestroyAll(err, cfg.APIKey)
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

// Close waits for in-flight Authenticate calls and destroys the API key; it is idempotent and later calls fail with ErrClosed.
func (a *Authenticator) Close() error {
	if a == nil {
		return nil
	}
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	a.closed = true
	return a.cfg.APIKey.Destroy()
}

// Authenticate validates a borrowed OTP enclave.
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
