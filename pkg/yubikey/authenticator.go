package yubikey

import (
	"context"
	"errors"
)

// OTPValidator describes a component capable of validating a YubiKey OTP.
type OTPValidator interface {
	Validate(ctx context.Context, clientID, secret, otp string) error
}

var (
	errSystemValidatorUnavailable = errors.New("yubikey: system validator unavailable; configure a validator implementation")
	// ErrInvalidOTP indicates the OTP was syntactically valid but rejected by the validation service.
	ErrInvalidOTP = errors.New("yubikey: invalid OTP")
)

// Config contains the inputs required to talk to a YubiKey validation service.
type Config struct {
	ClientID string
	APIKey   string
}

func (c Config) validate() error {
	if c.ClientID == "" {
		return errors.New("yubikey: client id must not be empty")
	}
	if c.APIKey == "" {
		return errors.New("yubikey: api key must not be empty")
	}
	return nil
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
}

// NewAuthenticator constructs a YubiKey authenticator. If validator is nil the
// package-level system validator is used which must be initialised by platform code.
func NewAuthenticator(cfg Config, validator OTPValidator) (*Authenticator, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if validator == nil {
		if systemValidator == nil {
			return nil, errSystemValidatorUnavailable
		}
		validator = systemValidator
	}
	return &Authenticator{cfg: cfg, validator: validator}, nil
}

// Authenticate validates the provided OTP.
func (a *Authenticator) Authenticate(ctx context.Context, otp string) error {
	if a == nil {
		return errors.New("yubikey: authenticator is nil")
	}
	if otp == "" {
		return errors.New("yubikey: otp must not be empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.validator.Validate(ctx, a.cfg.ClientID, a.cfg.APIKey, otp)
}
