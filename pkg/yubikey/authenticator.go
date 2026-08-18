package yubikey

import (
	"context"
	"errors"

	secretpkg "github.com/jeremyhahn/go-auth/pkg/secret"
)

// OTPValidator describes a component capable of validating a YubiKey OTP.
//
// Deprecated: implement ProtectedOTPValidator instead, which receives the API
// key in protected memory rather than as a Go string. This interface is still
// supported — an implementation of it is called with a copy of the key opened
// from the enclave — and will be removed in the coordinated breaking release.
type OTPValidator interface {
	Validate(ctx context.Context, clientID, secret, otp string) error
}

// ProtectedOTPValidator is an OTPValidator that takes the API key in protected
// memory. A validator implementing it is never handed the key as a string:
// HTTPValidator, the implementation in this package, opens the enclave only to
// sign a request and to verify the response signature.
type ProtectedOTPValidator interface {
	ValidateProtected(ctx context.Context, clientID string, apiKey *secretpkg.Secret, otp string) error
}

var (
	errSystemValidatorUnavailable = errors.New("yubikey: system validator unavailable; configure a validator implementation")
	// ErrInvalidOTP indicates the OTP was syntactically valid but rejected by the validation service.
	ErrInvalidOTP = errors.New("yubikey: invalid OTP")
)

// Config contains the inputs required to talk to a YubiKey validation service.
type Config struct {
	ClientID string
	// APIKey is the base64 API key issued by Yubico.
	//
	// Deprecated: a Go string cannot be wiped, so a key set here stays
	// resident for the lifetime of the process that read it. Use
	// ProtectedAPIKey instead. Still honored, and still the default when
	// ProtectedAPIKey is unset, but it will be removed in the coordinated
	// breaking release.
	APIKey string
	// ProtectedAPIKey is the base64 API key issued by Yubico, held in
	// protected memory. It is the replacement for APIKey: build one with
	// secret.NewString, or with secret.New from a key read into a buffer the
	// caller controls.
	//
	// Exactly one of APIKey and ProtectedAPIKey may be set. The authenticator
	// borrows the secret and does not take ownership of it: destroy it when
	// the last component using it is done.
	ProtectedAPIKey *secretpkg.Secret
}

func (c Config) validate() error {
	if c.ClientID == "" {
		return errors.New("yubikey: client id must not be empty")
	}
	if c.ProtectedAPIKey != nil {
		if c.APIKey != "" {
			return errors.New("yubikey: set either APIKey or ProtectedAPIKey, not both")
		}
		if c.ProtectedAPIKey.Size() == 0 {
			return errors.New("yubikey: api key must not be empty")
		}
		return nil
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
// package-level system validator is used which must be initialized by platform code.
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
	apiKey := a.cfg.ProtectedAPIKey
	if apiKey == nil {
		// The deprecated string path. Sealing it here does not undo the
		// exposure of Config.APIKey, but it does mean everything below this
		// line — including a custom validator that implements
		// ProtectedOTPValidator — sees the key the protected way.
		sealed, err := secretpkg.NewString(a.cfg.APIKey)
		if err != nil {
			return err
		}
		defer sealed.Destroy()
		apiKey = sealed
	}

	if protected, ok := a.validator.(ProtectedOTPValidator); ok {
		return protected.ValidateProtected(ctx, a.cfg.ClientID, apiKey, otp)
	}

	// A validator that only implements the deprecated interface has to be
	// given a string. The copy exists for the length of the call and is
	// unreachable afterwards, but it cannot be wiped — which is the reason
	// that interface is deprecated.
	return apiKey.OpenString(func(key string) error {
		return a.validator.Validate(ctx, a.cfg.ClientID, key, otp)
	})
}
