package pkcs11

import (
	"context"
	"errors"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
)

// Session represents an active PKCS#11 session capable of authenticating a PIN.
//
// Login BORROWS the PIN for the length of the call: an implementation reads it
// through WithBytes (or, where the binding only takes a string, through a
// copy it wipes), must not retain it, and must not destroy it.
type Session interface {
	Login(ctx context.Context, pin *enclave.MemoryEnclave) error
	Logout(ctx context.Context) error
}

// SessionProvider abstracts creation of PKCS#11 sessions from configuration.
type SessionProvider interface {
	Open(ctx context.Context, cfg Config) (Session, error)
}

var (
	errSystemProviderUnavailable = errors.New("pkcs11: system provider unavailable; build with PKCS#11 support to use default")
	// ErrInvalidPIN indicates the supplied PIN or passphrase was rejected by the token.
	ErrInvalidPIN = errors.New("pkcs11: invalid PIN")
	// ErrNilAuthenticator indicates a method was called on a nil authenticator.
	ErrNilAuthenticator = errors.New("pkcs11: authenticator is nil")
	// ErrMissingPIN indicates Authenticate was called without a live PIN
	// enclave. A destroyed one also matches enclave.ErrEnclaveDestroyed.
	ErrMissingPIN = errors.New("pkcs11: pin must not be empty")
	// ErrMissingModulePath indicates the configuration names no PKCS#11 module.
	ErrMissingModulePath = errors.New("pkcs11: module path must not be empty")
	// ErrMissingTokenSelector indicates the configuration names neither a
	// token label nor a slot.
	ErrMissingTokenSelector = errors.New("pkcs11: either token label or slot must be specified")
)

// Config supplies the parameters required to locate and access a PKCS#11 token.
type Config struct {
	ModulePath string
	TokenLabel string
	Slot       string
}

func (c Config) validate() error {
	if c.ModulePath == "" {
		return ErrMissingModulePath
	}
	if c.TokenLabel == "" && c.Slot == "" {
		return ErrMissingTokenSelector
	}
	return nil
}

var systemSessionProvider SessionProvider

// SetSystemSessionProvider installs the default session provider used when callers
// pass nil to NewAuthenticator. Primarily useful for tests or wiring concrete
// implementations from hosting applications.
func SetSystemSessionProvider(p SessionProvider) {
	systemSessionProvider = p
}

// Authenticator validates PIN-based credentials against a PKCS#11 token.
type Authenticator struct {
	cfg      Config
	provider SessionProvider
}

// NewAuthenticator constructs a PKCS#11 authenticator using the supplied configuration.
// If provider is nil the package-level system provider is used, which requires linking
// against a real PKCS#11 implementation.
func NewAuthenticator(cfg Config, provider SessionProvider) (*Authenticator, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if provider == nil {
		if systemSessionProvider == nil {
			return nil, errSystemProviderUnavailable
		}
		provider = systemSessionProvider
	}
	return &Authenticator{cfg: cfg, provider: provider}, nil
}

// Authenticate opens a PKCS#11 session and attempts to log in with the provided PIN.
//
// The PIN is BORROWED: it is lent to the session's Login and never destroyed
// here; the caller still owns it.
func (a *Authenticator) Authenticate(ctx context.Context, pin *enclave.MemoryEnclave) (err error) {
	if a == nil {
		return ErrNilAuthenticator
	}
	if err := credential.Require(pin, ErrMissingPIN); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	session, err := a.provider.Open(ctx, a.cfg)
	if err != nil {
		return err
	}

	defer func() {
		if cerr := session.Logout(ctx); cerr != nil {
			if err != nil {
				err = errors.Join(err, cerr)
			} else {
				err = cerr
			}
		}
	}()

	return session.Login(ctx, pin)
}
