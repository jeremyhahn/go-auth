package pkcs11

import (
	"context"
	"errors"
)

// Session represents an active PKCS#11 session capable of authenticating a PIN.
type Session interface {
	Login(ctx context.Context, pin string) error
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
)

// Config supplies the parameters required to locate and access a PKCS#11 token.
type Config struct {
	ModulePath string
	TokenLabel string
	Slot       string
}

func (c Config) validate() error {
	if c.ModulePath == "" {
		return errors.New("pkcs11: module path must not be empty")
	}
	if c.TokenLabel == "" && c.Slot == "" {
		return errors.New("pkcs11: either token label or slot must be specified")
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
func (a *Authenticator) Authenticate(ctx context.Context, pin string) (err error) {
	if a == nil {
		return errors.New("pkcs11: authenticator is nil")
	}
	if pin == "" {
		return errors.New("pkcs11: pin must not be empty")
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
