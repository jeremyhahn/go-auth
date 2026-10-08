package api

import (
	"context"
	"errors"
	"fmt"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
	ldapauth "github.com/jeremyhahn/go-auth/pkg/ldap"
	"github.com/jeremyhahn/go-auth/pkg/oauth"
	"github.com/jeremyhahn/go-auth/pkg/otp"
	"github.com/jeremyhahn/go-auth/pkg/pam"
	"github.com/jeremyhahn/go-auth/pkg/pkcs11"
	"github.com/jeremyhahn/go-auth/pkg/radius"
	"github.com/jeremyhahn/go-auth/pkg/tacacs"
	"github.com/jeremyhahn/go-auth/pkg/tpm2"
	"github.com/jeremyhahn/go-auth/pkg/yubikey"
)

// Handler defines the contract for a backend authenticator.
// The implementation should return nil on success or an error on failure.
//
// password and otp are BORROWED for the length of the call and either may be
// nil. A Handler reads them only through the backend it delegates to, must
// not retain them, and must not destroy them: Service.Login owns them.
type Handler interface {
	Authenticate(ctx context.Context, username string, password, otp *enclave.MemoryEnclave) error
}

// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(ctx context.Context, username string, password, otp *enclave.MemoryEnclave) error

// Authenticate executes the underlying function.
func (f HandlerFunc) Authenticate(ctx context.Context, username string, password, otp *enclave.MemoryEnclave) error {
	return f(ctx, username, password, otp)
}

// BackendName identifies a registered authentication backend.
type BackendName string

const (
	BackendPAM     BackendName = "pam"
	BackendRADIUS  BackendName = "radius"
	BackendTACACS  BackendName = "tacacs"
	BackendLDAP    BackendName = "ldap"
	BackendPKCS11  BackendName = "pkcs11"
	BackendYubiKey BackendName = "yubikey"
	BackendOAuth   BackendName = "oauth"
	BackendTPM2    BackendName = "tpm2"
	BackendOTP     BackendName = "otp"
)

// Backend represents a named authentication backend.
type Backend struct {
	Name    BackendName
	Handler Handler
}

// Config contains the ordered list of backends the service should attempt.
type Config struct {
	Backends []Backend
}

// Service coordinates authentication attempts across configured backends.
type Service struct {
	backends []Backend
}

var (
	// ErrNoBackends indicates the service was initialized without any backends.
	ErrNoBackends = errors.New("api: no authentication backends configured")
	// ErrBackendNotFound indicates a requested backend name does not exist.
	ErrBackendNotFound = errors.New("api: requested backend not configured")
	// ErrMissingCredentials indicates the request does not contain mandatory
	// fields: a username and a live password enclave. A destroyed password
	// also matches enclave.ErrEnclaveDestroyed.
	ErrMissingCredentials = errors.New("api: username and password are required")
	// ErrMissingPIN indicates a backend requires a PIN/secret but none was provided.
	ErrMissingPIN = errors.New("api: pin required")
	// ErrMissingOTP indicates a backend requires an OTP but none was provided.
	ErrMissingOTP = errors.New("api: otp required")
)

// NewService builds a Service from the supplied configuration.
func NewService(cfg Config) (*Service, error) {
	if len(cfg.Backends) == 0 {
		return nil, ErrNoBackends
	}

	backends := make([]Backend, 0, len(cfg.Backends))
	seen := map[BackendName]struct{}{}
	for i, b := range cfg.Backends {
		if b.Handler == nil {
			return nil, fmt.Errorf("api: backend at index %d has no handler", i)
		}
		if _, ok := seen[b.Name]; ok {
			return nil, fmt.Errorf("api: duplicate backend name %q", b.Name)
		}
		seen[b.Name] = struct{}{}
		backends = append(backends, b)
	}

	return &Service{backends: backends}, nil
}

// LoginRequest contains the credentials and optional target backend.
//
// Password and OTP are go-enclave locked memory. Password carries whatever
// single credential the target backend takes — a password, a PKCS#11 PIN, a
// TPM authorization value or an OAuth bearer token — and OTP the one-time
// password for backends that take one. Build them with
// enclave.NewMemoryEnclave (which wipes the caller's slice) or, at a boundary
// that hands out strings, enclave.NewMemoryEnclave([]byte(s)).
//
// Service.Login TAKES OWNERSHIP of both: it destroys them when the attempt
// completes, whether it succeeds, fails or is refused. Do not use or destroy
// them after passing the request to Login, and build a new request for a
// retry.
type LoginRequest struct {
	Backend  BackendName
	Username string
	Password *enclave.MemoryEnclave
	OTP      *enclave.MemoryEnclave
}

// Login attempts authentication using the configured backends.
//
// It owns req.Password and req.OTP and destroys them before returning, on
// every path. Backends borrow them for the length of their attempt. A failed
// Destroy is joined to the returned error, so a login that succeeded still
// reports credentials that could not be wiped.
func (s *Service) Login(ctx context.Context, req LoginRequest) (err error) {
	defer func() {
		err = credential.DestroyAll(err, req.Password, req.OTP)
	}()

	if s == nil || len(s.backends) == 0 {
		return ErrNoBackends
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if req.Username == "" {
		return ErrMissingCredentials
	}
	if err := credential.Require(req.Password, ErrMissingCredentials); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	var targets []Backend
	if req.Backend != "" {
		for _, b := range s.backends {
			if b.Name == req.Backend {
				targets = append(targets, b)
				break
			}
		}
		if len(targets) == 0 {
			return ErrBackendNotFound
		}
	} else {
		targets = s.backends
	}

	var errs []error
	for _, b := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := b.Handler.Authenticate(ctx, req.Username, req.Password, req.OTP); err == nil {
			return nil
		} else {
			errs = append(errs, fmt.Errorf("%s: %w", b.Name, err))
		}
	}

	if len(errs) == 0 {
		return ErrNoBackends
	}
	return errors.Join(errs...)
}

// passwordAuthenticator describes authenticators that take a username and a
// password (or bearer token) held in an enclave.
type passwordAuthenticator interface {
	Authenticate(ctx context.Context, username string, password *enclave.MemoryEnclave) error
}

// pinAuthenticator describes authenticators that take a single PIN or
// authorization value held in an enclave.
type pinAuthenticator interface {
	Authenticate(ctx context.Context, pin *enclave.MemoryEnclave) error
}

// otpAuthenticator describes authenticators that take a one-time password
// held in an enclave.
type otpAuthenticator interface {
	Authenticate(ctx context.Context, otp *enclave.MemoryEnclave) error
}

// firstLive returns primary when it holds material and fallback otherwise.
// This is the "password, else OTP" (or the reverse) choice the adapters
// make; it selects a borrowed enclave and copies nothing.
func firstLive(primary, fallback *enclave.MemoryEnclave) *enclave.MemoryEnclave {
	if primary.IsAlive() {
		return primary
	}
	return fallback
}

// PAM creates a Handler that delegates to a PAM authenticator.
func PAM(auth passwordAuthenticator) Handler {
	return HandlerFunc(func(ctx context.Context, username string, password, otp *enclave.MemoryEnclave) error {
		return auth.Authenticate(ctx, username, firstLive(password, otp))
	})
}

// RADIUS creates a Handler that delegates to a RADIUS authenticator.
func RADIUS(auth passwordAuthenticator) Handler {
	return HandlerFunc(func(ctx context.Context, username string, password, otp *enclave.MemoryEnclave) error {
		return auth.Authenticate(ctx, username, firstLive(password, otp))
	})
}

// TACACS creates a Handler that delegates to a TACACS+ authenticator.
func TACACS(auth passwordAuthenticator) Handler {
	return HandlerFunc(func(ctx context.Context, username string, password, otp *enclave.MemoryEnclave) error {
		return auth.Authenticate(ctx, username, firstLive(password, otp))
	})
}

// LDAP creates a Handler that delegates to an LDAP authenticator.
func LDAP(auth passwordAuthenticator) Handler {
	return HandlerFunc(func(ctx context.Context, username string, password, _ *enclave.MemoryEnclave) error {
		return auth.Authenticate(ctx, username, password)
	})
}

// OAuth creates a Handler that delegates to an OAuth authenticator.
// The token should be passed as the password or OTP field.
// Username is ignored for OAuth token validation.
func OAuth(auth passwordAuthenticator) Handler {
	return HandlerFunc(func(ctx context.Context, _ string, password, otp *enclave.MemoryEnclave) error {
		// Username is ignored for OAuth - token is validated directly
		return auth.Authenticate(ctx, "", firstLive(password, otp))
	})
}

// OTP creates a Handler that delegates to an OTP authenticator.
// The OTP code should be passed in the OTP field, or the Password field as a fallback.
// Username is ignored for standalone OTP validation.
// For TOTP, the code is validated against the current time with skew tolerance.
// For HOTP, the code is validated against the configured counter value.
func OTP(auth otpAuthenticator) Handler {
	return HandlerFunc(func(ctx context.Context, _ string, password, otp *enclave.MemoryEnclave) error {
		code := firstLive(otp, password)
		if !code.IsAlive() {
			return ErrMissingOTP
		}
		return auth.Authenticate(ctx, code)
	})
}

// PKCS11 adapts a PIN-based authenticator into a Handler.
func PKCS11(auth pinAuthenticator) Handler {
	return HandlerFunc(func(ctx context.Context, _ string, password, otp *enclave.MemoryEnclave) error {
		pin := firstLive(password, otp)
		if !pin.IsAlive() {
			return ErrMissingPIN
		}
		return auth.Authenticate(ctx, pin)
	})
}

// YubiKey adapts an OTP-based authenticator into a Handler.
func YubiKey(auth otpAuthenticator) Handler {
	return HandlerFunc(func(ctx context.Context, _ string, _, otp *enclave.MemoryEnclave) error {
		if !otp.IsAlive() {
			return ErrMissingOTP
		}
		return auth.Authenticate(ctx, otp)
	})
}

// TPM2 adapts a password-based TPM 2.0 authenticator into a Handler.
// The password is used to authorize unsealing of data from the TPM.
func TPM2(auth pinAuthenticator) Handler {
	return HandlerFunc(func(ctx context.Context, _ string, password, otp *enclave.MemoryEnclave) error {
		pin := firstLive(password, otp)
		if !pin.IsAlive() {
			return ErrMissingPIN
		}
		return auth.Authenticate(ctx, pin)
	})
}

// Ensure the concrete authenticators satisfy the passwordAuthenticator interface.
var (
	_ passwordAuthenticator = (*ldapauth.Authenticator)(nil)
	_ passwordAuthenticator = (*oauth.Authenticator)(nil)
	_ passwordAuthenticator = (*pam.Authenticator)(nil)
	_ passwordAuthenticator = (*radius.Authenticator)(nil)
	_ passwordAuthenticator = (*tacacs.Authenticator)(nil)
	_ pinAuthenticator      = (*pkcs11.Authenticator)(nil)
	_ pinAuthenticator      = (*tpm2.Authenticator)(nil)
	_ otpAuthenticator      = (*yubikey.Authenticator)(nil)
	_ otpAuthenticator      = (*otp.Authenticator)(nil)
)
