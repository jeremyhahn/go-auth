package pam

import (
	"context"
	"errors"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
)

// Session represents an authenticated PAM transaction lifecycle.
//
// Authenticate BORROWS the password for the length of the call: an
// implementation reads it through WithBytes (or, at the PAM conversation,
// through a copy it wipes), must not retain it, and must not destroy it.
type Session interface {
	Authenticate(ctx context.Context, password *enclave.MemoryEnclave) error
	Close() error
}

// SessionOpener creates new PAM sessions for a given service/username.
type SessionOpener interface {
	Open(ctx context.Context, service, username string) (Session, error)
}

var (
	// ErrEmptyServiceName indicates NewAuthenticator was given no PAM service.
	ErrEmptyServiceName = errors.New("pam: service name must not be empty")
	// ErrMissingUsername indicates Authenticate was called without a username.
	ErrMissingUsername = errors.New("pam: username must not be empty")
	// ErrMissingPassword indicates Authenticate was called without a live
	// password enclave. A destroyed one also matches
	// enclave.ErrEnclaveDestroyed.
	ErrMissingPassword = errors.New("pam: password must not be empty")

	errSystemOpenerUnavailable = errors.New("pam: system session opener unavailable; requires cgo build with PAM support")
	systemSessionOpener        SessionOpener
)

// Authenticator drives PAM authentication using a configurable session opener.
type Authenticator struct {
	service       string
	sessionOpener SessionOpener
}

// NewAuthenticator constructs a PAM authenticator using the provided service name.
// A nil opener selects the default implementation that talks to the host PAM stack.
func NewAuthenticator(service string, opener SessionOpener) (*Authenticator, error) {
	if service == "" {
		return nil, ErrEmptyServiceName
	}
	if opener == nil {
		if systemSessionOpener == nil {
			return nil, errSystemOpenerUnavailable
		}
		opener = systemSessionOpener
	}
	return &Authenticator{service: service, sessionOpener: opener}, nil
}

// Authenticate validates a user/password pair against the configured PAM service.
//
// The password is BORROWED: it is lent to the PAM conversation and never
// destroyed here; the caller still owns it.
func (a *Authenticator) Authenticate(ctx context.Context, username string, password *enclave.MemoryEnclave) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if username == "" {
		return ErrMissingUsername
	}
	if err := credential.Require(password, ErrMissingPassword); err != nil {
		return err
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	session, err := a.sessionOpener.Open(ctx, a.service, username)
	if err != nil {
		return err
	}

	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			if err != nil {
				err = errors.Join(err, closeErr)
			} else {
				err = closeErr
			}
		}
	}()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	return session.Authenticate(ctx, password)
}

type defaultSessionOpener struct{}
