package pam

import (
	"context"
	"errors"
)

// Session represents an authenticated PAM transaction lifecycle.
type Session interface {
	Authenticate(ctx context.Context, password string) error
	Close() error
}

// SessionOpener creates new PAM sessions for a given service/username.
type SessionOpener interface {
	Open(ctx context.Context, service, username string) (Session, error)
}

var (
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
		return nil, errors.New("service name must not be empty")
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
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if username == "" {
		return errors.New("username must not be empty")
	}
	if password == "" {
		return errors.New("password must not be empty")
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
