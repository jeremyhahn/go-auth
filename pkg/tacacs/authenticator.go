package tacacs

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	tacplus "github.com/nwaples/tacplus"
)

// Authenticator provides TACACS+ username/password authentication.
type Authenticator struct {
	addr        string
	secret      []byte
	privLevel   uint8
	timeout     time.Duration
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	mu sync.Mutex
}

// Option configures an Authenticator.
type Option func(*Authenticator)

// WithPrivLevel overrides the privilege level sent in authentication requests.
func WithPrivLevel(level uint8) Option {
	return func(a *Authenticator) {
		a.privLevel = level
	}
}

// WithTimeout sets a read/write timeout for TACACS+ operations.
func WithTimeout(d time.Duration) Option {
	return func(a *Authenticator) {
		a.timeout = d
	}
}

// WithDialContext injects a custom dialer (used in tests).
func WithDialContext(dial func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(a *Authenticator) {
		a.dialContext = dial
	}
}

// NewAuthenticator constructs a TACACS+ authenticator for the given server.
func NewAuthenticator(addr, secret string, opts ...Option) (*Authenticator, error) {
	if addr == "" {
		return nil, errors.New("tacacs: address must not be empty")
	}
	if secret == "" {
		return nil, errors.New("tacacs: secret must not be empty")
	}

	a := &Authenticator{
		addr:      addr,
		secret:    []byte(secret),
		privLevel: 1,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(a)
		}
	}
	return a, nil
}

// ErrAuthenticationFailed indicates TACACS+ rejected the supplied credentials.
var ErrAuthenticationFailed = errors.New("tacacs: authentication failed")

// Authenticate verifies username/password credentials against the TACACS+ server.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) error {
	if username == "" {
		return errors.New("tacacs: username must not be empty")
	}
	if password == "" {
		return errors.New("tacacs: password must not be empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	client := &tacplus.Client{
		Addr: a.addr,
		ConnConfig: tacplus.ConnConfig{
			Secret:       append([]byte(nil), a.secret...),
			ReadTimeout:  a.timeout,
			WriteTimeout: a.timeout,
		},
		DialContext: a.dialContext,
	}
	defer client.Close()

	start := &tacplus.AuthenStart{
		Action:        tacplus.AuthenActionLogin,
		PrivLvl:       a.privLevel,
		AuthenType:    tacplus.AuthenTypeASCII,
		AuthenService: tacplus.AuthenServiceLogin,
		User:          username,
	}

	reply, session, err := client.SendAuthenStart(ctx, start)
	if err != nil {
		return err
	}
	if session != nil {
		defer session.Close()
	}

	return a.handleReply(ctx, session, reply, username, password)
}

func (a *Authenticator) handleReply(ctx context.Context, session *tacplus.ClientSession, reply *tacplus.AuthenReply, username, password string) error {
	for {
		switch reply.Status {
		case tacplus.AuthenStatusPass:
			return nil
		case tacplus.AuthenStatusFail:
			return ErrAuthenticationFailed
		case tacplus.AuthenStatusError:
			if reply.ServerMsg != "" {
				return errors.New("tacacs: " + reply.ServerMsg)
			}
			return errors.New("tacacs: authentication error")
		case tacplus.AuthenStatusGetUser:
			var err error
			reply, err = continueSession(ctx, session, username, "tacacs: session unexpectedly nil during username prompt")
			if err != nil {
				return err
			}
		case tacplus.AuthenStatusGetPass, tacplus.AuthenStatusGetData:
			var err error
			reply, err = continueSession(ctx, session, password, "tacacs: session unexpectedly nil during password prompt")
			if err != nil {
				return err
			}
		case tacplus.AuthenStatusRestart:
			var err error
			reply, err = continueSession(ctx, session, "", "tacacs: session unexpectedly nil during restart")
			if err != nil {
				return err
			}
		default:
			return errors.New("tacacs: unsupported reply status")
		}
	}
}

func continueSession(ctx context.Context, session *tacplus.ClientSession, message, errMsg string) (*tacplus.AuthenReply, error) {
	if session == nil {
		return nil, errors.New(errMsg)
	}
	return session.Continue(ctx, message)
}
