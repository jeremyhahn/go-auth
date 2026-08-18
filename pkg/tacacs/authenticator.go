package tacacs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	tacplus "github.com/nwaples/tacplus"

	secretpkg "github.com/jeremyhahn/go-auth/pkg/secret"
)

// Authenticator provides TACACS+ username/password authentication.
type Authenticator struct {
	addr string
	// secret is the TACACS+ shared secret in a locked, non-swappable buffer
	// that lives as long as the authenticator does.
	//
	// Every other backend in this library seals its secret in an enclave and
	// opens it around a single exchange. TACACS+ cannot: tacplus keeps the
	// slice it is given for the life of the connection and decrypts with it
	// from goroutines it does not join — conn.serve and its readLoop, plus the
	// handler serve spawns for a packet belonging to no known session — and
	// neither Client.Close nor session.Close waits for any of them. Memory
	// unmapped at the end of an Open would fault those readers; an ordinary
	// heap copy would put the plaintext where it can be swapped or dumped, and
	// wiping it afterwards would race the same readers. A locked buffer whose
	// lifetime is the authenticator's is the shape that is both safe and
	// protected: mlock(2)ed so it is never paged out, MADV_DONTDUMP so it is
	// never in a core dump, guard-paged, and never in the Go heap.
	//
	// It follows that this backend has no release point. Destroying the buffer
	// would unmap pages a tacplus goroutine may still be reading, which faults
	// the process, and wiping them instead would be an unsynchronized write to
	// the same bytes; neither can be made safe without joining goroutines the
	// dependency does not expose. So the key stays resident, in locked memory,
	// for as long as the process holds the authenticator — one page per
	// authenticator, which is why one per server is the intended shape. The
	// alternatives are worse: a plaintext heap copy, or a Close that can crash
	// the process. Releasing it safely needs tacplus to be forked or replaced,
	// which is an owner decision rather than part of this additive change.
	secret      *secretpkg.Locked
	privLevel   uint8
	timeout     time.Duration
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
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
//
// The secret is sealed in protected memory before this returns, but the string
// the caller passed in cannot be wiped and stays resident until the collector
// reclaims it.
//
// Deprecated: use NewAuthenticatorWithSecret, which takes the shared secret in
// protected memory and never requires it to exist as a Go string. This
// constructor is still supported and will be removed in the coordinated
// breaking release.
func NewAuthenticator(addr, secret string, opts ...Option) (*Authenticator, error) {
	if secret == "" {
		return nil, errors.New("tacacs: secret must not be empty")
	}
	sealed, err := secretpkg.NewString(secret)
	if err != nil {
		return nil, fmt.Errorf("tacacs: seal shared secret: %w", err)
	}
	defer sealed.Destroy()
	return NewAuthenticatorWithSecret(addr, sealed, opts...)
}

// NewAuthenticatorWithSecret constructs a TACACS+ authenticator whose shared
// secret is held in protected memory.
//
// It is the protected-memory replacement for NewAuthenticator: the secret
// never exists as a Go string or as a heap []byte. Build it with secret.New or
// secret.NewString.
//
// The authenticator copies the secret into its own locked buffer and does not
// take ownership of the one it is given: destroy that when the last component
// using it is done. Its own copy is held for the life of the authenticator and
// has no release point — see the Authenticator type for why, and construct one
// authenticator per server rather than one per authentication.
func NewAuthenticatorWithSecret(addr string, sharedSecret *secretpkg.Secret, opts ...Option) (*Authenticator, error) {
	if addr == "" {
		return nil, errors.New("tacacs: address must not be empty")
	}
	if sharedSecret.Size() == 0 {
		return nil, errors.New("tacacs: secret must not be empty")
	}

	locked, err := sharedSecret.Lock()
	if err != nil {
		return nil, fmt.Errorf("tacacs: lock shared secret: %w", err)
	}

	a := &Authenticator{
		addr:      addr,
		secret:    locked,
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

	// The secret keys the obfuscation of every packet body in the session
	// (RFC 8907 §4.5), so tacplus holds the slice it is given for as long as
	// the connection lives and reads it back on every exchange — from
	// goroutines it does not join. Handing it the locked buffer directly is
	// what makes that safe: those bytes stay mapped for the authenticator's
	// lifetime, so no reader can outlive them, and there is no heap copy to
	// wipe or to leave behind.
	sessionSecret := a.secret.Bytes()
	if len(sessionSecret) == 0 {
		return errors.New("tacacs: shared secret is unavailable")
	}

	client := &tacplus.Client{
		Addr: a.addr,
		ConnConfig: tacplus.ConnConfig{
			Secret:       sessionSecret,
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
