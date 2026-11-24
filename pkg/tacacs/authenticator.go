// TACACS+ obfuscates bodies with an MD5 keystream (RFC 8907 §4.5), so under GODEBUG=fips140=only the constructors return ErrFIPSUnsupported. See docs/fips.md.

package tacacs

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
	tacplus "github.com/nwaples/tacplus"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
)

var (
	// ErrAuthenticationFailed indicates TACACS+ rejected the supplied credentials.
	ErrAuthenticationFailed = errors.New("tacacs: authentication failed")
	// ErrEmptyAddress indicates NewAuthenticator was given no server address.
	ErrEmptyAddress = errors.New("tacacs: address must not be empty")
	// ErrMissingSharedSecret indicates NewAuthenticator was given no live
	// shared-secret enclave. A destroyed one also matches
	// enclave.ErrEnclaveDestroyed.
	ErrMissingSharedSecret = errors.New("tacacs: secret must not be empty")
	// ErrMissingUsername indicates Authenticate was called without a username.
	ErrMissingUsername = errors.New("tacacs: username must not be empty")
	// ErrMissingPassword indicates Authenticate was called without a live
	// password enclave. A destroyed one also matches
	// enclave.ErrEnclaveDestroyed.
	ErrMissingPassword = errors.New("tacacs: password must not be empty")
	// ErrClosed indicates the authenticator has been closed and its shared
	// secret destroyed.
	ErrClosed = errors.New("tacacs: authenticator is closed")
)

// Authenticator provides TACACS+ username/password authentication.
type Authenticator struct {
	addr string
	// secret is lent to tacplus only for one Authenticate, whose crypt runs on the calling goroutine; re-check on a tacplus upgrade (residue R3).
	secret      *enclave.MemoryEnclave
	privLevel   uint8
	timeout     time.Duration
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// lifecycle orders Close against in-flight calls: every call holds the
	// read lock for its whole length and Close takes the write lock, so the
	// credential is destroyed only once no call can still need it.
	lifecycle sync.RWMutex
	closed    bool // guarded by lifecycle
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

// NewAuthenticator constructs a TACACS+ authenticator; it takes ownership of sharedSecret and returns ErrFIPSUnsupported first under FIPS activation.
func NewAuthenticator(addr string, sharedSecret *enclave.MemoryEnclave, opts ...Option) (*Authenticator, error) {
	if err := validateArgs(addr, sharedSecret); err != nil {
		return nil, credential.DestroyAll(err, sharedSecret)
	}

	a := &Authenticator{
		addr:      addr,
		secret:    sharedSecret,
		privLevel: 1,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(a)
		}
	}
	return a, nil
}

func validateArgs(addr string, sharedSecret *enclave.MemoryEnclave) error {
	// Ahead of the argument checks: under FIPS activation there is nothing
	// the secret could be used for. See fips.go.
	if fips140OnlyActive() {
		return ErrFIPSUnsupported
	}
	if addr == "" {
		return ErrEmptyAddress
	}
	return credential.Require(sharedSecret, ErrMissingSharedSecret)
}

// Close destroys the shared secret the authenticator owns. It waits for every
// in-flight Authenticate to return first, and it is idempotent. Authenticate
// fails with ErrClosed afterwards.
func (a *Authenticator) Close() error {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	a.closed = true
	return a.secret.Destroy()
}

// Authenticate verifies a username and borrowed password; it returns ErrFIPSUnsupported under FIPS activation.
func (a *Authenticator) Authenticate(ctx context.Context, username string, password *enclave.MemoryEnclave) error {
	if fips140OnlyActive() {
		return ErrFIPSUnsupported
	}
	a.lifecycle.RLock()
	defer a.lifecycle.RUnlock()
	if a.closed {
		return ErrClosed
	}
	if username == "" {
		return ErrMissingUsername
	}
	if err := credential.Require(password, ErrMissingPassword); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// The secret keys body obfuscation (RFC 8907 §4.5); the borrow covers every read. Residue R3: tacplus copies it per packet.
	return a.secret.WithBytes(func(sessionSecret []byte) error {
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
	})
}

func (a *Authenticator) handleReply(ctx context.Context, session *tacplus.ClientSession, reply *tacplus.AuthenReply, username string, password *enclave.MemoryEnclave) error {
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
			// Residue R3: tacplus's Continue takes the reply as a string. It
			// marshals it into the packet buffer and obfuscates that buffer in
			// place before writing, and the string itself is wiped on return.
			err := credential.WithTransientString(password, func(plaintext string) error {
				var err error
				reply, err = continueSession(ctx, session, plaintext, "tacacs: session unexpectedly nil during password prompt")
				return err
			})
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
