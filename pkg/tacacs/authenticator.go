// TACACS+ is in every build and refuses to run when FIPS is activated.
//
// RFC 8907 §4.5 obfuscates every packet body with an MD5-based keystream
// (a chain of MD5(session_id || key || version || seq_no || prev_hash) blocks
// XORed over the body). It is the only body encoding the protocol defines, so
// a conforming TACACS+ client cannot avoid MD5. Under GODEBUG=fips140=only the
// constructors therefore return ErrFIPSUnsupported (fips.go) rather than
// shipping a backend that panics on first use. See docs/fips.md.

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
	// secret is the TACACS+ shared secret in locked memory. The authenticator
	// owns it, lends it to tacplus for the length of one Authenticate, and
	// destroys it in Close.
	//
	// Lending the locked pages directly, rather than a copy, is safe because
	// of where tacplus v0.0.3 reads the key. ConnConfig.Secret is used only by
	// crypt, which runs in session.readPacket and session.writePacket — and
	// those run on the goroutine that called SendAuthenStart or Continue, so
	// every read is over before Authenticate returns. The connection's own
	// goroutines (serve, readLoop, writeLoop) move ciphertext and never call
	// crypt. The one handler serve spawns on a client connection, for a packet
	// that belongs to no session, fails its sequence-number checks before
	// crypt can run: a new session expects seq 1, and a client rejects odd
	// sequence numbers. So nothing reads the slice after the borrow ends, and
	// Close can unmap it. A tacplus upgrade must re-check this; see residue R3
	// in docs/security/credential-residues.md.
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

// NewAuthenticator constructs a TACACS+ authenticator for the given server.
//
// sharedSecret is the RFC 8907 shared secret in locked memory; build it with
// enclave.NewMemoryEnclave (which wipes the caller's slice) or, from a
// configuration string, enclave.NewMemoryEnclaveFromString.
//
// It TAKES OWNERSHIP of sharedSecret on every return path: when it returns an
// error — the FIPS refusal included — the enclave has already been destroyed,
// and otherwise Close destroys it. Do not use or destroy it afterwards, and
// give each authenticator its own enclave.
//
// Under FIPS activation this returns ErrFIPSUnsupported ahead of every argument
// check, so startup code can branch on errors.Is(err, ErrFIPSUnsupported) to
// learn the backend is unavailable.
func NewAuthenticator(addr string, sharedSecret *enclave.MemoryEnclave, opts ...Option) (*Authenticator, error) {
	if err := validateArgs(addr, sharedSecret); err != nil {
		sharedSecret.Destroy()
		return nil, err
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
	return a.secret.DestroyErr()
}

// Authenticate verifies username/password credentials against the TACACS+ server.
//
// The password is BORROWED and never destroyed here. Under FIPS activation it
// returns ErrFIPSUnsupported before any packet is built; the constructor
// already refuses, so this only matters for an authenticator that did not
// come from it.
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

	// The secret keys the obfuscation of every packet body in the session
	// (RFC 8907 §4.5). tacplus reads it only on this goroutine, inside
	// SendAuthenStart and Continue (see the secret field), so the borrow
	// covers every read and Close cannot unmap the pages under one.
	//
	// Residue R3: tacplus copies the key into a heap buffer for each packet.
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
