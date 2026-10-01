// RADIUS is in every build and refuses to run when FIPS is activated.
//
// Every RADIUS exchange is authenticated with MD5: RFC 2865 §3 defines the
// Request/Response Authenticator as MD5(Code || ID || Length || RequestAuth ||
// Attributes || Secret), and RFC 2869 §5.14 defines the Message-Authenticator
// as HMAC-MD5. There is no conforming RADIUS without MD5, and RadSec (RFC 6614)
// does not help — it wraps the same packet in TLS, and the inner authenticator
// is still MD5. So this backend cannot be made FIPS-140-only compliant; under
// GODEBUG=fips140=only the constructors return ErrFIPSUnsupported (fips.go)
// rather than shipping a backend that panics on first use. See docs/fips.md.

package radius

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
	radiuslib "layeh.com/radius"
	"layeh.com/radius/rfc2865"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
)

var (
	// ErrRejected indicates the RADIUS server rejected the credentials provided.
	ErrRejected = errors.New("radius: access rejected")
	// ErrEmptyAddress indicates NewAuthenticator was given no server address.
	ErrEmptyAddress = errors.New("radius: address must not be empty")
	// ErrMissingSharedSecret indicates NewAuthenticator was given no live
	// shared-secret enclave. A destroyed one also matches
	// enclave.ErrEnclaveDestroyed.
	ErrMissingSharedSecret = errors.New("radius: secret must not be empty")
	// ErrMissingUsername indicates Authenticate was called without a username.
	ErrMissingUsername = errors.New("radius: username must not be empty")
	// ErrMissingPassword indicates a PAP Authenticate was called without a
	// live password enclave. A destroyed one also matches
	// enclave.ErrEnclaveDestroyed.
	ErrMissingPassword = errors.New("radius: password must not be empty")
	// ErrClosed indicates the authenticator has been closed and its shared
	// secret destroyed.
	ErrClosed = errors.New("radius: authenticator is closed")
)

type packetExchanger interface {
	exchange(ctx context.Context, packet *radiuslib.Packet, addr string) (*radiuslib.Packet, error)
}

type authConfig struct {
	exchanger          packetExchanger
	network            string
	tlsConfig          *tls.Config
	useTLS             bool
	tlsDialer          dialContext
	retry              time.Duration
	maxPacketErrors    int
	insecureSkipVerify bool
	dialTimeout        time.Duration
	eapTLS             *EAPTLSConfig
}

type dialContext interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Option configures an Authenticator.
type Option func(*authConfig)

// WithPacketExchanger overrides the packet exchanger implementation; primarily used for testing.
//
// The packet an exchanger is given aliases the shared secret's locked pages,
// borrowed for the length of the exchange and unmapped by Close. An
// implementation must not retain the packet, its Secret field, or anything
// derived from them beyond the call — a read after Close is of unmapped memory
// and faults the process.
// The exchangers in this package, and layeh.com/radius itself, use the secret
// only on the synchronous encode and verify paths.
func WithPacketExchanger(pe packetExchanger) Option {
	return func(c *authConfig) {
		c.exchanger = pe
	}
}

// WithNetwork overrides the transport network used by the underlying RADIUS client when TLS is not enabled.
func WithNetwork(network string) Option {
	return func(c *authConfig) {
		c.network = network
	}
}

// WithTLSConfig enables RadSec (RADIUS-over-TLS) using the provided TLS configuration.
// The configuration is cloned before use to avoid external mutation.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(c *authConfig) {
		c.useTLS = true
		c.tlsConfig = cfg
	}
}

// WithTLSDialer overrides the dialer used by the TLS packet exchanger. Primarily used for testing.
func WithTLSDialer(d dialContext) Option {
	return func(c *authConfig) {
		c.tlsDialer = d
	}
}

// WithRetry adjusts the resend interval for Access-Request packets.
func WithRetry(d time.Duration) Option {
	return func(c *authConfig) {
		c.retry = d
	}
}

// WithMaxPacketErrors limits how many malformed responses are tolerated before failing the exchange.
func WithMaxPacketErrors(n int) Option {
	return func(c *authConfig) {
		c.maxPacketErrors = n
	}
}

// WithInsecureSkipVerify toggles verification of response authenticators. Avoid enabling outside of controlled tests.
func WithInsecureSkipVerify(skip bool) Option {
	return func(c *authConfig) {
		c.insecureSkipVerify = skip
	}
}

// WithEAPTLS enables EAP-TLS authentication using the provided configuration.
func WithEAPTLS(cfg *EAPTLSConfig) Option {
	return func(c *authConfig) {
		c.eapTLS = cfg
	}
}

// WithDialTimeout sets the timeout on the underlying dialer.
func WithDialTimeout(d time.Duration) Option {
	return func(c *authConfig) {
		c.dialTimeout = d
	}
}

type radiusClient struct {
	client *radiuslib.Client
}

type tlsPacketExchanger struct {
	dialer             dialContext
	retry              time.Duration
	maxPacketErrors    int
	insecureSkipVerify bool
}

func (c radiusClient) exchange(ctx context.Context, packet *radiuslib.Packet, addr string) (*radiuslib.Packet, error) {
	return c.client.Exchange(ctx, packet, addr)
}

// Authenticator performs PAP-based authentication against an upstream RADIUS server.
type Authenticator struct {
	address string
	// secret is the RADIUS shared secret in locked memory. The authenticator
	// owns it, borrows it for the length of a single packet exchange, and
	// destroys it in Close.
	secret *enclave.MemoryEnclave
	client packetExchanger
	eapTLS *EAPTLSConfig
	// lifecycle orders Close against in-flight calls: every call holds the
	// read lock for its whole length and Close takes the write lock, so the
	// credential is destroyed only once no call can still need it.
	lifecycle sync.RWMutex
	closed    bool // guarded by lifecycle
}

// NewAuthenticator constructs a RADIUS authenticator.
//
// The address must include host and port (for example, "127.0.0.1:1812").
// sharedSecret is the shared secret that protects Access-Request packets, in
// locked memory; build it with enclave.NewMemoryEnclave (which wipes the
// caller's slice) or, from a configuration string, with
// enclave.NewMemoryEnclaveFromString. Options adjust transport behavior,
// enable TLS, or supply custom packet exchangers.
//
// It TAKES OWNERSHIP of sharedSecret on every return path: when it returns an
// error — the FIPS refusal included — the enclave has already been destroyed,
// and otherwise Close destroys it. Do not use or destroy it afterwards, and
// give each authenticator its own enclave.
//
// Under FIPS activation this returns ErrFIPSUnsupported ahead of every argument
// check, whatever the arguments are, so startup code can branch on
// errors.Is(err, ErrFIPSUnsupported) to learn the backend is unavailable.
func NewAuthenticator(address string, sharedSecret *enclave.MemoryEnclave, opts ...Option) (*Authenticator, error) {
	auth, err := newAuthenticator(address, sharedSecret, opts)
	if err != nil {
		sharedSecret.Destroy()
		return nil, err
	}
	return auth, nil
}

func newAuthenticator(address string, sharedSecret *enclave.MemoryEnclave, opts []Option) (*Authenticator, error) {
	// Refuse to start under FIPS activation rather than panic on the first
	// Access-Request, ahead of the argument checks: a FIPS-activated
	// deployment must be told the backend is categorically unavailable, not
	// that its arguments are wrong. See fips.go.
	if fips140OnlyActive() {
		return nil, ErrFIPSUnsupported
	}
	if address == "" {
		return nil, ErrEmptyAddress
	}
	if err := credential.Require(sharedSecret, ErrMissingSharedSecret); err != nil {
		return nil, err
	}

	cfg := &authConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}

	client := cfg.exchanger
	if client == nil {
		if cfg.useTLS {
			tlsExchanger, err := newTLSPacketExchanger(cfg)
			if err != nil {
				return nil, err
			}
			client = tlsExchanger
		} else {
			netDialer := net.Dialer{}
			if cfg.dialTimeout > 0 {
				netDialer.Timeout = cfg.dialTimeout
			}
			rClient := &radiuslib.Client{}
			if cfg.network != "" {
				rClient.Net = cfg.network
			}
			rClient.Dialer = netDialer
			if cfg.retry > 0 {
				rClient.Retry = cfg.retry
			}
			if cfg.maxPacketErrors > 0 {
				rClient.MaxPacketErrors = cfg.maxPacketErrors
			}
			rClient.InsecureSkipVerify = cfg.insecureSkipVerify
			client = radiusClient{client: rClient}
		}
	}

	return &Authenticator{
		address: address,
		secret:  sharedSecret,
		client:  client,
		eapTLS:  cfg.eapTLS,
	}, nil
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

// Authenticate validates the provided username/password pair.
//
// The password is BORROWED and never destroyed here. With EAP-TLS configured
// the client certificate is the credential, the password is ignored, and it
// may be nil.
func (a *Authenticator) Authenticate(ctx context.Context, username string, password *enclave.MemoryEnclave) error {
	a.lifecycle.RLock()
	defer a.lifecycle.RUnlock()
	if a.closed {
		return ErrClosed
	}
	if a.eapTLS != nil {
		return a.authenticateEAPTLS(ctx, username)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if username == "" {
		return ErrMissingUsername
	}
	if err := credential.Require(password, ErrMissingPassword); err != nil {
		return err
	}

	// The packet keeps a reference to the shared secret rather than a copy of
	// it: layeh.com/radius reads it back when the request is encoded and again
	// when the response authenticator is checked. So the whole exchange runs
	// inside the borrow, and only the response code — which carries nothing
	// secret — is carried back out. Nothing that aliases the key may escape
	// this callback: Close unmaps the pages, so a retained reference faults
	// rather than reads stale bytes.
	var code radiuslib.Code
	// Residue R2: layeh's MD5 state absorbs the shared secret on the heap.
	err := a.secret.WithBytes(func(sharedSecret []byte) error {
		packet := radiuslib.New(radiuslib.CodeAccessRequest, sharedSecret)
		if err := rfc2865.UserName_SetString(packet, username); err != nil {
			return fmt.Errorf("radius: set username: %w", err)
		}
		// UserPassword_Set obfuscates straight out of the borrowed bytes
		// (RFC 2865 §5.2); only the obfuscated attribute reaches the packet.
		err := password.WithBytes(func(plaintext []byte) error {
			return rfc2865.UserPassword_Set(packet, plaintext)
		})
		if err != nil {
			return fmt.Errorf("radius: set password: %w", err)
		}

		response, err := a.client.exchange(ctx, packet, a.address)
		if err != nil {
			return err
		}
		code = response.Code
		return nil
	})
	if err != nil {
		return err
	}

	switch code {
	case radiuslib.CodeAccessAccept:
		return nil
	case radiuslib.CodeAccessReject:
		return ErrRejected
	default:
		return fmt.Errorf("radius: unexpected response code %s", code)
	}
}

func newTLSPacketExchanger(cfg *authConfig) (*tlsPacketExchanger, error) {
	if cfg.tlsConfig == nil {
		return nil, errors.New("radius: TLS configuration must be provided")
	}

	var dialer dialContext
	if cfg.tlsDialer != nil {
		dialer = cfg.tlsDialer
	} else {
		clone := cfg.tlsConfig.Clone()
		if clone == nil {
			return nil, errors.New("radius: TLS configuration must not be nil")
		}
		netDialer := &net.Dialer{}
		if cfg.dialTimeout > 0 {
			netDialer.Timeout = cfg.dialTimeout
		}
		dialer = &tls.Dialer{
			NetDialer: netDialer,
			Config:    clone,
		}
	}

	return &tlsPacketExchanger{
		dialer:             dialer,
		retry:              cfg.retry,
		maxPacketErrors:    cfg.maxPacketErrors,
		insecureSkipVerify: cfg.insecureSkipVerify,
	}, nil
}

func (t *tlsPacketExchanger) exchange(ctx context.Context, packet *radiuslib.Packet, addr string) (*radiuslib.Packet, error) {
	if ctx == nil {
		panic("nil context")
	}

	wire, err := packet.Encode()
	if err != nil {
		return nil, err
	}

	conn, err := t.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	var retryTimer <-chan time.Time
	if t.retry > 0 {
		ticker := time.NewTicker(t.retry)
		defer ticker.Stop()
		retryTimer = ticker.C
	}

	go func() {
		defer conn.Close()
		for {
			select {
			case <-retryTimer:
				// Best-effort retransmit: a failed write is retried on the
				// next tick, and the surrounding read loop reports timeout.
				_, _ = conn.Write(wire)
			case <-ctx.Done():
				return
			}
		}
	}()

	incoming := make([]byte, radiuslib.MaxPacketLength)
	var packetErrorCount int

	for {
		n, err := conn.Read(incoming)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			return nil, err
		}

		received, err := radiuslib.Parse(incoming[:n], packet.Secret)
		if err != nil {
			packetErrorCount++
			if t.maxPacketErrors > 0 && packetErrorCount >= t.maxPacketErrors {
				return nil, err
			}
			continue
		}

		if !t.insecureSkipVerify && !radiuslib.IsAuthenticResponse(incoming[:n], wire, packet.Secret) {
			packetErrorCount++
			if t.maxPacketErrors > 0 && packetErrorCount >= t.maxPacketErrors {
				return nil, &radiuslib.NonAuthenticResponseError{}
			}
			continue
		}

		return received, nil
	}
}
