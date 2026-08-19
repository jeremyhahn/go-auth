// RADIUS is excluded from fips140only builds.
//
// Every RADIUS exchange is authenticated with MD5: RFC 2865 §3 defines the
// Request/Response Authenticator as MD5(Code || ID || Length || RequestAuth ||
// Attributes || Secret), and RFC 2869 §5.14 defines the Message-Authenticator
// as HMAC-MD5. There is no conforming RADIUS without MD5, and RadSec (RFC 6614)
// does not help — it wraps the same packet in TLS, and the inner authenticator
// is still MD5. So this backend cannot be made FIPS-140-only compliant; it is
// kept out of that build entirely rather than shipped as a backend that panics
// on first use. See docs/fips.md.

//go:build !fips140only

package radius

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	radiuslib "layeh.com/radius"
	"layeh.com/radius/rfc2865"

	secretpkg "github.com/jeremyhahn/go-auth/pkg/secret"
)

var (
	// ErrRejected indicates the RADIUS server rejected the credentials provided.
	ErrRejected = errors.New("radius: access rejected")
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
// The packet an exchanger is given aliases the shared secret in protected
// memory, which is unmapped as soon as the exchange returns. An implementation
// must not retain the packet, its Secret field, or anything derived from them
// beyond the call — a later read is of unmapped memory and faults the process.
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
	// secret is the RADIUS shared secret, sealed in protected memory for the
	// lifetime of the authenticator and opened only for the duration of a
	// single packet exchange.
	secret *secretpkg.Secret
	client packetExchanger
	eapTLS *EAPTLSConfig
}

// NewAuthenticator constructs a RADIUS authenticator.
//
// The address must include host and port (for example, "127.0.0.1:1812"). The secret
// provides the shared secret used to protect Access-Request packets. Options allow callers
// to adjust transport behavior, enable TLS, or supply custom packet exchangers.
//
// The secret is sealed in protected memory before this returns, but the string
// the caller passed in cannot be wiped and stays resident until the collector
// reclaims it.
//
// Deprecated: use NewAuthenticatorWithSecret, which takes the shared secret in
// protected memory and never requires it to exist as a Go string. This
// constructor is still supported and will be removed in the coordinated
// breaking release.
func NewAuthenticator(address, secret string, opts ...Option) (*Authenticator, error) {
	if secret == "" {
		return nil, errors.New("radius: secret must not be empty")
	}
	sealed, err := secretpkg.NewString(secret)
	if err != nil {
		return nil, fmt.Errorf("radius: seal shared secret: %w", err)
	}
	return NewAuthenticatorWithSecret(address, sealed, opts...)
}

// NewAuthenticatorWithSecret constructs a RADIUS authenticator whose shared
// secret is held in protected memory.
//
// It is the protected-memory replacement for NewAuthenticator: the secret is
// opened only for the duration of a single packet exchange, and the plaintext
// is wiped and unmapped before Authenticate returns. Build the secret with
// secret.New or secret.NewString.
//
// The authenticator borrows the secret and does not take ownership of it:
// destroy it when the last component using it is done.
func NewAuthenticatorWithSecret(address string, sharedSecret *secretpkg.Secret, opts ...Option) (*Authenticator, error) {
	if address == "" {
		return nil, errors.New("radius: address must not be empty")
	}
	if sharedSecret.Size() == 0 {
		return nil, errors.New("radius: secret must not be empty")
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

// Authenticate validates the provided username/password pair.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) error {
	if a.eapTLS != nil {
		return a.authenticateEAPTLS(ctx, username, password)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if username == "" {
		return errors.New("radius: username must not be empty")
	}
	if password == "" {
		return errors.New("radius: password must not be empty")
	}

	// The packet keeps a reference to the shared secret rather than a copy of
	// it: layeh.com/radius reads it back when the request is encoded and again
	// when the response authenticator is checked. So the whole exchange runs
	// inside Open, and only the response code — which carries nothing secret —
	// is carried back out. Nothing that aliases the key may escape this
	// callback: the memory is unmapped when it returns, so a retained
	// reference faults rather than reads stale bytes.
	var code radiuslib.Code
	err := a.secret.Open(func(sharedSecret []byte) error {
		packet := radiuslib.New(radiuslib.CodeAccessRequest, sharedSecret)
		if err := rfc2865.UserName_SetString(packet, username); err != nil {
			return fmt.Errorf("radius: set username: %w", err)
		}
		if err := rfc2865.UserPassword_SetString(packet, password); err != nil {
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
