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
	secret  string
	client  packetExchanger
	eapTLS  *EAPTLSConfig
}

// NewAuthenticator constructs a RADIUS authenticator.
//
// The address must include host and port (for example, "127.0.0.1:1812"). The secret
// provides the shared secret used to protect Access-Request packets. Options allow callers
// to adjust transport behaviour, enable TLS, or supply custom packet exchangers.
func NewAuthenticator(address, secret string, opts ...Option) (*Authenticator, error) {
	if address == "" {
		return nil, errors.New("radius: address must not be empty")
	}
	if secret == "" {
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
		secret:  secret,
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

	packet := radiuslib.New(radiuslib.CodeAccessRequest, []byte(a.secret))
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

	switch response.Code {
	case radiuslib.CodeAccessAccept:
		return nil
	case radiuslib.CodeAccessReject:
		return ErrRejected
	default:
		return fmt.Errorf("radius: unexpected response code %s", response.Code)
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
				conn.Write(wire)
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
