package ldapauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Authenticator performs username/password authentication against an LDAP directory.
type Authenticator struct {
	url             string
	userDNTemplate  string
	serviceBindDN   string
	servicePassword string
	startTLS        bool
	tlsConfig       *tls.Config
	timeout         time.Duration
	implicitTLS     bool

	dialContext func(ctx context.Context) (ldapConn, error)
}

// Option configures the authenticator.
type Option func(*Authenticator)

// WithUserDNTemplate configures how user DNs are derived from usernames.
// The template must contain a single %s verb, which will be replaced with the username.
func WithUserDNTemplate(template string) Option {
	return func(a *Authenticator) {
		a.userDNTemplate = template
	}
}

// WithServiceAccount sets the DN and password used for an initial bind before authenticating users.
func WithServiceAccount(dn, password string) Option {
	return func(a *Authenticator) {
		a.serviceBindDN = dn
		a.servicePassword = password
	}
}

// WithStartTLS enables StartTLS negotiation after connecting over ldap://.
func WithStartTLS() Option {
	return func(a *Authenticator) {
		a.startTLS = true
	}
}

// WithTLSConfig supplies the TLS configuration used for StartTLS or ldaps connections.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(a *Authenticator) {
		a.tlsConfig = cfg
	}
}

// WithTimeout sets the dial (and read) timeout for LDAP operations.
func WithTimeout(d time.Duration) Option {
	return func(a *Authenticator) {
		a.timeout = d
	}
}

// WithDialContext overrides the dial logic. Used in tests.
func WithDialContext(dial func(ctx context.Context) (ldapConn, error)) Option {
	return func(a *Authenticator) {
		a.dialContext = dial
	}
}

// ldapConn captures the subset of methods we exercise on *ldap.Conn.
type ldapConn interface {
	Bind(username, password string) error
	StartTLS(config *tls.Config) error
	Close() error
}

var (
	// ErrMissingTemplate indicates no template was supplied to derive user DNs.
	ErrMissingTemplate = errors.New("ldap: user DN template must be configured")
)

// NewAuthenticator constructs an LDAP authenticator targeting the provided LDAP URL.
func NewAuthenticator(url string, opts ...Option) (*Authenticator, error) {
	if strings.TrimSpace(url) == "" {
		return nil, errors.New("ldap: url must not be empty")
	}

	auth := &Authenticator{url: url}

	for _, opt := range opts {
		if opt != nil {
			opt(auth)
		}
	}

	if strings.HasPrefix(strings.ToLower(url), "ldaps://") {
		auth.implicitTLS = true
		auth.startTLS = false
		if auth.tlsConfig == nil {
			auth.tlsConfig = defaultTLSConfig()
		}
	} else if auth.startTLS && auth.tlsConfig == nil {
		auth.tlsConfig = defaultTLSConfig()
	}

	return auth, nil
}

// Authenticate binds to LDAP using the derived user DN.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(username) == "" || password == "" {
		return errors.New("ldap: username and password must not be empty")
	}
	if a.userDNTemplate == "" {
		return ErrMissingTemplate
	}

	userDN := fmt.Sprintf(a.userDNTemplate, username)

	conn, err := a.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if a.startTLS {
		if err := conn.StartTLS(a.tlsConfig); err != nil {
			return fmt.Errorf("ldap: starttls failed: %w", err)
		}
	}

	if a.serviceBindDN != "" {
		if err := conn.Bind(a.serviceBindDN, a.servicePassword); err != nil {
			return fmt.Errorf("ldap: service bind failed: %w", err)
		}
	}

	if err := conn.Bind(userDN, password); err != nil {
		return fmt.Errorf("ldap: user bind failed: %w", err)
	}

	return nil
}

func (a *Authenticator) dial(ctx context.Context) (ldapConn, error) {
	if a.dialContext != nil {
		return a.dialContext(ctx)
	}

	dialer := &net.Dialer{}
	if a.timeout > 0 {
		dialer.Timeout = a.timeout
	}

	opts := []ldap.DialOpt{ldap.DialWithDialer(dialer)}

	if a.implicitTLS {
		tlsCfg := a.tlsConfig
		if tlsCfg == nil {
			tlsCfg = defaultTLSConfig()
		}
		opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
	}

	conn, err := ldap.DialURL(a.url, opts...)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial failed: %w", err)
	}
	return conn, nil
}

func defaultTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}
