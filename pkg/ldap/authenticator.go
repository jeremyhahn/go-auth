package ldapauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
)

// Authenticator performs username/password authentication against an LDAP directory.
type Authenticator struct {
	url            string
	userDNTemplate string
	serviceBindDN  string
	// servicePassword is the service account's bind password in locked
	// memory. The authenticator owns it from the moment WithServiceAccount is
	// applied, opens it only for the duration of a single service bind, and
	// destroys it in Close (or in NewAuthenticator, if construction fails).
	servicePassword *enclave.MemoryEnclave
	// optionErr collects a failed Destroy of a password an option replaced.
	// Options cannot return an error, so NewAuthenticator reports it.
	optionErr   error
	startTLS    bool
	tlsConfig   *tls.Config
	timeout     time.Duration
	implicitTLS bool
	// lifecycle orders Close against in-flight calls: every call holds the
	// read lock for its whole length and Close takes the write lock, so the
	// credential is destroyed only once no call can still need it.
	lifecycle sync.RWMutex
	closed    bool // guarded by lifecycle

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

// WithServiceAccount sets the DN and password used for an initial bind before
// authenticating users.
//
// The authenticator TAKES OWNERSHIP of password: NewAuthenticator destroys it
// if construction fails, and Close destroys it otherwise. Do not use or
// destroy it after passing it here. Applying the option twice replaces the
// first password, which is destroyed.
//
// The password is opened only for the duration of the service bind. go-ldap's
// Bind takes it as a string, so it is lent through a heap copy that is wiped
// when the bind returns; go-ldap's BER packet keeps its own copy, which is
// residue R1 (docs/security/credential-residues.md).
func WithServiceAccount(dn string, password *enclave.MemoryEnclave) Option {
	return func(a *Authenticator) {
		if a.servicePassword != password {
			a.optionErr = credential.DestroyAll(a.optionErr, a.servicePassword)
		}
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
	// ErrEmptyURL indicates NewAuthenticator was given no LDAP URL.
	ErrEmptyURL = errors.New("ldap: url must not be empty")
	// ErrMissingCredentials indicates Authenticate was called without a
	// username or without a live password enclave. A destroyed password also
	// matches enclave.ErrEnclaveDestroyed.
	ErrMissingCredentials = errors.New("ldap: username and password must not be empty")
	// ErrServicePasswordRequired indicates WithServiceAccount was given a DN
	// without a live password enclave.
	ErrServicePasswordRequired = errors.New("ldap: service account password must be provided")
	// ErrClosed indicates the authenticator has been closed and its service
	// account password destroyed.
	ErrClosed = errors.New("ldap: authenticator is closed")
)

// NewAuthenticator constructs an LDAP authenticator targeting the provided LDAP URL.
//
// It owns the service-account password from WithServiceAccount on every
// return path: when it returns an error the password has already been
// destroyed.
func NewAuthenticator(url string, opts ...Option) (*Authenticator, error) {
	auth := &Authenticator{url: url}

	// Options run before the URL check so that a password handed over in one
	// of them is known to this function, and destroyed, on every refusal.
	for _, opt := range opts {
		if opt != nil {
			opt(auth)
		}
	}

	err := auth.validate()
	if auth.optionErr != nil {
		err = errors.Join(err, auth.optionErr)
	}
	if err != nil {
		return nil, credential.DestroyAll(err, auth.servicePassword)
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

func (a *Authenticator) validate() error {
	if strings.TrimSpace(a.url) == "" {
		return ErrEmptyURL
	}
	if a.serviceBindDN != "" {
		return credential.Require(a.servicePassword, ErrServicePasswordRequired)
	}
	return nil
}

// Close destroys the service-account password the authenticator owns. It
// waits for every in-flight Authenticate to return first — one that has not
// reached its service bind yet still needs the password — and it is
// idempotent. Authenticate fails with ErrClosed afterwards.
func (a *Authenticator) Close() error {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	a.closed = true
	return a.servicePassword.Destroy()
}

// Authenticate binds to LDAP using the derived user DN.
//
// The password is BORROWED: it is opened for the user bind and never
// destroyed here; the caller still owns it.
func (a *Authenticator) Authenticate(ctx context.Context, username string, password *enclave.MemoryEnclave) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.lifecycle.RLock()
	defer a.lifecycle.RUnlock()
	if a.closed {
		return ErrClosed
	}
	if strings.TrimSpace(username) == "" {
		return ErrMissingCredentials
	}
	if err := credential.Require(password, ErrMissingCredentials); err != nil {
		return err
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
		// Residue R1: go-ldap's Bind takes the password as a string.
		err := credential.WithTransientString(a.servicePassword, func(servicePassword string) error {
			return conn.Bind(a.serviceBindDN, servicePassword)
		})
		if err != nil {
			return fmt.Errorf("ldap: service bind failed: %w", err)
		}
	}

	// Residue R1: go-ldap's Bind takes the password as a string.
	err = credential.WithTransientString(password, func(userPassword string) error {
		return conn.Bind(userDN, userPassword)
	})
	if err != nil {
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
