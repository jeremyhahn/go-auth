package ldapauth

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// retainingConn keeps the strings it was given WITHOUT copying them, so a test
// can look at what is left of them once Authenticate has returned.
type retainingConn struct {
	passwords []string
}

func (r *retainingConn) Bind(_, password string) error {
	r.passwords = append(r.passwords, password)
	return nil
}
func (r *retainingConn) StartTLS(*tls.Config) error { return nil }
func (r *retainingConn) Close() error               { return nil }

func TestAuthenticateWithServiceAccount_SendsTheRealPasswords(t *testing.T) {
	conn := &fakeConn{}
	auth, err := NewAuthenticator("ldap://example.com:389",
		WithUserDNTemplate("uid=%s,ou=people,dc=example,dc=com"),
		WithServiceAccount("cn=admin,dc=example,dc=com", pw(t, "service-password")),
		WithDialContext(func(context.Context) (ldapConn, error) { return conn, nil }))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Close()

	if err := auth.Authenticate(context.Background(), "bob", pw(t, "user-password")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(conn.binds) != 2 {
		t.Fatalf("expected two binds, got %d", len(conn.binds))
	}
	if conn.binds[0].dn != "cn=admin,dc=example,dc=com" || conn.binds[0].password != "service-password" {
		t.Fatalf("service bind = %+v", conn.binds[0])
	}
	if conn.binds[1].dn != "uid=bob,ou=people,dc=example,dc=com" || conn.binds[1].password != "user-password" {
		t.Fatalf("user bind = %+v", conn.binds[1])
	}
}

// TestBindStringsAreWipedAfterAuthenticate proves residue R1 is bounded to the
// bind: the strings go-ldap was lent read as zeros once Authenticate returns.
func TestBindStringsAreWipedAfterAuthenticate(t *testing.T) {
	conn := &retainingConn{}
	auth, err := NewAuthenticator("ldap://example.com:389",
		WithUserDNTemplate("uid=%s,dc=example,dc=com"),
		WithServiceAccount("cn=admin,dc=example,dc=com", pw(t, "service-password")),
		WithDialContext(func(context.Context) (ldapConn, error) { return conn, nil }))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Close()

	if err := auth.Authenticate(context.Background(), "bob", pw(t, "user-password")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(conn.passwords) != 2 {
		t.Fatalf("binds = %d, want 2", len(conn.passwords))
	}
	for i, p := range conn.passwords {
		if strings.Trim(p, "\x00") != "" {
			t.Fatalf("bind %d password still readable after Authenticate: %q", i, p)
		}
	}
}

// TestAuthenticateBorrowsThePassword: the per-call password stays the
// caller's, alive, on success and on failure.
func TestAuthenticateBorrowsThePassword(t *testing.T) {
	for _, bindErr := range []error{nil, errors.New("bad creds")} {
		conn := &fakeConn{bindErrs: []error{bindErr}}
		auth, err := NewAuthenticator("ldap://example.com:389",
			WithUserDNTemplate("cn=%s,dc=example,dc=com"),
			WithDialContext(func(context.Context) (ldapConn, error) { return conn, nil }))
		if err != nil {
			t.Fatalf("NewAuthenticator: %v", err)
		}
		password := pw(t, "pass")
		_ = auth.Authenticate(context.Background(), "user", password)
		if !password.IsAlive() {
			t.Fatalf("bindErr=%v: Authenticate destroyed a borrowed password", bindErr)
		}
	}
}

func TestAuthenticateRejectsDestroyedPassword(t *testing.T) {
	conn := &fakeConn{}
	auth, err := NewAuthenticator("ldap://example.com:389",
		WithUserDNTemplate("cn=%s,dc=example,dc=com"),
		WithDialContext(func(context.Context) (ldapConn, error) { return conn, nil }))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	password := pw(t, "pass")
	password.Destroy()

	err = auth.Authenticate(context.Background(), "user", password)
	if !errors.Is(err, ErrMissingCredentials) || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("err = %v, want ErrMissingCredentials joined with ErrEnclaveDestroyed", err)
	}
	if len(conn.binds) != 0 {
		t.Fatalf("bound %d times with a destroyed password", len(conn.binds))
	}
}

// TestNewAuthenticatorDestroysServicePasswordOnRefusal: ownership transfers on
// every return path, including the refusals.
func TestNewAuthenticatorDestroysServicePasswordOnRefusal(t *testing.T) {
	password := pw(t, "service-password")
	if _, err := NewAuthenticator("", WithServiceAccount("cn=admin", password)); !errors.Is(err, ErrEmptyURL) {
		t.Fatalf("err = %v, want ErrEmptyURL", err)
	}
	if password.IsAlive() {
		t.Fatal("refused construction left the service password alive")
	}
}

func TestNewAuthenticatorRequiresServicePassword(t *testing.T) {
	if _, err := NewAuthenticator("ldap://example.com", WithServiceAccount("cn=admin", nil)); !errors.Is(err, ErrServicePasswordRequired) {
		t.Fatalf("nil password: err = %v, want ErrServicePasswordRequired", err)
	}

	dead := pw(t, "service-password")
	dead.Destroy()
	_, err := NewAuthenticator("ldap://example.com", WithServiceAccount("cn=admin", dead))
	if !errors.Is(err, ErrServicePasswordRequired) || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("destroyed password: err = %v", err)
	}
}

func TestWithServiceAccountTwiceDestroysTheReplacedPassword(t *testing.T) {
	first := pw(t, "first")
	second := pw(t, "second")
	auth, err := NewAuthenticator("ldap://example.com",
		WithServiceAccount("cn=admin", first),
		WithServiceAccount("cn=admin", second))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if first.IsAlive() {
		t.Fatal("the replaced service password is still alive")
	}
	if !second.IsAlive() {
		t.Fatal("the current service password was destroyed")
	}
	if err := auth.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if second.IsAlive() {
		t.Fatal("Close left the service password alive")
	}
}

func TestCloseDestroysServicePasswordAndRefusesFurtherUse(t *testing.T) {
	conn := &fakeConn{}
	service := pw(t, "service-password")
	auth, err := NewAuthenticator("ldap://example.com:389",
		WithUserDNTemplate("cn=%s,dc=example,dc=com"),
		WithServiceAccount("cn=admin,dc=example,dc=com", service),
		WithDialContext(func(context.Context) (ldapConn, error) { return conn, nil }))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	if err := auth.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if service.IsAlive() {
		t.Fatal("Close left the service password alive")
	}
	if err := auth.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := auth.Authenticate(context.Background(), "user", pw(t, "pass")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Authenticate after Close = %v, want ErrClosed", err)
	}
	if len(conn.binds) != 0 {
		t.Fatalf("bound %d times after Close", len(conn.binds))
	}
}
