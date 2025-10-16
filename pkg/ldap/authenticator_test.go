package ldapauth

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeConn struct {
	binds    []bindCall
	startTLS bool
	startErr error
	bindErrs []error
}

type bindCall struct {
	dn, password string
}

func (f *fakeConn) Bind(username, password string) error {
	f.binds = append(f.binds, bindCall{username, password})
	if len(f.bindErrs) == 0 {
		return nil
	}
	err := f.bindErrs[0]
	f.bindErrs = f.bindErrs[1:]
	return err
}

func (f *fakeConn) StartTLS(_ *tls.Config) error {
	f.startTLS = true
	return f.startErr
}

func (f *fakeConn) Close() error { return nil }

func TestAuthenticateSuccess(t *testing.T) {
	conn := &fakeConn{}
	auth, err := NewAuthenticator("ldap://example.com:389", WithUserDNTemplate("cn=%s,dc=example,dc=com"), WithDialContext(func(ctx context.Context) (ldapConn, error) {
		return conn, nil
	}))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "alice", "password"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if len(conn.binds) != 1 {
		t.Fatalf("expected single bind, got %d", len(conn.binds))
	}
	if conn.binds[0].dn != "cn=alice,dc=example,dc=com" {
		t.Fatalf("unexpected bind DN %s", conn.binds[0].dn)
	}
	if conn.binds[0].password != "password" {
		t.Fatalf("unexpected bind password %s", conn.binds[0].password)
	}
}

func TestAuthenticateWithServiceAccount(t *testing.T) {
	conn := &fakeConn{}
	auth, err := NewAuthenticator("ldap://example.com:389",
		WithUserDNTemplate("uid=%s,ou=people,dc=example,dc=com"),
		WithServiceAccount("cn=admin,dc=example,dc=com", "secret"),
		WithDialContext(func(ctx context.Context) (ldapConn, error) { return conn, nil }))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "bob", "pass"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if len(conn.binds) != 2 {
		t.Fatalf("expected two binds, got %d", len(conn.binds))
	}
	if conn.binds[0].dn != "cn=admin,dc=example,dc=com" {
		t.Fatalf("service bind mismatch: %v", conn.binds[0])
	}
	if conn.binds[1].dn != "uid=bob,ou=people,dc=example,dc=com" {
		t.Fatalf("user bind mismatch: %v", conn.binds[1])
	}
}

func TestAuthenticateStartTLS(t *testing.T) {
	conn := &fakeConn{}
	auth, err := NewAuthenticator("ldap://example.com:389",
		WithUserDNTemplate("cn=%s,dc=example,dc=com"),
		WithStartTLS(),
		WithDialContext(func(ctx context.Context) (ldapConn, error) { return conn, nil }))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "alice", "pass"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if !conn.startTLS {
		t.Fatalf("expected StartTLS to be invoked")
	}
}

func TestDialError(t *testing.T) {
	auth, err := NewAuthenticator("ldap://example.com:389", WithUserDNTemplate("cn=%s,dc=example,dc=com"),
		WithDialContext(func(ctx context.Context) (ldapConn, error) { return nil, errors.New("dial failed") }))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	err = auth.Authenticate(context.Background(), "user", "pass")
	if err == nil || !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("expected dial failed, got %v", err)
	}
}

func TestBindError(t *testing.T) {
    conn := &fakeConn{bindErrs: []error{errors.New("bad creds")}}
	auth, err := NewAuthenticator("ldap://example.com:389", WithUserDNTemplate("cn=%s,dc=example,dc=com"), WithDialContext(func(ctx context.Context) (ldapConn, error) { return conn, nil }))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	err = auth.Authenticate(context.Background(), "user", "pass")
	if err == nil || !strings.Contains(err.Error(), "user bind failed") {
		t.Fatalf("expected user bind failure, got %v", err)
	}
}

func TestInputValidation(t *testing.T) {
	auth, err := NewAuthenticator("ldap://example.com:389")
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "user", "pass"); !errors.Is(err, ErrMissingTemplate) {
		t.Fatalf("expected ErrMissingTemplate, got %v", err)
	}

	auth.userDNTemplate = "cn=%s,dc=example,dc=com"
	if err := auth.Authenticate(context.Background(), "", "pass"); err == nil {
		t.Fatalf("expected error for empty username")
	}

	if err := auth.Authenticate(context.Background(), "user", ""); err == nil {
		t.Fatalf("expected error for empty password")
	}
}

func TestContextCancellation(t *testing.T) {
	dialInvoked := false
	auth, err := NewAuthenticator("ldap://example.com:389", WithUserDNTemplate("cn=%s,dc=example,dc=com"), WithDialContext(func(ctx context.Context) (ldapConn, error) {
		dialInvoked = true
		return &fakeConn{}, nil
	}))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := auth.Authenticate(ctx, "user", "pass"); err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if dialInvoked {
		t.Fatalf("dial should not be invoked after cancellation")
	}
}

func TestTimeoutDialer(t *testing.T) {
	auth, err := NewAuthenticator("ldap://example.com:389", WithUserDNTemplate("cn=%s,dc=example,dc=com"), WithTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	if auth.timeout != 10*time.Second {
		t.Fatalf("expected timeout to be set")
	}
}

func TestInvalidURL(t *testing.T) {
	if _, err := NewAuthenticator("", WithUserDNTemplate("cn=%s")); err == nil {
		t.Fatalf("expected error for empty url")
	}
}
