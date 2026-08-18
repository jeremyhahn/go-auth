package ldapauth

import (
	"context"
	"strings"
	"testing"

	secretpkg "github.com/jeremyhahn/go-auth/pkg/secret"
)

func TestAuthenticateWithProtectedServiceAccount(t *testing.T) {
	const password = "service-password"

	sealed, err := secretpkg.NewString(password)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sealed.Destroy()

	conn := &fakeConn{}
	auth, err := NewAuthenticator("ldap://example.com:389",
		WithUserDNTemplate("uid=%s,ou=people,dc=example,dc=com"),
		WithProtectedServiceAccount("cn=admin,dc=example,dc=com", sealed),
		WithDialContext(func(context.Context) (ldapConn, error) { return conn, nil }))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "bob", "pass"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if len(conn.binds) != 2 {
		t.Fatalf("expected two binds, got %d", len(conn.binds))
	}
	if conn.binds[0].dn != "cn=admin,dc=example,dc=com" {
		t.Fatalf("service bind DN = %q", conn.binds[0].dn)
	}
	// The password go-ldap was given has to be the real one: the point of the
	// protected path is to change where the secret lives, not what is sent.
	if conn.binds[0].password != password {
		t.Fatalf("service bind password = %q, want %q", conn.binds[0].password, password)
	}
	if conn.binds[1].dn != "uid=bob,ou=people,dc=example,dc=com" {
		t.Fatalf("user bind DN = %q", conn.binds[1].dn)
	}
}

// TestServiceAccountOptionSealsTheSecret checks the deprecated option stores
// the password in protected memory rather than in a string field.
func TestServiceAccountOptionSealsTheSecret(t *testing.T) {
	conn := &fakeConn{}
	auth, err := NewAuthenticator("ldap://example.com:389",
		WithUserDNTemplate("uid=%s,ou=people,dc=example,dc=com"),
		WithServiceAccount("cn=admin,dc=example,dc=com", "service-password"),
		WithDialContext(func(context.Context) (ldapConn, error) { return conn, nil }))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if auth.servicePassword == nil {
		t.Fatal("WithServiceAccount did not seal the password")
	}

	if err := auth.Authenticate(context.Background(), "bob", "pass"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if conn.binds[0].password != "service-password" {
		t.Fatalf("service bind password = %q", conn.binds[0].password)
	}
}

// TestServiceBindAfterSecretDestroyed proves the authenticator holds no
// plaintext copy of the service password: releasing the secret stops the
// service bind, and it stops it before any credential reaches the connection.
func TestServiceBindAfterSecretDestroyed(t *testing.T) {
	sealed, err := secretpkg.NewString("service-password")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}

	conn := &fakeConn{}
	auth, err := NewAuthenticator("ldap://example.com:389",
		WithUserDNTemplate("uid=%s,ou=people,dc=example,dc=com"),
		WithProtectedServiceAccount("cn=admin,dc=example,dc=com", sealed),
		WithDialContext(func(context.Context) (ldapConn, error) { return conn, nil }))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	sealed.Destroy()

	err = auth.Authenticate(context.Background(), "bob", "pass")
	if err == nil {
		t.Fatal("Authenticate succeeded after the service password was destroyed")
	}
	if !strings.Contains(err.Error(), "service bind failed") {
		t.Fatalf("error = %v, want a service bind failure", err)
	}
	if len(conn.binds) != 0 {
		t.Fatalf("bound %d times with a destroyed password", len(conn.binds))
	}
}

// TestServiceAccountWithEmptyPassword pins the compatibility of the deprecated
// option when it is given nothing to seal: the bind still happens, with an
// empty password, exactly as it did before the password moved into protected
// memory.
//
// Against a real server this never gets that far — go-ldap refuses an empty
// simple bind locally (ErrorEmptyPassword, "empty password not allowed by the
// client") unless AllowEmptyPassword is set, which Conn.Bind does not set. The
// behavior is observable only through an injected connection, which is exactly
// what this test uses and what a caller relying on it would have.
func TestServiceAccountWithEmptyPassword(t *testing.T) {
	conn := &fakeConn{}
	auth, err := NewAuthenticator("ldap://example.com:389",
		WithUserDNTemplate("uid=%s,ou=people,dc=example,dc=com"),
		WithServiceAccount("cn=admin,dc=example,dc=com", ""),
		WithDialContext(func(context.Context) (ldapConn, error) { return conn, nil }))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if auth.servicePassword != nil {
		t.Fatal("an empty password was sealed")
	}

	if err := auth.Authenticate(context.Background(), "bob", "pass"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if len(conn.binds) != 2 {
		t.Fatalf("expected two binds, got %d", len(conn.binds))
	}
	if conn.binds[0].dn != "cn=admin,dc=example,dc=com" {
		t.Fatalf("service bind DN = %q", conn.binds[0].dn)
	}
	if conn.binds[0].password != "" {
		t.Fatalf("service bind password = %q, want an empty one", conn.binds[0].password)
	}
}

// TestProtectedServiceAccountClearsTheEmptyPasswordState checks the options do
// not leak state into one another: a protected password set after an empty one
// is used as a protected password.
func TestProtectedServiceAccountClearsTheEmptyPasswordState(t *testing.T) {
	sealed, err := secretpkg.NewString("service-password")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sealed.Destroy()

	conn := &fakeConn{}
	auth, err := NewAuthenticator("ldap://example.com:389",
		WithUserDNTemplate("uid=%s,ou=people,dc=example,dc=com"),
		WithServiceAccount("cn=admin,dc=example,dc=com", ""),
		WithProtectedServiceAccount("cn=admin,dc=example,dc=com", sealed),
		WithDialContext(func(context.Context) (ldapConn, error) { return conn, nil }))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "bob", "pass"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if conn.binds[0].password != "service-password" {
		t.Fatalf("service bind password = %q", conn.binds[0].password)
	}

	// And the other way round: an empty password after a protected one goes
	// back to the legacy bind rather than reusing the secret.
	conn = &fakeConn{}
	auth, err = NewAuthenticator("ldap://example.com:389",
		WithUserDNTemplate("uid=%s,ou=people,dc=example,dc=com"),
		WithProtectedServiceAccount("cn=admin,dc=example,dc=com", sealed),
		WithServiceAccount("cn=admin,dc=example,dc=com", ""),
		WithDialContext(func(context.Context) (ldapConn, error) { return conn, nil }))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if err := auth.Authenticate(context.Background(), "bob", "pass"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if conn.binds[0].password != "" {
		t.Fatalf("service bind password = %q, want an empty one", conn.binds[0].password)
	}
}
