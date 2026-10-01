//go:build integration

package ldap_integration_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	ldapauth "github.com/jeremyhahn/go-auth/pkg/ldap"
)

func TestLDAPAuthenticateSuccess(t *testing.T) {
	srv := startStubServer(t, map[string]string{
		"cn=admin,dc=example,dc=com": "secret",
		"cn=alice,dc=example,dc=com": "password",
	})

	auth, err := ldapauth.NewAuthenticator("ldap://"+srv.Addr(),
		ldapauth.WithUserDNTemplate("cn=%s,dc=example,dc=com"),
		ldapauth.WithServiceAccount("cn=admin,dc=example,dc=com", sealed(t, "secret")))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := auth.Authenticate(ctx, "alice", sealed(t, "password")); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	assertBinds(t, srv, []bindRecord{
		{dn: "cn=admin,dc=example,dc=com", success: true},
		{dn: "cn=alice,dc=example,dc=com", success: true},
	})
}

func TestLDAPAuthenticateWrongPassword(t *testing.T) {
	srv := startStubServer(t, map[string]string{
		"cn=alice,dc=example,dc=com": "password",
	})

	auth, err := ldapauth.NewAuthenticator("ldap://"+srv.Addr(),
		ldapauth.WithUserDNTemplate("cn=%s,dc=example,dc=com"))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	if err := auth.Authenticate(context.Background(), "alice", sealed(t, "wrong")); err == nil {
		t.Fatal("expected failure for wrong password")
	}

	assertBinds(t, srv, []bindRecord{
		{dn: "cn=alice,dc=example,dc=com", success: false},
	})
}

func TestLDAPAuthenticateServiceBindFailure(t *testing.T) {
	srv := startStubServer(t, map[string]string{
		"cn=admin,dc=example,dc=com": "secret",
		"cn=alice,dc=example,dc=com": "password",
	})

	auth, err := ldapauth.NewAuthenticator("ldap://"+srv.Addr(),
		ldapauth.WithUserDNTemplate("cn=%s,dc=example,dc=com"),
		ldapauth.WithServiceAccount("cn=admin,dc=example,dc=com", sealed(t, "not-the-secret")))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	if err := auth.Authenticate(context.Background(), "alice", sealed(t, "password")); err == nil {
		t.Fatal("expected failure when the service bind is rejected")
	}

	// The user bind must never be attempted once the service bind fails.
	assertBinds(t, srv, []bindRecord{
		{dn: "cn=admin,dc=example,dc=com", success: false},
	})
}

func TestLDAPAuthenticateLDAPS(t *testing.T) {
	srv := startStubServer(t, map[string]string{
		"cn=bob,dc=example,dc=com": "secret",
	}, withLDAPS(serverTLSConfig(t)))

	clientTLS := &tls.Config{InsecureSkipVerify: true}
	auth, err := ldapauth.NewAuthenticator("ldaps://"+srv.Addr(),
		ldapauth.WithUserDNTemplate("cn=%s,dc=example,dc=com"),
		ldapauth.WithTLSConfig(clientTLS))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	if err := auth.Authenticate(context.Background(), "bob", sealed(t, "secret")); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	assertBinds(t, srv, []bindRecord{
		{dn: "cn=bob,dc=example,dc=com", success: true, tls: true},
	})
}

func TestLDAPAuthenticateStartTLS(t *testing.T) {
	srv := startStubServer(t, map[string]string{
		"cn=admin,dc=example,dc=com": "secret",
		"cn=carol,dc=example,dc=com": "secret",
	}, withStartTLS(serverTLSConfig(t)))

	clientTLS := &tls.Config{InsecureSkipVerify: true}
	auth, err := ldapauth.NewAuthenticator("ldap://"+srv.Addr(),
		ldapauth.WithUserDNTemplate("cn=%s,dc=example,dc=com"),
		ldapauth.WithServiceAccount("cn=admin,dc=example,dc=com", sealed(t, "secret")),
		ldapauth.WithStartTLS(),
		ldapauth.WithTLSConfig(clientTLS))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	if err := auth.Authenticate(context.Background(), "carol", sealed(t, "secret")); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	// Both binds must travel over the negotiated TLS session, never in clear.
	assertBinds(t, srv, []bindRecord{
		{dn: "cn=admin,dc=example,dc=com", success: true, tls: true},
		{dn: "cn=carol,dc=example,dc=com", success: true, tls: true},
	})
}

func TestLDAPAuthenticateStartTLSRefused(t *testing.T) {
	// The server offers no StartTLS: the client must fail rather than fall
	// back to binding in clear.
	srv := startStubServer(t, map[string]string{
		"cn=carol,dc=example,dc=com": "secret",
	})

	auth, err := ldapauth.NewAuthenticator("ldap://"+srv.Addr(),
		ldapauth.WithUserDNTemplate("cn=%s,dc=example,dc=com"),
		ldapauth.WithStartTLS(),
		ldapauth.WithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	if err := auth.Authenticate(context.Background(), "carol", sealed(t, "secret")); err == nil {
		t.Fatal("expected failure when the server refuses StartTLS")
	}

	assertBinds(t, srv, nil)
}

// TestLDAPSearch exercises the search path against the fixture. pkg/ldap's
// Authenticator binds by DN template and never searches, so this drives the
// go-ldap client (the library pkg/ldap is built on) directly: bind as the
// service account, then search by filter and scope as a directory lookup
// would, asserting both the entries returned and a successful SearchResultDone.
func TestLDAPSearch(t *testing.T) {
	srv := startStubServer(t, map[string]string{
		"cn=admin,dc=example,dc=com": "secret",
	}, withEntries(
		stubEntry{dn: "dc=example,dc=com", attrs: map[string][]string{
			"objectClass": {"domain"}, "dc": {"example"},
		}},
		stubEntry{dn: "uid=alice,ou=people,dc=example,dc=com", attrs: map[string][]string{
			"objectClass": {"inetOrgPerson"}, "uid": {"alice"}, "mail": {"alice@example.com"}, "cn": {"Alice"},
		}},
		stubEntry{dn: "uid=bob,ou=people,dc=example,dc=com", attrs: map[string][]string{
			"objectClass": {"inetOrgPerson"}, "uid": {"bob"}, "mail": {"bob@example.com"}, "cn": {"Bob"},
		}},
		stubEntry{dn: "ou=people,dc=example,dc=com", attrs: map[string][]string{
			"objectClass": {"organizationalUnit"}, "ou": {"people"},
		}},
	))

	conn, err := goldap.DialURL("ldap://" + srv.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("service bind: %v", err)
	}

	tests := []struct {
		name    string
		base    string
		scope   int
		filter  string
		attrs   []string
		wantDNs []string
		check   func(t *testing.T, entries []*goldap.Entry)
	}{
		{
			name:    "subtree equality returns requested attributes only",
			base:    "dc=example,dc=com",
			scope:   goldap.ScopeWholeSubtree,
			filter:  "(uid=alice)",
			attrs:   []string{"mail"},
			wantDNs: []string{"uid=alice,ou=people,dc=example,dc=com"},
			check: func(t *testing.T, entries []*goldap.Entry) {
				if got := entries[0].GetAttributeValue("mail"); got != "alice@example.com" {
					t.Fatalf("mail = %q, want alice@example.com", got)
				}
				if len(entries[0].Attributes) != 1 {
					t.Fatalf("attributes = %d, want only the requested mail", len(entries[0].Attributes))
				}
			},
		},
		{
			name:    "single level excludes base and deeper entries",
			base:    "dc=example,dc=com",
			scope:   goldap.ScopeSingleLevel,
			filter:  "(objectClass=*)",
			wantDNs: []string{"ou=people,dc=example,dc=com"},
		},
		{
			name:    "subtree presence under an ou",
			base:    "ou=people,dc=example,dc=com",
			scope:   goldap.ScopeWholeSubtree,
			filter:  "(mail=*)",
			wantDNs: []string{"uid=alice,ou=people,dc=example,dc=com", "uid=bob,ou=people,dc=example,dc=com"},
			check: func(t *testing.T, entries []*goldap.Entry) {
				if got := entries[1].GetAttributeValue("cn"); got != "Bob" {
					t.Fatalf("cn = %q, want Bob (all attributes when none requested)", got)
				}
			},
		},
		{
			name:    "base object",
			base:    "uid=bob,ou=people,dc=example,dc=com",
			scope:   goldap.ScopeBaseObject,
			filter:  "(objectClass=inetOrgPerson)",
			wantDNs: []string{"uid=bob,ou=people,dc=example,dc=com"},
		},
		{
			name:    "no match completes with zero entries",
			base:    "dc=example,dc=com",
			scope:   goldap.ScopeWholeSubtree,
			filter:  "(uid=mallory)",
			wantDNs: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := conn.Search(goldap.NewSearchRequest(
				tc.base, tc.scope, goldap.NeverDerefAliases, 0, 0, false,
				tc.filter, tc.attrs, nil))
			if err != nil {
				t.Fatalf("search: %v", err)
			}
			var gotDNs []string
			for _, e := range res.Entries {
				gotDNs = append(gotDNs, e.DN)
			}
			if !slices.Equal(gotDNs, tc.wantDNs) {
				t.Fatalf("DNs = %v, want %v", gotDNs, tc.wantDNs)
			}
			if tc.check != nil {
				tc.check(t, res.Entries)
			}
		})
	}
}

// TestLDAPStubShutdownWithLiveClient covers the fixture's own shutdown with a
// client still connected mid-session — the case that raced in the previous
// fixture (vjeantet/ldapserver, "send on closed channel"). Close must return
// only after every server goroutine has exited, without panicking.
func TestLDAPStubShutdownWithLiveClient(t *testing.T) {
	srv := startStubServer(t, map[string]string{
		"cn=alice,dc=example,dc=com": "password",
	})

	conns := make([]net.Conn, 0, 4)
	for range 4 {
		conn, err := net.Dial("tcp", srv.Addr())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conns = append(conns, conn)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	// One complete bind round-trip proves a session is live and being served
	// at the moment the server is closed.
	auth, err := ldapauth.NewAuthenticator("ldap://"+srv.Addr(),
		ldapauth.WithUserDNTemplate("cn=%s,dc=example,dc=com"))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })
	if err := auth.Authenticate(context.Background(), "alice", sealed(t, "password")); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	srv.Close()

	// Every idle client connection must have been closed by the server.
	for _, c := range conns {
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("expected the server to close idle client connections")
		}
	}

	// Close is idempotent; the t.Cleanup registration calls it again.
	srv.Close()
}

func assertBinds(t *testing.T, srv *stubServer, want []bindRecord) {
	t.Helper()
	got := srv.Binds()
	if len(got) != len(want) {
		t.Fatalf("binds = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bind %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func serverTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	certPEM, keyPEM := generateSelfSignedCert(t)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse key pair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}

func generateSelfSignedCert(t *testing.T) ([]byte, []byte) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}
