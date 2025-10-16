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
	"testing"
	"time"

	ldap "github.com/vjeantet/ldapserver"

	ldapauth "github.com/jhahn/go-auth/pkg/ldap"
)

type credStore struct {
	creds map[string]string
}

func (c credStore) handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	req := m.GetBindRequest()
	dn := string(req.Name())
	pw := string(req.AuthenticationSimple())
	resp := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	if expected, ok := c.creds[dn]; !ok || expected != pw {
		resp.SetResultCode(ldap.LDAPResultInvalidCredentials)
		resp.SetDiagnosticMessage("invalid credentials")
	}
	w.Write(resp)
}

func startLDAPServer(t *testing.T, creds map[string]string, tlsConfig *tls.Config) (string, func()) {
	t.Helper()

	server := ldap.NewServer()
	mux := ldap.NewRouteMux()
	mux.Bind(credStore{creds: creds}.handleBind)
	server.Handle(mux)

	done := make(chan error, 1)
	var option func(*ldap.Server)
	if tlsConfig != nil {
		option = func(s *ldap.Server) {
			s.Listener = tls.NewListener(s.Listener, tlsConfig)
		}
	}

	go func() {
		if option != nil {
			done <- server.ListenAndServe("127.0.0.1:0", option)
		} else {
			done <- server.ListenAndServe("127.0.0.1:0")
		}
	}()

	// Wait for listener to be ready
	deadline := time.After(2 * time.Second)
	for server.Listener == nil {
		select {
		case <-deadline:
			t.Fatalf("LDAP server failed to start")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	addr := server.Listener.Addr().String()

	cleanup := func() {
		server.Stop()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}

	return addr, cleanup
}

func TestLDAPAuthenticateSuccess(t *testing.T) {
	addr, cleanup := startLDAPServer(t, map[string]string{
		"cn=admin,dc=example,dc=com": "secret",
		"cn=alice,dc=example,dc=com": "password",
	}, nil)
	defer cleanup()

	auth, err := ldapauth.NewAuthenticator("ldap://"+addr,
		ldapauth.WithUserDNTemplate("cn=%s,dc=example,dc=com"),
		ldapauth.WithServiceAccount("cn=admin,dc=example,dc=com", "secret"))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := auth.Authenticate(ctx, "alice", "password"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestLDAPAuthenticateWrongPassword(t *testing.T) {
	addr, cleanup := startLDAPServer(t, map[string]string{
		"cn=alice,dc=example,dc=com": "password",
	}, nil)
	defer cleanup()

	auth, err := ldapauth.NewAuthenticator("ldap://"+addr,
		ldapauth.WithUserDNTemplate("cn=%s,dc=example,dc=com"))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "alice", "wrong"); err == nil {
		t.Fatal("expected failure for wrong password")
	}
}

func TestLDAPAuthenticateLDAPS(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse key pair: %v", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{tlsCert}}

	addr, cleanup := startLDAPServer(t, map[string]string{
		"cn=bob,dc=example,dc=com": "secret",
	}, tlsConfig)
	defer cleanup()

	clientTLS := &tls.Config{InsecureSkipVerify: true}
	auth, err := ldapauth.NewAuthenticator("ldaps://"+addr,
		ldapauth.WithUserDNTemplate("cn=%s,dc=example,dc=com"),
		ldapauth.WithTLSConfig(clientTLS))
	if err != nil {
		t.Fatalf("NewAuthenticator error: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "bob", "secret"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
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
