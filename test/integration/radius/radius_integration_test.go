//go:build integration

package radius_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	radiuslib "github.com/jhahn/go-auth/pkg/radius"
)

const (
	testAddr    = "127.0.0.1:1812"
	testTLSAddr = "127.0.0.1:2083"
	testSecret  = "testing123"
)

func newAuthenticator(t *testing.T) *radiuslib.Authenticator {
	t.Helper()
	auth, err := radiuslib.NewAuthenticator(testAddr, testSecret)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	return auth
}

func newTLSAuthenticator(t *testing.T) *radiuslib.Authenticator {
	t.Helper()
	tlsCfg := loadTLSConfig(t)
	auth, err := radiuslib.NewAuthenticator(testTLSAddr, testSecret, radiuslib.WithTLSConfig(tlsCfg))
	if err != nil {
		t.Fatalf("failed to create TLS authenticator: %v", err)
	}
	return auth
}

func newEAPTLSAuthenticator(t *testing.T) *radiuslib.Authenticator {
	t.Helper()
	tlsCfg := loadTLSConfig(t)
	config := &radiuslib.EAPTLSConfig{
		TLSConfig:     tlsCfg,
		Identity:      "radius-client",
		OuterIdentity: "radius-client",
		FragmentSize:  1600,
	}
	auth, err := radiuslib.NewAuthenticator(testAddr, testSecret, radiuslib.WithEAPTLS(config))
	if err != nil {
		t.Fatalf("failed to create EAP-TLS authenticator: %v", err)
	}
	return auth
}

func loadTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("failed to resolve caller file path")
	}
	certDir := filepath.Join(filepath.Dir(filename), "..", "..", "..", "pkg", "radius", "testdata", "certs")
	caPEM, err := os.ReadFile(filepath.Join(certDir, "ca.pem"))
	if err != nil {
		t.Fatalf("failed to read CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to append CA cert")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "client.pem"), filepath.Join(certDir, "client.key"))
	if err != nil {
		t.Fatalf("failed to load client cert: %v", err)
	}
	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   "127.0.0.1",
	}
}

func withTimeout(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func TestAuthenticateSuccess(t *testing.T) {
	auth := newAuthenticator(t)

	ctx, cancel := withTimeout(t)
	defer cancel()

	if err := auth.Authenticate(ctx, "radiususer", "radiuspass"); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestAuthenticateRejectsWrongPassword(t *testing.T) {
	auth := newAuthenticator(t)

	ctx, cancel := withTimeout(t)
	defer cancel()

	err := auth.Authenticate(ctx, "radiususer", "wrongpass")
	if err == nil {
		t.Fatal("expected failure for wrong password")
	}
	if err != radiuslib.ErrRejected {
		t.Fatalf("expected ErrRejected, got %v", err)
	}
}

func TestAuthenticateRejectsUnknownUser(t *testing.T) {
	auth := newAuthenticator(t)

	ctx, cancel := withTimeout(t)
	defer cancel()

	err := auth.Authenticate(ctx, "unknown", "radiuspass")
	if err == nil {
		t.Fatal("expected failure for unknown user")
	}
	if err != radiuslib.ErrRejected {
		t.Fatalf("expected ErrRejected, got %v", err)
	}
}

func TestAuthenticateSuccessTLS(t *testing.T) {
	auth := newTLSAuthenticator(t)

	ctx, cancel := withTimeout(t)
	defer cancel()

	if err := auth.Authenticate(ctx, "radiususer", "radiuspass"); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestAuthenticateRejectsWrongPasswordTLS(t *testing.T) {
	auth := newTLSAuthenticator(t)

	ctx, cancel := withTimeout(t)
	defer cancel()

	err := auth.Authenticate(ctx, "radiususer", "wrongpass")
	if err == nil {
		t.Fatal("expected failure for wrong password")
	}
	if err != radiuslib.ErrRejected {
		t.Fatalf("expected ErrRejected, got %v", err)
	}
}

func TestAuthenticateRejectsUnknownUserTLS(t *testing.T) {
	auth := newTLSAuthenticator(t)

	ctx, cancel := withTimeout(t)
	defer cancel()

	err := auth.Authenticate(ctx, "unknown", "radiuspass")
	if err == nil {
		t.Fatal("expected failure for unknown user")
	}
	if err != radiuslib.ErrRejected {
		t.Fatalf("expected ErrRejected, got %v", err)
	}
}

func TestAuthenticateEAPTLSSuccess(t *testing.T) {
	auth := newEAPTLSAuthenticator(t)

	ctx, cancel := withTimeout(t)
	defer cancel()

	if err := auth.Authenticate(ctx, "radius-client", ""); err != nil {
		t.Fatalf("expected EAP-TLS success, got error: %v", err)
	}
}
