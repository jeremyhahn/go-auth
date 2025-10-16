package api

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type stubHandler struct {
	err      error
	calls    int
	username string
	password string
	otp      string
}

func (s *stubHandler) Authenticate(ctx context.Context, username, password, otp string) error {
	s.calls++
	s.username = username
	s.password = password
	s.otp = otp
	return s.err
}

func TestLoginSuccessFirstBackend(t *testing.T) {
	first := &stubHandler{err: nil}
	second := &stubHandler{err: errors.New("should not be called")}

	svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: first}, {Name: BackendRADIUS, Handler: second}}})
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	req := LoginRequest{Username: "user", Password: "pass"}
	if err := svc.Login(context.Background(), req); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if first.calls != 1 {
		t.Fatalf("expected first backend to be called once, got %d", first.calls)
	}
	if second.calls != 0 {
		t.Fatalf("expected second backend not to be called, got %d", second.calls)
	}
}

func TestLoginFallbackOnFailure(t *testing.T) {
	first := &stubHandler{err: errors.New("failure")}
	second := &stubHandler{}
	svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: first}, {Name: BackendRADIUS, Handler: second}}})
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	if err := svc.Login(context.Background(), LoginRequest{Username: "user", Password: "pass"}); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if first.calls != 1 || second.calls != 1 {
		t.Fatalf("unexpected call counts: first=%d second=%d", first.calls, second.calls)
	}
}

func TestLoginPreferredBackend(t *testing.T) {
	first := &stubHandler{err: errors.New("failure")}
	second := &stubHandler{}
	svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: first}, {Name: BackendRADIUS, Handler: second}}})
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	if err := svc.Login(context.Background(), LoginRequest{Backend: BackendRADIUS, Username: "user", Password: "pass"}); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if first.calls != 0 || second.calls != 1 {
		t.Fatalf("unexpected call counts: first=%d second=%d", first.calls, second.calls)
	}
}

func TestLoginUnknownBackend(t *testing.T) {
	svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: &stubHandler{}}}})
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	err = svc.Login(context.Background(), LoginRequest{Backend: BackendRADIUS, Username: "user", Password: "pass"})
	if !errors.Is(err, ErrBackendNotFound) {
		t.Fatalf("expected ErrBackendNotFound, got %v", err)
	}
}

func TestLoginAggregatesErrors(t *testing.T) {
	first := &stubHandler{err: errors.New("failure one")}
	second := &stubHandler{err: errors.New("failure two")}
	svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: first}, {Name: BackendRADIUS, Handler: second}}})
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	err = svc.Login(context.Background(), LoginRequest{Username: "user", Password: "pass"})
	if err == nil {
		t.Fatalf("expected aggregated error")
	}
	for _, backend := range []BackendName{BackendPAM, BackendRADIUS} {
		if !strings.Contains(err.Error(), string(backend)) {
			t.Fatalf("expected error to contain backend %s", backend)
		}
	}
}

func TestLoginNoBackends(t *testing.T) {
	svc := &Service{}
	if err := svc.Login(context.Background(), LoginRequest{Username: "user", Password: "pass"}); !errors.Is(err, ErrNoBackends) {
		t.Fatalf("expected ErrNoBackends, got %v", err)
	}
}

func TestLoginContextCancellation(t *testing.T) {
	handler := &stubHandler{err: context.DeadlineExceeded}
	svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: handler}}})
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := svc.Login(ctx, LoginRequest{Username: "user", Password: "pass"}); err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestOTPForwarded(t *testing.T) {
	handler := &stubHandler{err: errors.New("failure")}
	svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: handler}}})
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	_ = svc.Login(context.Background(), LoginRequest{Username: "user", Password: "pass", OTP: "123456"})
	if handler.otp != "123456" {
		t.Fatalf("expected OTP to be forwarded, got %s", handler.otp)
	}
}

func TestValidationErrors(t *testing.T) {
	svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: &stubHandler{}}}})
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	if err := svc.Login(context.Background(), LoginRequest{}); !errors.Is(err, ErrMissingCredentials) {
		t.Fatalf("expected ErrMissingCredentials, got %v", err)
	}
}

func TestPAMWrapper(t *testing.T) {
	fake := &fakePasswordAuthenticator{}
	handler := PAM(fake)
	if err := handler.Authenticate(context.Background(), "user", "secret", "otp"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.username != "user" || fake.password != "secret" {
		t.Fatalf("wrapper did not forward credentials correctly: %+v", fake)
	}
}

func TestPasswordFallbackToOTP(t *testing.T) {
	fake := &fakePasswordAuthenticator{}
	handler := RADIUS(fake)
	if err := handler.Authenticate(context.Background(), "user", "", "otp"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.password != "otp" {
		t.Fatalf("expected OTP to be used when password empty, got %s", fake.password)
	}
}

func TestLDAPWrapper(t *testing.T) {
	fake := &fakePasswordAuthenticator{}
	handler := LDAP(fake)
	if err := handler.Authenticate(context.Background(), "user", "secret", "otp"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.username != "user" || fake.password != "secret" {
		t.Fatalf("wrapper did not forward credentials correctly: %+v", fake)
	}
}

func TestPKCS11Wrapper(t *testing.T) {
	fake := &fakePINAuthenticator{}
	handler := PKCS11(fake)
	if err := handler.Authenticate(context.Background(), "", "1234", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.pin != "1234" {
		t.Fatalf("expected pin to be forwarded, got %s", fake.pin)
	}
}

func TestPKCS11WrapperFallsBackToOTP(t *testing.T) {
	fake := &fakePINAuthenticator{}
	handler := PKCS11(fake)
	if err := handler.Authenticate(context.Background(), "", "", "5678"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.pin != "5678" {
		t.Fatalf("expected otp fallback, got %s", fake.pin)
	}
}

func TestPKCS11WrapperMissingSecret(t *testing.T) {
	if err := PKCS11(&fakePINAuthenticator{}).Authenticate(context.Background(), "", "", ""); !errors.Is(err, ErrMissingPIN) {
		t.Fatalf("expected ErrMissingPIN, got %v", err)
	}
}

func TestYubiKeyWrapper(t *testing.T) {
	fake := &fakeOTPAuthenticator{}
	handler := YubiKey(fake)
	if err := handler.Authenticate(context.Background(), "", "", "abcdef"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.otp != "abcdef" {
		t.Fatalf("expected otp forwarded, got %s", fake.otp)
	}
}

func TestYubiKeyWrapperMissingOTP(t *testing.T) {
	if err := YubiKey(&fakeOTPAuthenticator{}).Authenticate(context.Background(), "", "", ""); !errors.Is(err, ErrMissingOTP) {
		t.Fatalf("expected ErrMissingOTP, got %v", err)
	}
}

func TestTPM2Wrapper(t *testing.T) {
	fake := &fakePINAuthenticator{}
	handler := TPM2(fake)
	if err := handler.Authenticate(context.Background(), "", "tpm-password", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.pin != "tpm-password" {
		t.Fatalf("expected password to be forwarded, got %s", fake.pin)
	}
}

func TestTPM2WrapperFallsBackToOTP(t *testing.T) {
	fake := &fakePINAuthenticator{}
	handler := TPM2(fake)
	if err := handler.Authenticate(context.Background(), "", "", "tpm-otp"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.pin != "tpm-otp" {
		t.Fatalf("expected otp fallback, got %s", fake.pin)
	}
}

func TestTPM2WrapperMissingSecret(t *testing.T) {
	if err := TPM2(&fakePINAuthenticator{}).Authenticate(context.Background(), "", "", ""); !errors.Is(err, ErrMissingPIN) {
		t.Fatalf("expected ErrMissingPIN, got %v", err)
	}
}

func TestOTPWrapper(t *testing.T) {
	fake := &fakeOTPAuthenticator{}
	handler := OTP(fake)
	if err := handler.Authenticate(context.Background(), "", "", "123456"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.otp != "123456" {
		t.Fatalf("expected otp forwarded, got %s", fake.otp)
	}
}

func TestOTPWrapperFallsBackToPassword(t *testing.T) {
	fake := &fakeOTPAuthenticator{}
	handler := OTP(fake)
	if err := handler.Authenticate(context.Background(), "", "654321", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.otp != "654321" {
		t.Fatalf("expected password to be used when OTP empty, got %s", fake.otp)
	}
}

func TestOTPWrapperMissingCode(t *testing.T) {
	if err := OTP(&fakeOTPAuthenticator{}).Authenticate(context.Background(), "", "", ""); !errors.Is(err, ErrMissingOTP) {
		t.Fatalf("expected ErrMissingOTP, got %v", err)
	}
}

func TestOTPWrapperIgnoresUsername(t *testing.T) {
	fake := &fakeOTPAuthenticator{}
	handler := OTP(fake)
	if err := handler.Authenticate(context.Background(), "user123", "", "999888"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.otp != "999888" {
		t.Fatalf("expected otp forwarded, got %s", fake.otp)
	}
}

type fakePasswordAuthenticator struct {
	username string
	password string
}

func (f *fakePasswordAuthenticator) Authenticate(ctx context.Context, username, password string) error {
	f.username = username
	f.password = password
	return nil
}

type fakePINAuthenticator struct {
	pin string
}

func (f *fakePINAuthenticator) Authenticate(ctx context.Context, pin string) error {
	f.pin = pin
	return nil
}

type fakeOTPAuthenticator struct {
	otp string
}

func (f *fakeOTPAuthenticator) Authenticate(ctx context.Context, otp string) error {
	f.otp = otp
	return nil
}
