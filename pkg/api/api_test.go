package api

import (
	"context"
	"errors"
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// sealed returns s in an enclave, or nil for the empty string, which is the
// "nothing supplied" case. The cleanup is a no-op for an enclave Login has
// already destroyed.
func sealed(t *testing.T, s string) *enclave.MemoryEnclave {
	t.Helper()
	if s == "" {
		return nil
	}
	e, err := enclave.NewMemoryEnclaveFromString(s)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveFromString: %v", err)
	}
	t.Cleanup(e.Destroy)
	return e
}

// reveal copies an enclave's material out for an assertion, or "" when there
// is none. Test-only: production code never does this.
func reveal(e *enclave.MemoryEnclave) string {
	if !e.IsAlive() {
		return ""
	}
	s, err := e.OpenString()
	if err != nil {
		return ""
	}
	return s
}

type stubHandler struct {
	err      error
	calls    int
	username string
	password string
	otp      string
	// aliveDuringCall records whether the password was still alive when the
	// handler ran: Login may only destroy it once the attempt completes.
	aliveDuringCall bool
}

func (s *stubHandler) Authenticate(ctx context.Context, username string, password, otp *enclave.MemoryEnclave) error {
	s.calls++
	s.username = username
	s.password = reveal(password)
	s.otp = reveal(otp)
	s.aliveDuringCall = password.IsAlive()
	return s.err
}

func TestLoginSuccessFirstBackend(t *testing.T) {
	first := &stubHandler{err: nil}
	second := &stubHandler{err: errors.New("should not be called")}

	svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: first}, {Name: BackendRADIUS, Handler: second}}})
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	req := LoginRequest{Username: "user", Password: sealed(t, "pass")}
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

	if err := svc.Login(context.Background(), LoginRequest{Username: "user", Password: sealed(t, "pass")}); err != nil {
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

	if err := svc.Login(context.Background(), LoginRequest{Backend: BackendRADIUS, Username: "user", Password: sealed(t, "pass")}); err != nil {
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

	err = svc.Login(context.Background(), LoginRequest{Backend: BackendRADIUS, Username: "user", Password: sealed(t, "pass")})
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

	err = svc.Login(context.Background(), LoginRequest{Username: "user", Password: sealed(t, "pass")})
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
	if err := svc.Login(context.Background(), LoginRequest{Username: "user", Password: sealed(t, "pass")}); !errors.Is(err, ErrNoBackends) {
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

	if err := svc.Login(ctx, LoginRequest{Username: "user", Password: sealed(t, "pass")}); err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestOTPForwarded(t *testing.T) {
	handler := &stubHandler{err: errors.New("failure")}
	svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: handler}}})
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	_ = svc.Login(context.Background(), LoginRequest{Username: "user", Password: sealed(t, "pass"), OTP: sealed(t, "123456")})
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
	if err := handler.Authenticate(context.Background(), "user", sealed(t, "secret"), sealed(t, "otp")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.username != "user" || fake.password != "secret" {
		t.Fatalf("wrapper did not forward credentials correctly: %+v", fake)
	}
}

func TestPasswordFallbackToOTP(t *testing.T) {
	fake := &fakePasswordAuthenticator{}
	handler := RADIUS(fake)
	if err := handler.Authenticate(context.Background(), "user", nil, sealed(t, "otp")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.password != "otp" {
		t.Fatalf("expected OTP to be used when password empty, got %s", fake.password)
	}
}

func TestLDAPWrapper(t *testing.T) {
	fake := &fakePasswordAuthenticator{}
	handler := LDAP(fake)
	if err := handler.Authenticate(context.Background(), "user", sealed(t, "secret"), sealed(t, "otp")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.username != "user" || fake.password != "secret" {
		t.Fatalf("wrapper did not forward credentials correctly: %+v", fake)
	}
}

func TestPKCS11Wrapper(t *testing.T) {
	fake := &fakePINAuthenticator{}
	handler := PKCS11(fake)
	if err := handler.Authenticate(context.Background(), "", sealed(t, "1234"), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.pin != "1234" {
		t.Fatalf("expected pin to be forwarded, got %s", fake.pin)
	}
}

func TestPKCS11WrapperFallsBackToOTP(t *testing.T) {
	fake := &fakePINAuthenticator{}
	handler := PKCS11(fake)
	if err := handler.Authenticate(context.Background(), "", nil, sealed(t, "5678")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.pin != "5678" {
		t.Fatalf("expected otp fallback, got %s", fake.pin)
	}
}

func TestPKCS11WrapperMissingSecret(t *testing.T) {
	if err := PKCS11(&fakePINAuthenticator{}).Authenticate(context.Background(), "", nil, nil); !errors.Is(err, ErrMissingPIN) {
		t.Fatalf("expected ErrMissingPIN, got %v", err)
	}
}

func TestYubiKeyWrapper(t *testing.T) {
	fake := &fakeOTPAuthenticator{}
	handler := YubiKey(fake)
	if err := handler.Authenticate(context.Background(), "", nil, sealed(t, "abcdef")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.otp != "abcdef" {
		t.Fatalf("expected otp forwarded, got %s", fake.otp)
	}
}

func TestYubiKeyWrapperMissingOTP(t *testing.T) {
	if err := YubiKey(&fakeOTPAuthenticator{}).Authenticate(context.Background(), "", nil, nil); !errors.Is(err, ErrMissingOTP) {
		t.Fatalf("expected ErrMissingOTP, got %v", err)
	}
}

func TestTPM2Wrapper(t *testing.T) {
	fake := &fakePINAuthenticator{}
	handler := TPM2(fake)
	if err := handler.Authenticate(context.Background(), "", sealed(t, "tpm-password"), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.pin != "tpm-password" {
		t.Fatalf("expected password to be forwarded, got %s", fake.pin)
	}
}

func TestTPM2WrapperFallsBackToOTP(t *testing.T) {
	fake := &fakePINAuthenticator{}
	handler := TPM2(fake)
	if err := handler.Authenticate(context.Background(), "", nil, sealed(t, "tpm-otp")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.pin != "tpm-otp" {
		t.Fatalf("expected otp fallback, got %s", fake.pin)
	}
}

func TestTPM2WrapperMissingSecret(t *testing.T) {
	if err := TPM2(&fakePINAuthenticator{}).Authenticate(context.Background(), "", nil, nil); !errors.Is(err, ErrMissingPIN) {
		t.Fatalf("expected ErrMissingPIN, got %v", err)
	}
}

func TestOTPWrapper(t *testing.T) {
	fake := &fakeOTPAuthenticator{}
	handler := OTP(fake)
	if err := handler.Authenticate(context.Background(), "", nil, sealed(t, "123456")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.otp != "123456" {
		t.Fatalf("expected otp forwarded, got %s", fake.otp)
	}
}

func TestOTPWrapperFallsBackToPassword(t *testing.T) {
	fake := &fakeOTPAuthenticator{}
	handler := OTP(fake)
	if err := handler.Authenticate(context.Background(), "", sealed(t, "654321"), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.otp != "654321" {
		t.Fatalf("expected password to be used when OTP empty, got %s", fake.otp)
	}
}

func TestOTPWrapperMissingCode(t *testing.T) {
	if err := OTP(&fakeOTPAuthenticator{}).Authenticate(context.Background(), "", nil, nil); !errors.Is(err, ErrMissingOTP) {
		t.Fatalf("expected ErrMissingOTP, got %v", err)
	}
}

func TestOTPWrapperIgnoresUsername(t *testing.T) {
	fake := &fakeOTPAuthenticator{}
	handler := OTP(fake)
	if err := handler.Authenticate(context.Background(), "user123", nil, sealed(t, "999888")); err != nil {
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

func (f *fakePasswordAuthenticator) Authenticate(ctx context.Context, username string, password *enclave.MemoryEnclave) error {
	f.username = username
	f.password = reveal(password)
	return nil
}

type fakePINAuthenticator struct {
	pin string
}

func (f *fakePINAuthenticator) Authenticate(ctx context.Context, pin *enclave.MemoryEnclave) error {
	f.pin = reveal(pin)
	return nil
}

type fakeOTPAuthenticator struct {
	otp string
}

func (f *fakeOTPAuthenticator) Authenticate(ctx context.Context, otp *enclave.MemoryEnclave) error {
	f.otp = reveal(otp)
	return nil
}

// loginOutcomes drives Login down every return path it has. Each case builds
// its own service and request so the enclaves are fresh.
func loginOutcomes() map[string]func(t *testing.T, req LoginRequest) (*Service, LoginRequest, context.Context) {
	ok := func(t *testing.T) *Service {
		svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: &stubHandler{}}}})
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		return svc
	}
	failing := func(t *testing.T) *Service {
		svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: &stubHandler{err: errors.New("no")}}}})
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		return svc
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	return map[string]func(t *testing.T, req LoginRequest) (*Service, LoginRequest, context.Context){
		"success": func(t *testing.T, req LoginRequest) (*Service, LoginRequest, context.Context) {
			return ok(t), req, context.Background()
		},
		"every backend fails": func(t *testing.T, req LoginRequest) (*Service, LoginRequest, context.Context) {
			return failing(t), req, context.Background()
		},
		"nil service": func(t *testing.T, req LoginRequest) (*Service, LoginRequest, context.Context) {
			return nil, req, context.Background()
		},
		"no backends": func(t *testing.T, req LoginRequest) (*Service, LoginRequest, context.Context) {
			return &Service{}, req, context.Background()
		},
		"missing username": func(t *testing.T, req LoginRequest) (*Service, LoginRequest, context.Context) {
			req.Username = ""
			return ok(t), req, context.Background()
		},
		"unknown backend": func(t *testing.T, req LoginRequest) (*Service, LoginRequest, context.Context) {
			req.Backend = BackendRADIUS
			return ok(t), req, context.Background()
		},
		"canceled context": func(t *testing.T, req LoginRequest) (*Service, LoginRequest, context.Context) {
			return ok(t), req, canceled
		},
	}
}

// TestLoginDestroysRequestCredentialsOnEveryPath proves Login owns the
// request's enclaves: whatever the outcome, both are wiped when it returns.
func TestLoginDestroysRequestCredentialsOnEveryPath(t *testing.T) {
	for name, setup := range loginOutcomes() {
		t.Run(name, func(t *testing.T) {
			req := LoginRequest{Username: "user", Password: sealed(t, "pass"), OTP: sealed(t, "123456")}
			password, otp := req.Password, req.OTP
			svc, req, ctx := setup(t, req)
			_ = svc.Login(ctx, req)
			if password.IsAlive() {
				t.Error("Login left the request password alive")
			}
			if otp.IsAlive() {
				t.Error("Login left the request OTP alive")
			}
		})
	}
}

// TestLoginKeepsCredentialsAliveForTheAttempt: the backends see live
// credentials, including the second backend after the first one failed.
func TestLoginKeepsCredentialsAliveForTheAttempt(t *testing.T) {
	first := &stubHandler{err: errors.New("failure")}
	second := &stubHandler{}
	svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: first}, {Name: BackendRADIUS, Handler: second}}})
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	if err := svc.Login(context.Background(), LoginRequest{Username: "user", Password: sealed(t, "pass")}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !first.aliveDuringCall || !second.aliveDuringCall {
		t.Fatalf("a backend saw a destroyed password: first=%v second=%v", first.aliveDuringCall, second.aliveDuringCall)
	}
	if second.password != "pass" {
		t.Fatalf("second backend saw password %q", second.password)
	}
}

func TestLoginRejectsDestroyedPassword(t *testing.T) {
	handler := &stubHandler{}
	svc, err := NewService(Config{Backends: []Backend{{Name: BackendPAM, Handler: handler}}})
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	password := sealed(t, "pass")
	password.Destroy()
	err = svc.Login(context.Background(), LoginRequest{Username: "user", Password: password})
	if !errors.Is(err, ErrMissingCredentials) || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("err = %v, want ErrMissingCredentials joined with ErrEnclaveDestroyed", err)
	}
	if handler.calls != 0 {
		t.Fatalf("a backend was called %d times with a destroyed password", handler.calls)
	}
}

// TestHandlersBorrow: an adapter called directly leaves the caller's enclaves
// alive; only Service.Login destroys.
func TestHandlersBorrow(t *testing.T) {
	password := sealed(t, "secret")
	otp := sealed(t, "123456")
	handlers := map[string]Handler{
		"PAM":     PAM(&fakePasswordAuthenticator{}),
		"RADIUS":  RADIUS(&fakePasswordAuthenticator{}),
		"TACACS":  TACACS(&fakePasswordAuthenticator{}),
		"LDAP":    LDAP(&fakePasswordAuthenticator{}),
		"OAuth":   OAuth(&fakePasswordAuthenticator{}),
		"OTP":     OTP(&fakeOTPAuthenticator{}),
		"PKCS11":  PKCS11(&fakePINAuthenticator{}),
		"YubiKey": YubiKey(&fakeOTPAuthenticator{}),
		"TPM2":    TPM2(&fakePINAuthenticator{}),
	}
	for name, h := range handlers {
		if err := h.Authenticate(context.Background(), "user", password, otp); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !password.IsAlive() || !otp.IsAlive() {
			t.Fatalf("%s destroyed a borrowed credential", name)
		}
	}
}
