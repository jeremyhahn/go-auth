package pkcs11

import (
	"context"
	"errors"
	"testing"
)

type fakeSessionProvider struct {
	session Session
	err     error
	calls   int
}

func (f *fakeSessionProvider) Open(ctx context.Context, cfg Config) (Session, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.session, nil
}

type fakeSession struct {
	loginErr  error
	logoutErr error
	logins    int
	logouts   int
	lastPIN   string
}

func (f *fakeSession) Login(ctx context.Context, pin string) error {
	f.logins++
	f.lastPIN = pin
	return f.loginErr
}

func (f *fakeSession) Logout(ctx context.Context) error {
	f.logouts++
	return f.logoutErr
}

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"missing module", Config{}, false},
		{"missing selectors", Config{ModulePath: "/usr/lib/libpkcs11.so"}, false},
		{"label provided", Config{ModulePath: "mod.so", TokenLabel: "MyToken"}, true},
		{"slot provided", Config{ModulePath: "mod.so", Slot: "0"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate()
			if tc.want && err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			if !tc.want && err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestNewAuthenticatorRequiresProvider(t *testing.T) {
	cfg := Config{ModulePath: "mod.so", TokenLabel: "token"}
	systemSessionProvider = nil
	if _, err := NewAuthenticator(cfg, nil); !errors.Is(err, errSystemProviderUnavailable) {
		t.Fatalf("expected errSystemProviderUnavailable, got %v", err)
	}
}

func TestNewAuthenticatorUsesProvidedProvider(t *testing.T) {
	cfg := Config{ModulePath: "mod.so", TokenLabel: "token"}
	fake := &fakeSessionProvider{}
	auth, err := NewAuthenticator(cfg, fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth == nil {
		t.Fatalf("expected authenticator instance")
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	cfg := Config{ModulePath: "mod.so", TokenLabel: "token"}
	sess := &fakeSession{}
	provider := &fakeSessionProvider{session: sess}

	auth, err := NewAuthenticator(cfg, provider)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "1234"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if provider.calls != 1 {
		t.Fatalf("expected provider open once, got %d", provider.calls)
	}
	if sess.logins != 1 || sess.logouts != 1 {
		t.Fatalf("expected one login/logout, got login=%d logout=%d", sess.logins, sess.logouts)
	}
	if sess.lastPIN != "1234" {
		t.Fatalf("unexpected pin passed to session: %s", sess.lastPIN)
	}
}

func TestAuthenticatePropagatesLoginError(t *testing.T) {
	cfg := Config{ModulePath: "mod.so", TokenLabel: "token"}
	want := errors.New("login failed")
	sess := &fakeSession{loginErr: want}
	provider := &fakeSessionProvider{session: sess}

	auth, err := NewAuthenticator(cfg, provider)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "1234"); !errors.Is(err, want) {
		t.Fatalf("expected %v, got %v", want, err)
	}
}

func TestAuthenticateIncludesLogoutError(t *testing.T) {
	cfg := Config{ModulePath: "mod.so", TokenLabel: "token"}
	loginErr := errors.New("bad pin")
	logoutErr := errors.New("logout failed")
	sess := &fakeSession{loginErr: loginErr, logoutErr: logoutErr}
	provider := &fakeSessionProvider{session: sess}

	auth, err := NewAuthenticator(cfg, provider)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = auth.Authenticate(context.Background(), "1234")
	if !errors.Is(err, loginErr) {
		t.Fatalf("expected login error, got %v", err)
	}
	if !errors.Is(err, logoutErr) {
		t.Fatalf("expected logout error to be joined, got %v", err)
	}
}

func TestAuthenticateRejectsEmptyPIN(t *testing.T) {
	cfg := Config{ModulePath: "mod.so", TokenLabel: "token"}
	provider := &fakeSessionProvider{session: &fakeSession{}}
	auth, err := NewAuthenticator(cfg, provider)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := auth.Authenticate(context.Background(), ""); err == nil {
		t.Fatalf("expected error for empty pin")
	}
}

func TestAuthenticateRespectsContextCancel(t *testing.T) {
	cfg := Config{ModulePath: "mod.so", TokenLabel: "token"}
	provider := &fakeSessionProvider{session: &fakeSession{}}
	auth, err := NewAuthenticator(cfg, provider)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := auth.Authenticate(ctx, "1234"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}
