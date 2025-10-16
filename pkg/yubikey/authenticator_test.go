package yubikey

import (
	"context"
	"errors"
	"testing"
)

type fakeValidator struct {
	err        error
	calls      int
	lastClient string
	lastKey    string
	lastOTP    string
}

func (f *fakeValidator) Validate(ctx context.Context, clientID, secret, otp string) error {
	f.calls++
	f.lastClient = clientID
	f.lastKey = secret
	f.lastOTP = otp
	return f.err
}

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"missing client", Config{APIKey: "secret"}, false},
		{"missing key", Config{ClientID: "id"}, false},
		{"valid", Config{ClientID: "id", APIKey: "secret"}, true},
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

func TestNewAuthenticatorRequiresValidator(t *testing.T) {
	cfg := Config{ClientID: "id", APIKey: "secret"}
	systemValidator = nil
	if _, err := NewAuthenticator(cfg, nil); !errors.Is(err, errSystemValidatorUnavailable) {
		t.Fatalf("expected errSystemValidatorUnavailable, got %v", err)
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	cfg := Config{ClientID: "id", APIKey: "secret"}
	validator := &fakeValidator{}
	auth, err := NewAuthenticator(cfg, validator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := auth.Authenticate(context.Background(), "otp-value"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if validator.calls != 1 {
		t.Fatalf("expected validator called once, got %d", validator.calls)
	}
	if validator.lastClient != "id" || validator.lastKey != "secret" || validator.lastOTP != "otp-value" {
		t.Fatalf("unexpected parameters: %#v", validator)
	}
}

func TestAuthenticatePropagatesError(t *testing.T) {
	cfg := Config{ClientID: "id", APIKey: "secret"}
	want := errors.New("remote failure")
	validator := &fakeValidator{err: want}
	auth, err := NewAuthenticator(cfg, validator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := auth.Authenticate(context.Background(), "otp-value"); !errors.Is(err, want) {
		t.Fatalf("expected %v, got %v", want, err)
	}
}

func TestAuthenticateRejectsEmptyOTP(t *testing.T) {
	cfg := Config{ClientID: "id", APIKey: "secret"}
	validator := &fakeValidator{}
	auth, err := NewAuthenticator(cfg, validator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := auth.Authenticate(context.Background(), ""); err == nil {
		t.Fatalf("expected error for empty otp")
	}
}

func TestAuthenticateContextCancel(t *testing.T) {
	cfg := Config{ClientID: "id", APIKey: "secret"}
	validator := &fakeValidator{}
	auth, err := NewAuthenticator(cfg, validator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := auth.Authenticate(ctx, "otp-value"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}
