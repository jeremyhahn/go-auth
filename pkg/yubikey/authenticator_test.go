package yubikey

import (
	"context"
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// fakeValidator records what it was lent, as copies taken during the call.
type fakeValidator struct {
	err        error
	calls      int
	lastClient string
	lastKey    string
	lastOTP    string
}

func (f *fakeValidator) Validate(_ context.Context, clientID string, apiKey, otp *enclave.MemoryEnclave) error {
	f.calls++
	f.lastClient = clientID
	var key string
	err := apiKey.WithBytes(func(b []byte) error {
		key = string(b)
		return nil
	})
	if err != nil {
		return err
	}
	f.lastKey = key
	var code string
	err = otp.WithBytes(func(b []byte) error {
		code = string(b)
		return nil
	})
	if err != nil {
		return err
	}
	f.lastOTP = code
	return f.err
}

func TestConfigValidate(t *testing.T) {
	dead := sealed(t, "secret")
	dead.Destroy()

	cases := []struct {
		name string
		cfg  Config
		want []error
	}{
		{"missing client", Config{APIKey: sealed(t, "secret")}, []error{ErrMissingClientID}},
		{"missing key", Config{ClientID: "id"}, []error{ErrMissingAPIKey}},
		{"destroyed key", Config{ClientID: "id", APIKey: dead}, []error{ErrMissingAPIKey, enclave.ErrEnclaveDestroyed}},
		{"valid", Config{ClientID: "id", APIKey: sealed(t, "secret")}, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate()
			if tc.want == nil && err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			for _, want := range tc.want {
				if !errors.Is(err, want) {
					t.Fatalf("err = %v, want %v", err, want)
				}
			}
		})
	}
}

func TestNewAuthenticatorRequiresValidator(t *testing.T) {
	key := sealed(t, "secret")
	restore := systemValidator
	t.Cleanup(func() { systemValidator = restore })
	systemValidator = nil
	if _, err := NewAuthenticator(Config{ClientID: "id", APIKey: key}, nil); !errors.Is(err, errSystemValidatorUnavailable) {
		t.Fatalf("expected errSystemValidatorUnavailable, got %v", err)
	}
	if key.IsAlive() {
		t.Fatal("refused construction left the API key alive")
	}
}

func TestNewAuthenticatorDestroysKeyOnInvalidConfig(t *testing.T) {
	key := sealed(t, "secret")
	if _, err := NewAuthenticator(Config{APIKey: key}, &fakeValidator{}); !errors.Is(err, ErrMissingClientID) {
		t.Fatalf("err = %v, want ErrMissingClientID", err)
	}
	if key.IsAlive() {
		t.Fatal("refused construction left the API key alive")
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	validator := &fakeValidator{}
	auth, err := NewAuthenticator(Config{ClientID: "id", APIKey: sealed(t, "secret")}, validator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer auth.Close()

	otp := sealed(t, "otp-value")
	if err := auth.Authenticate(context.Background(), otp); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if validator.calls != 1 {
		t.Fatalf("expected validator called once, got %d", validator.calls)
	}
	if validator.lastClient != "id" || validator.lastKey != "secret" || validator.lastOTP != "otp-value" {
		t.Fatalf("unexpected parameters: %#v", validator)
	}
	if !otp.IsAlive() {
		t.Fatal("Authenticate destroyed a borrowed OTP")
	}
}

func TestAuthenticatePropagatesError(t *testing.T) {
	want := errors.New("remote failure")
	auth, err := NewAuthenticator(Config{ClientID: "id", APIKey: sealed(t, "secret")}, &fakeValidator{err: want})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer auth.Close()
	if err := auth.Authenticate(context.Background(), sealed(t, "otp-value")); !errors.Is(err, want) {
		t.Fatalf("expected %v, got %v", want, err)
	}
}

func TestAuthenticateRejectsMissingOTP(t *testing.T) {
	validator := &fakeValidator{}
	auth, err := NewAuthenticator(Config{ClientID: "id", APIKey: sealed(t, "secret")}, validator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer auth.Close()
	if err := auth.Authenticate(context.Background(), nil); !errors.Is(err, ErrMissingOTP) {
		t.Fatalf("nil otp: err = %v, want ErrMissingOTP", err)
	}
	dead := sealed(t, "otp-value")
	dead.Destroy()
	if err := auth.Authenticate(context.Background(), dead); !errors.Is(err, ErrMissingOTP) || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("destroyed otp: err = %v", err)
	}
	if validator.calls != 0 {
		t.Fatalf("validator called %d times without an OTP", validator.calls)
	}
}

func TestAuthenticateContextCancel(t *testing.T) {
	auth, err := NewAuthenticator(Config{ClientID: "id", APIKey: sealed(t, "secret")}, &fakeValidator{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer auth.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := auth.Authenticate(ctx, sealed(t, "otp-value")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func TestCloseDestroysAPIKeyAndRefusesFurtherUse(t *testing.T) {
	key := sealed(t, "secret")
	validator := &fakeValidator{}
	auth, err := NewAuthenticator(Config{ClientID: "id", APIKey: key}, validator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := auth.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if key.IsAlive() {
		t.Fatal("Close left the API key alive")
	}
	if err := auth.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := auth.Authenticate(context.Background(), sealed(t, "otp-value")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Authenticate after Close = %v, want ErrClosed", err)
	}
	if validator.calls != 0 {
		t.Fatalf("validator called %d times after Close", validator.calls)
	}
}

func TestNilAuthenticator(t *testing.T) {
	var auth *Authenticator
	if err := auth.Authenticate(context.Background(), sealed(t, "otp")); !errors.Is(err, ErrNilAuthenticator) {
		t.Fatalf("err = %v, want ErrNilAuthenticator", err)
	}
	if err := auth.Close(); err != nil {
		t.Fatalf("Close on nil: %v", err)
	}
}
