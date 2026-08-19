//go:build fips140only

package yubikey

import (
	"context"
	"errors"
	"os"
	"testing"
)

// systemValidatorAtStartup is the package default as package initialization
// left it. TestMain runs after every init() but before any test, which is the
// only point at which this is observable: TestNewAuthenticatorRequiresValidator
// sets systemValidator to nil, so a guard that read the variable during a test
// would pass whether or not init() had installed a validator.
var systemValidatorAtStartup OTPValidator

func TestMain(m *testing.M) {
	systemValidatorAtStartup = systemValidator
	os.Exit(m.Run())
}

// TestYubiCloudUnreachableUnderFIPS is the guard for the exclusion in
// yubicloud_validator.go.
//
// The YubiCloud validator signs with HMAC-SHA-1, which panics under
// GODEBUG=fips140=only. Because it used to install itself as the package
// default in init(), the panic was reachable through the ordinary
// NewAuthenticator(cfg, nil) path while every unit test injected a fake
// validator and so never touched it — a backend that passed CI and failed on
// first real use.
//
// In a fips140only build there must be no default validator at all: the
// failure has to surface at construction, as a typed error.
func TestYubiCloudUnreachableUnderFIPS(t *testing.T) {
	if systemValidatorAtStartup != nil {
		t.Fatalf("fips140only build installed a default validator (%T); "+
			"the only implementation in this package signs with HMAC-SHA-1",
			systemValidatorAtStartup)
	}

	systemValidator = systemValidatorAtStartup
	cfg := Config{ClientID: "id", APIKey: "secret"}
	auth, err := NewAuthenticator(cfg, nil)
	if !errors.Is(err, errSystemValidatorUnavailable) {
		t.Fatalf("expected errSystemValidatorUnavailable, got auth=%v err=%v", auth, err)
	}
}

// TestInjectedValidatorStillWorksUnderFIPS records the other half of the
// exemption: excluding YubiCloud does not remove YubiKey support from FIPS
// builds. A caller that supplies a validator speaking to an approved service
// keeps the full authentication path.
func TestInjectedValidatorStillWorksUnderFIPS(t *testing.T) {
	validator := &fakeValidator{}
	auth, err := NewAuthenticator(Config{ClientID: "id", APIKey: "secret"}, validator)
	if err != nil {
		t.Fatalf("failed to construct with an injected validator: %v", err)
	}

	if err := auth.Authenticate(context.Background(), "ccccccbchvth"); err != nil {
		t.Fatalf("authenticate with injected validator: %v", err)
	}
	if validator.calls != 1 {
		t.Errorf("expected the injected validator to be called once, got %d", validator.calls)
	}
}
