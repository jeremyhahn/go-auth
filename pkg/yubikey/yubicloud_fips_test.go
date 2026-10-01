package yubikey

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

// subprocessEnvKey marks the re-executed child of
// TestFIPSActivationRefusesYubiCloud.
const subprocessEnvKey = "GO_AUTH_YUBIKEY_FIPS_CHILD"

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

// skipUnderFIPSActivation skips a test that drives the HMAC-SHA-1 signature
// Yubico Validation Protocol 2.0 mandates, which a FIPS-activated process
// refuses to execute. Under that activation the YubiCloud validator's whole
// contract is the refusal, which the tests in this file assert.
func skipUnderFIPSActivation(t *testing.T) {
	t.Helper()
	if fips140OnlyActive() {
		t.Skip("FIPS 140-only mode is active: the YubiCloud validator refuses to run " +
			"(Yubico Validation Protocol 2.0 HMAC-SHA-1); the refusal is covered by yubicloud_fips_test.go")
	}
}

// substituteFIPSActivation makes the gate report active for the rest of t.
func substituteFIPSActivation(t *testing.T) {
	t.Helper()
	restore := fips140OnlyActive
	fips140OnlyActive = func() bool { return true }
	t.Cleanup(func() { fips140OnlyActive = restore })
}

// TestYubiCloudIsTheDefaultValidator guards the single-artifact model: the
// YubiCloud validator is installed by init() in every build, and FIPS
// activation is handled by refusing at runtime, never by its absence.
func TestYubiCloudIsTheDefaultValidator(t *testing.T) {
	if _, ok := systemValidatorAtStartup.(*HTTPValidator); !ok {
		t.Fatalf("package default validator = %T, want *HTTPValidator installed by init()", systemValidatorAtStartup)
	}
}

// TestHMACSHA1IsAvailableInAnOrdinaryProcess is the false-positive guard: a
// probe that reported "unavailable" here would disable YubiCloud in every
// non-FIPS deployment and every test below would just see a refusal.
func TestHMACSHA1IsAvailableInAnOrdinaryProcess(t *testing.T) {
	if os.Getenv("GODEBUG") != "" {
		t.Skipf("GODEBUG is set to %q; this test needs an unrestricted runtime", os.Getenv("GODEBUG"))
	}
	if hmacSHA1Unavailable() {
		t.Fatal("hmacSHA1Unavailable() = true in an ordinary process; YubiCloud would refuse everywhere")
	}
	if fips140OnlyActive() {
		t.Fatal("fips140OnlyActive() = true in an ordinary process")
	}
}

// TestNewAuthenticatorRefusesYubiCloudWhenFIPSIsActive drives the
// construction-time refusal without a second process. The refusal comes ahead
// of the configuration checks, as in pkg/radius, so startup code learns the
// validator is categorically unavailable rather than that its inputs are wrong.
func TestNewAuthenticatorRefusesYubiCloudWhenFIPSIsActive(t *testing.T) {
	substituteFIPSActivation(t)

	restore := systemValidator
	t.Cleanup(func() { systemValidator = restore })
	systemValidator = systemValidatorAtStartup

	cases := []struct {
		name      string
		clientID  string
		apiKey    string
		validator OTPValidator
	}{
		{"package default", "id", "key", nil},
		{"explicit HTTPValidator", "id", "key", NewHTTPValidator(nil, "")},
		{"package default, invalid config", "", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := sealed(t, tc.apiKey)
			auth, err := NewAuthenticator(Config{ClientID: tc.clientID, APIKey: key}, tc.validator)
			if !errors.Is(err, ErrFIPSUnsupported) {
				t.Fatalf("err = %v, want ErrFIPSUnsupported", err)
			}
			if auth != nil {
				t.Error("an authenticator was returned alongside the refusal")
			}
			// The refusal is a return path on which NewAuthenticator owns the key.
			if key.IsAlive() {
				t.Error("the refusal left the API key alive")
			}
		})
	}
}

// TestHTTPValidatorRefusesWhenFIPSIsActive covers a caller that uses the
// validator directly, or wraps it in its own OTPValidator so that
// NewAuthenticator cannot recognize it. Every entry point that would reach the
// HMAC-SHA-1 must return the typed error, and must do so before any request
// leaves the process.
func TestHTTPValidatorRefusesWhenFIPSIsActive(t *testing.T) {
	substituteFIPSActivation(t)

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "unreachable", http.StatusInternalServerError)
	}))
	defer server.Close()

	key := sealed(t, "a2V5")
	otp := sealed(t, "ccccccbdefgh")

	validator := NewHTTPValidator(server.Client(), server.URL)
	entryPoints := map[string]func() error{
		"Validate": func() error {
			return validator.Validate(context.Background(), "id", key, otp)
		},
		"computeSignature": func() error {
			_, err := computeSignature(url.Values{"id": {"id"}}, key)
			return err
		},
	}
	for name, call := range entryPoints {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrFIPSUnsupported) {
				t.Fatalf("err = %v, want ErrFIPSUnsupported", err)
			}
		})
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("%d request(s) reached the validation service under FIPS activation", n)
	}
}

// TestInjectedValidatorStillWorksUnderFIPS records the other half: refusing
// YubiCloud does not remove YubiKey support under FIPS activation. A caller
// that supplies a validator speaking to an approved service keeps the full
// authentication path.
func TestInjectedValidatorStillWorksUnderFIPS(t *testing.T) {
	substituteFIPSActivation(t)

	validator := &fakeValidator{}
	auth, err := NewAuthenticator(Config{ClientID: "id", APIKey: sealed(t, "secret")}, validator)
	if err != nil {
		t.Fatalf("failed to construct with an injected validator: %v", err)
	}
	defer auth.Close()
	if err := auth.Authenticate(context.Background(), sealed(t, "ccccccbchvth")); err != nil {
		t.Fatalf("authenticate with injected validator: %v", err)
	}
	if validator.calls != 1 {
		t.Errorf("expected the injected validator to be called once, got %d", validator.calls)
	}
}

// TestFIPSActivationRefusesYubiCloud is the end-to-end proof: it re-executes
// this test binary with GODEBUG=fips140=only, exactly how a deployment
// activates FIPS under boundary ruling 1, and asserts the real probe detects
// the runtime's refusal and the default path fails closed without panicking.
func TestFIPSActivationRefusesYubiCloud(t *testing.T) {
	if os.Getenv(subprocessEnvKey) == "1" {
		fipsActivatedChild(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestFIPSActivationRefusesYubiCloud$", "-test.v")
	cmd.Env = append(envWithout(os.Environ(), "GODEBUG", subprocessEnvKey),
		"GODEBUG=fips140=only",
		subprocessEnvKey+"=1",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child under GODEBUG=fips140=only failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Fatalf("child did not pass:\n%s", out)
	}
}

// fipsActivatedChild runs inside the GODEBUG=fips140=only process.
func fipsActivatedChild(t *testing.T) {
	if !hmacSHA1Unavailable() {
		t.Fatal("hmacSHA1Unavailable() = false under GODEBUG=fips140=only; the runtime accepted HMAC-SHA-1")
	}
	if !fips140OnlyActive() {
		t.Fatal("fips140OnlyActive() = false under GODEBUG=fips140=only")
	}

	auth, err := NewAuthenticator(Config{ClientID: "id", APIKey: sealed(t, "key")}, nil)
	if !errors.Is(err, ErrFIPSUnsupported) {
		t.Errorf("NewAuthenticator with the default validator: err = %v, want ErrFIPSUnsupported", err)
	}
	if auth != nil {
		t.Error("an authenticator was returned under FIPS activation")
	}

	err = NewHTTPValidator(nil, "http://127.0.0.1:0").Validate(context.Background(), "id", sealed(t, "a2V5"), sealed(t, "ccccccbdefgh"))
	if !errors.Is(err, ErrFIPSUnsupported) {
		t.Errorf("HTTPValidator.Validate: err = %v, want ErrFIPSUnsupported", err)
	}
}

// envWithout returns env with every assignment of the named keys removed, so
// the child inherits the parent's environment except for what the test sets
// itself. A duplicate GODEBUG would leave which value wins up to the runtime.
func envWithout(env []string, keys ...string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		drop := false
		for _, key := range keys {
			if strings.HasPrefix(kv, key+"=") {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return out
}
