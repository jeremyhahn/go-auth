package tacacs

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	secretpkg "github.com/jeremyhahn/go-auth/pkg/secret"
)

// subprocessEnvKey marks the re-executed child of
// TestFIPSActivationRefusesTACACS.
const subprocessEnvKey = "GO_AUTH_TACACS_FIPS_CHILD"

// skipUnderFIPSActivation skips a test that drives the RFC 8907 §4.5 MD5 body
// obfuscation, which a FIPS-activated process refuses to execute. Under that
// activation the backend's whole contract is the refusal, which
// TestFIPSActivationRefusesTACACS and TestNewAuthenticatorRefusesWhenFIPSIsActive
// assert; everything else in this package has nothing to exercise there.
func skipUnderFIPSActivation(t *testing.T) {
	t.Helper()
	if fips140OnlyActive() {
		t.Skip("FIPS 140-only mode is active: TACACS+ refuses to run (RFC 8907 §4.5 MD5); " +
			"the refusal is covered by the fips_test.go tests")
	}
}

// TestMD5IsAvailableInAnOrdinaryProcess is the false-positive guard. The probe
// decides whether the whole backend is usable, so a probe that reported
// "unavailable" here would disable TACACS+ in every non-FIPS deployment and no
// other test would notice — every one of them would just see a refusal.
func TestMD5IsAvailableInAnOrdinaryProcess(t *testing.T) {
	if os.Getenv("GODEBUG") != "" {
		t.Skipf("GODEBUG is set to %q; this test needs an unrestricted runtime", os.Getenv("GODEBUG"))
	}
	if md5Unavailable() {
		t.Fatal("md5Unavailable() = true in an ordinary process; the backend would refuse to start everywhere")
	}
	if fips140OnlyActive() {
		t.Fatal("fips140OnlyActive() = true in an ordinary process")
	}
}

// TestNewAuthenticatorRefusesWhenFIPSIsActive drives the refusal branch through
// both constructors without a second process, by substituting the probe.
func TestNewAuthenticatorRefusesWhenFIPSIsActive(t *testing.T) {
	restore := fips140OnlyActive
	fips140OnlyActive = func() bool { return true }
	t.Cleanup(func() { fips140OnlyActive = restore })

	t.Run("NewAuthenticator", func(t *testing.T) {
		auth, err := NewAuthenticator("127.0.0.1:49", testSecret)
		if !errors.Is(err, ErrFIPSUnsupported) {
			t.Fatalf("err = %v, want ErrFIPSUnsupported", err)
		}
		if auth != nil {
			t.Error("an authenticator was returned alongside the refusal")
		}
	})

	t.Run("NewAuthenticatorWithSecret", func(t *testing.T) {
		sealed, err := secretpkg.NewString(testSecret)
		if err != nil {
			t.Fatalf("seal secret: %v", err)
		}
		defer sealed.Destroy()

		auth, err := NewAuthenticatorWithSecret("127.0.0.1:49", sealed)
		if !errors.Is(err, ErrFIPSUnsupported) {
			t.Fatalf("err = %v, want ErrFIPSUnsupported", err)
		}
		if auth != nil {
			t.Error("an authenticator was returned alongside the refusal")
		}
	})

	// The refusal must come before every argument check, in both constructors,
	// so a FIPS deployment is told the backend is categorically unavailable
	// rather than told its arguments are wrong. NewAuthenticator validates and
	// seals the secret string itself before delegating, so it needs its own
	// gate rather than inheriting the delegate's.
	t.Run("precedence over argument validation", func(t *testing.T) {
		cases := []struct {
			name string
			call func() (*Authenticator, error)
		}{
			{"NewAuthenticator/empty secret", func() (*Authenticator, error) {
				return NewAuthenticator("127.0.0.1:49", "")
			}},
			{"NewAuthenticator/empty address", func() (*Authenticator, error) {
				return NewAuthenticator("", testSecret)
			}},
			{"NewAuthenticator/both empty", func() (*Authenticator, error) {
				return NewAuthenticator("", "")
			}},
			{"NewAuthenticatorWithSecret/empty address and nil secret", func() (*Authenticator, error) {
				return NewAuthenticatorWithSecret("", nil)
			}},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				auth, err := tc.call()
				if !errors.Is(err, ErrFIPSUnsupported) {
					t.Errorf("err = %v, want ErrFIPSUnsupported ahead of the argument checks", err)
				}
				if auth != nil {
					t.Error("an authenticator was returned alongside the refusal")
				}
			})
		}
	})
}

// TestAuthenticateRefusesWhenFIPSIsActive covers an authenticator constructed
// before the gate could see the activation — the zero value, or one built by a
// caller that reached the struct another way. Authenticate must refuse with
// the typed error before it hands the secret to tacplus, whose first packet
// would otherwise panic inside crypto/md5.
func TestAuthenticateRefusesWhenFIPSIsActive(t *testing.T) {
	restore := fips140OnlyActive
	fips140OnlyActive = func() bool { return true }
	t.Cleanup(func() { fips140OnlyActive = restore })

	err := (&Authenticator{addr: "127.0.0.1:49"}).Authenticate(context.Background(), "alice", "password")
	if !errors.Is(err, ErrFIPSUnsupported) {
		t.Fatalf("err = %v, want ErrFIPSUnsupported", err)
	}
}

// TestFIPSActivationRefusesTACACS is the end-to-end proof: it re-executes this
// test binary with GODEBUG=fips140=only, which is exactly how a deployment
// activates FIPS under boundary ruling 1, and asserts the real probe reports
// the runtime's refusal and the constructors fail closed without panicking.
func TestFIPSActivationRefusesTACACS(t *testing.T) {
	if os.Getenv(subprocessEnvKey) == "1" {
		fipsActivatedChild(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestFIPSActivationRefusesTACACS$", "-test.v")
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
	if !md5Unavailable() {
		t.Fatal("md5Unavailable() = false under GODEBUG=fips140=only; the runtime accepted MD5")
	}
	if !fips140OnlyActive() {
		t.Fatal("fips140OnlyActive() = false under GODEBUG=fips140=only")
	}

	for _, tc := range []struct {
		name         string
		addr, secret string
	}{
		{"well-formed", "127.0.0.1:49", testSecret},
		{"empty secret", "127.0.0.1:49", ""},
		{"empty address", "", testSecret},
		{"both empty", "", ""},
	} {
		auth, err := NewAuthenticator(tc.addr, tc.secret)
		if !errors.Is(err, ErrFIPSUnsupported) {
			t.Errorf("%s: NewAuthenticator err = %v, want ErrFIPSUnsupported", tc.name, err)
		}
		if auth != nil {
			t.Errorf("%s: an authenticator was returned under FIPS activation", tc.name)
		}
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
