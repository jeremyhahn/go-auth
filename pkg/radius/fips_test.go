//go:build !fips140only

package radius

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	secretpkg "github.com/jeremyhahn/go-auth/pkg/secret"
)

// subprocessEnvKey marks the re-executed child of
// TestFIPSActivationRefusesRADIUS.
const subprocessEnvKey = "GO_AUTH_RADIUS_FIPS_CHILD"

// TestHMACMD5IsAvailableInAnOrdinaryProcess is the false-positive guard. The
// probe decides whether the whole backend is usable, so a probe that reported
// "unavailable" here would disable RADIUS in every non-FIPS deployment and no
// other test would notice — every one of them would just see a refusal.
func TestHMACMD5IsAvailableInAnOrdinaryProcess(t *testing.T) {
	if os.Getenv("GODEBUG") != "" {
		t.Skipf("GODEBUG is set to %q; this test needs an unrestricted runtime", os.Getenv("GODEBUG"))
	}
	if hmacMD5Unavailable() {
		t.Fatal("hmacMD5Unavailable() = true in an ordinary process; the backend would refuse to start everywhere")
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
		auth, err := NewAuthenticator("127.0.0.1:1812", "shared-secret")
		if !errors.Is(err, ErrFIPSUnsupported) {
			t.Fatalf("err = %v, want ErrFIPSUnsupported", err)
		}
		if auth != nil {
			t.Error("an authenticator was returned alongside the refusal")
		}
	})

	t.Run("NewAuthenticatorWithSecret", func(t *testing.T) {
		sealed, err := secretpkg.NewString("shared-secret")
		if err != nil {
			t.Fatalf("seal secret: %v", err)
		}
		defer sealed.Destroy()

		auth, err := NewAuthenticatorWithSecret("127.0.0.1:1812", sealed)
		if !errors.Is(err, ErrFIPSUnsupported) {
			t.Fatalf("err = %v, want ErrFIPSUnsupported", err)
		}
		if auth != nil {
			t.Error("an authenticator was returned alongside the refusal")
		}
	})

	// The refusal must come before every argument check, in both constructors,
	// so a FIPS deployment is told the backend is categorically unavailable
	// rather than told its arguments are wrong. Startup code branching on
	// errors.Is(err, ErrFIPSUnsupported) has to be able to rely on that
	// whichever constructor it calls and whatever it passes.
	//
	// NewAuthenticator is the one that can regress here: it validates and seals
	// the secret string itself before delegating, so it needs its own gate
	// rather than inheriting the delegate's.
	t.Run("precedence over argument validation", func(t *testing.T) {
		cases := []struct {
			name string
			call func() (*Authenticator, error)
		}{
			{"NewAuthenticator/empty secret", func() (*Authenticator, error) {
				return NewAuthenticator("127.0.0.1:1812", "")
			}},
			{"NewAuthenticator/empty address", func() (*Authenticator, error) {
				return NewAuthenticator("", "shared-secret")
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

// TestFIPSActivationRefusesRADIUS is the end-to-end proof: it re-executes this
// test binary with GODEBUG=fips140=only, which is exactly how a deployment
// activates FIPS under boundary ruling 1, and asserts the real probe reports
// the runtime's refusal and the constructor fails closed.
//
// The substitution test above can only show the branch is wired up. This one
// shows the condition is detected, which is the part that depends on runtime
// behavior no unit test can assert from inside an unrestricted process.
func TestFIPSActivationRefusesRADIUS(t *testing.T) {
	if os.Getenv(subprocessEnvKey) == "1" {
		fipsActivatedChild(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestFIPSActivationRefusesRADIUS$", "-test.v")
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
	if !hmacMD5Unavailable() {
		t.Fatal("hmacMD5Unavailable() = false under GODEBUG=fips140=only; the runtime accepted HMAC-MD5")
	}
	if !fips140OnlyActive() {
		t.Fatal("fips140OnlyActive() = false under GODEBUG=fips140=only")
	}

	// The well-formed call and the ones that would otherwise fail argument
	// validation first, all against the real runtime rather than the
	// substitution seam.
	for _, tc := range []struct {
		name            string
		address, secret string
	}{
		{"well-formed", "127.0.0.1:1812", "shared-secret"},
		{"empty secret", "127.0.0.1:1812", ""},
		{"empty address", "", "shared-secret"},
		{"both empty", "", ""},
	} {
		auth, err := NewAuthenticator(tc.address, tc.secret)
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
