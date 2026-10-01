package otp

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// subprocessEnvKey marks the re-executed child of TestFIPSActivation.
const subprocessEnvKey = "GO_AUTH_OTP_FIPS_CHILD"

// TestHMACSHA1IsAvailableInAnOrdinaryProcess is the false-positive guard. The
// probe decides whether SHA-1 OTP is usable at all, so a probe that reported
// "unavailable" here would refuse SHA-1 — and switch the default digest — in
// every non-FIPS deployment, and no other test would notice.
func TestHMACSHA1IsAvailableInAnOrdinaryProcess(t *testing.T) {
	if os.Getenv("GODEBUG") != "" {
		t.Skipf("GODEBUG is set to %q; this test needs an unrestricted runtime", os.Getenv("GODEBUG"))
	}
	if hmacSHA1Unavailable() {
		t.Fatal("hmacSHA1Unavailable() = true in an ordinary process; SHA-1 OTP would be refused everywhere")
	}
	if fips140OnlyActive() {
		t.Fatal("fips140OnlyActive() = true in an ordinary process")
	}
}

// TestFIPSActivation re-executes this test binary under GODEBUG=fips140=only —
// how a deployment activates FIPS under boundary ruling 1 — so the real probe
// and the real runtime refusal are exercised in every ordinary test run, not
// only in the FIPS CI job. In the FIPS job itself the parent is already
// activated and runs the child's assertions directly.
func TestFIPSActivation(t *testing.T) {
	if os.Getenv(subprocessEnvKey) == "1" || fips140OnlyActive() {
		fipsActivatedChecks(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestFIPSActivation$", "-test.v", "-test.count=1")
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

// fipsActivatedChecks runs inside a process under GODEBUG=fips140=only, with
// the real probe. Reaching the end at all is part of the proof: every call
// below that keys HMAC with SHA-1 or a short key would otherwise panic.
func fipsActivatedChecks(t *testing.T) {
	if !hmacSHA1Unavailable() {
		t.Fatal("hmacSHA1Unavailable() = false under GODEBUG=fips140=only; the runtime accepted HMAC-SHA-1")
	}
	if !fips140OnlyActive() {
		t.Fatal("fips140OnlyActive() = false under GODEBUG=fips140=only")
	}

	assertSHA1Refused(t)
	assertOmittedAlgorithmRefused(t)
	assertApprovedDigestsWork(t)
	assertSeedFloor(t)
	assertDeriveNeverPanics(t)
}

// TestSHA1RefusedUnderFIPS drives the refusal branch in an ordinary process by
// substituting the probe; TestFIPSActivation covers the real runtime.
func TestSHA1RefusedUnderFIPS(t *testing.T) {
	forceFIPSActive(t)
	assertSHA1Refused(t)
}

// assertSHA1Refused proves an explicit SHA-1 fails closed at construction.
//
// Under fips140=only, crypto/hmac panics on SHA-1 rather than returning an
// error. If the configuration were accepted, that panic would sit behind
// Generate, Authenticate and ValidateCounter — attacker-reachable traffic —
// and crash the process instead of failing a login.
func assertSHA1Refused(t *testing.T) {
	t.Helper()
	for _, otpType := range []Type{TypeTOTP, TypeHOTP} {
		seed := testSeed(t)
		auth, err := NewAuthenticator(Config{Type: otpType, Seed: seed, Algorithm: AlgorithmSHA1})
		if !errors.Is(err, ErrFIPSUnsupported) || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s with SHA-1 = %v, want ErrFIPSUnsupported wrapped in ErrInvalidConfig", otpType, err)
		}
		if auth != nil {
			t.Errorf("%s: expected no authenticator alongside the error, got %v", otpType, auth)
		}
		if seed.IsAlive() {
			t.Errorf("%s: refused configuration left the seed alive", otpType)
		}
	}
}

// TestOmittedAlgorithmRefusedUnderFIPS covers the default. RFC 6238's SHA-1
// default is exactly what panics, and silently substituting SHA-256 would
// validate every seed enrolled under that default with the wrong digest — a
// lockout with nothing at startup to explain it. Under activation an omitted
// algorithm is refused, so the operator names SHA-256 or SHA-512 deliberately.
func TestOmittedAlgorithmRefusedUnderFIPS(t *testing.T) {
	forceFIPSActive(t)
	assertOmittedAlgorithmRefused(t)
}

func assertOmittedAlgorithmRefused(t *testing.T) {
	t.Helper()
	for _, otpType := range []Type{TypeTOTP, TypeHOTP} {
		seed := testSeed(t)
		auth, err := NewAuthenticator(Config{Type: otpType, Seed: seed, Issuer: "TestApp", AccountName: "user@example.com"})
		if !errors.Is(err, ErrFIPSUnsupported) || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s with an omitted algorithm = %v, want ErrFIPSUnsupported wrapped in ErrInvalidConfig", otpType, err)
		}
		if !strings.Contains(err.Error(), "explicitly") {
			t.Errorf("%s: refusal %q does not tell the operator to set the algorithm explicitly", otpType, err)
		}
		if auth != nil {
			t.Errorf("%s: expected no authenticator alongside the error, got %v", otpType, auth)
		}
		if seed.IsAlive() {
			t.Errorf("%s: refused configuration left the seed alive", otpType)
		}
	}
}

// TestApprovedDigestsWorkUnderFIPS is the other half: SHA-256 and SHA-512,
// named explicitly, construct and round-trip, and enrollment advertises the
// digest validation will use.
func TestApprovedDigestsWorkUnderFIPS(t *testing.T) {
	forceFIPSActive(t)
	assertApprovedDigestsWork(t)
}

func assertApprovedDigestsWork(t *testing.T) {
	t.Helper()
	for _, algo := range []Algorithm{AlgorithmSHA256, AlgorithmSHA512} {
		auth, err := NewAuthenticator(Config{Type: TypeTOTP, Seed: testSeed(t), Algorithm: algo, Issuer: "TestApp", AccountName: "user@example.com"})
		if err != nil {
			t.Fatalf("%s: %v", algo, err)
		}
		code, err := auth.Generate()
		if err != nil {
			t.Fatalf("%s Generate: %v", algo, err)
		}
		if err := auth.Authenticate(context.Background(), codeOf(t, code)); err != nil {
			t.Errorf("%s Authenticate: %v", algo, err)
		}
		uri, err := auth.ProvisioningURI()
		if err != nil {
			t.Fatalf("%s ProvisioningURI: %v", algo, err)
		}
		parsed, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("parse URI: %v", err)
		}
		if got := parsed.Query().Get("algorithm"); got != string(algo) {
			t.Errorf("provisioning URI advertises %q, want %s", got, algo)
		}
		_ = auth.Close()

		hotp, err := NewAuthenticator(Config{Type: TypeHOTP, Seed: testSeed(t), Algorithm: algo})
		if err != nil {
			t.Fatalf("%s HOTP: %v", algo, err)
		}
		code, err = hotp.Generate(1)
		if err != nil {
			t.Fatalf("%s HOTP Generate: %v", algo, err)
		}
		if _, err := hotp.ValidateCounter(context.Background(), codeOf(t, code), 1); err != nil {
			t.Errorf("%s ValidateCounter: %v", algo, err)
		}
		_ = hotp.Close()
	}
}

// Seeds either side of the FIPS 140-3 HMAC key floor: crypto/hmac panics below
// 112 bits under fips140=only. Measured against the go1.27.1 toolchain, 13
// bytes panics and 14 does not.
var fipsKeyFloorCases = []struct {
	name   string
	bytes  int
	accept bool
}{
	{"80 bits, the JBSWY3DPEHPK3PXP example's length", 10, false},
	{"104 bits, one byte below the floor", 13, false},
	{"112 bits, the floor exactly", 14, true},
	{"160 bits, what GenerateProtectedSecret emits", 20, true},
}

// TestShortSeedRefusedUnderFIPS proves a seed too short to key HMAC fails
// closed at construction — the same failure shape as SHA-1: a panic, not an
// error, from crypto/hmac. Applications holding seeds enrolled from the widely
// copied 80-bit example are exactly the ones affected, and they need to see it
// at startup, not at a login. 112 bits exactly must be accepted: a check that
// refused it would be quietly over-strict.
func TestShortSeedRefusedUnderFIPS(t *testing.T) {
	forceFIPSActive(t)
	assertSeedFloor(t)
}

func assertSeedFloor(t *testing.T) {
	t.Helper()
	for _, tc := range fipsKeyFloorCases {
		seed := newSeed(t, fmt.Sprintf("%0*d", tc.bytes, 7)) // tc.bytes ASCII bytes
		auth, err := NewAuthenticator(Config{Type: TypeTOTP, Seed: seed, Algorithm: AlgorithmSHA256})
		if !tc.accept {
			if !errors.Is(err, ErrFIPSUnsupported) {
				t.Errorf("%s: %v, want ErrFIPSUnsupported", tc.name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: refused: %v", tc.name, err)
		}
		code, err := auth.Generate()
		if err != nil {
			t.Fatalf("%s: Generate: %v", tc.name, err)
		}
		if err := auth.Authenticate(context.Background(), codeOf(t, code)); err != nil {
			t.Errorf("%s: Authenticate: %v", tc.name, err)
		}
		_ = auth.Close()
	}
}

// TestShortSeedAcceptedOutsideFIPS keeps the default deployment's behavior:
// there is no key-length floor there, so seeds enrolled from the 80-bit example
// go on working.
func TestShortSeedAcceptedOutsideFIPS(t *testing.T) {
	if fips140OnlyActive() {
		t.Skip("FIPS 140-only mode is active; the floor applies (TestFIPSActivation)")
	}
	auth, err := NewAuthenticator(Config{Type: TypeTOTP, Seed: newSeed(t, "0123456789"), Algorithm: AlgorithmSHA1})
	if err != nil {
		t.Fatalf("80-bit seed refused outside FIPS: %v", err)
	}
	_ = auth.Close()
}

// TestDeriveCodeNeverReachesTheHMACPanic is the backstop. Construction refuses
// SHA-1 and short seeds, but deriveCode is the only place HMAC is keyed, so it
// re-checks beside it. Under the real runtime (TestFIPSActivation) this calls
// deriveCode with exactly the inputs that panic crypto/hmac; reaching the
// assertions at all is the proof.
func TestDeriveCodeNeverReachesTheHMACPanic(t *testing.T) {
	forceFIPSActive(t)
	assertDeriveNeverPanics(t)
}

func assertDeriveNeverPanics(t *testing.T) {
	t.Helper()
	if _, err := deriveCode([]byte(rfcKeySHA1), 0, 6, AlgorithmSHA1); !errors.Is(err, ErrFIPSUnsupported) {
		t.Errorf("SHA-1 = %v, want ErrFIPSUnsupported", err)
	}
	if _, err := deriveCode([]byte("0123456789123"), 0, 6, AlgorithmSHA256); !errors.Is(err, ErrFIPSUnsupported) {
		t.Errorf("104-bit key = %v, want ErrFIPSUnsupported", err)
	}
	if _, err := deriveCode([]byte("01234567891234"), 0, 6, AlgorithmSHA256); err != nil {
		t.Errorf("112-bit key = %v, want nil", err)
	}
}

// envWithout returns env minus every variable named in keys.
func envWithout(env []string, keys ...string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		drop := false
		for _, k := range keys {
			if name == k {
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
