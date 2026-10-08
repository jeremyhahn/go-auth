package otp

import (
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// The RFC reference keys, which the RFCs give as ASCII. rfcKeySHA1 is the RFC
// 4226 Appendix D seed and doubles as the general-purpose fixture: 20 bytes /
// 160 bits, which is what GenerateProtectedSecret emits and comfortably above
// the 112-bit HMAC key floor fips140=only enforces.
const (
	rfcKeySHA1   = "12345678901234567890"
	rfcKeySHA256 = "12345678901234567890123456789012"
	rfcKeySHA512 = "1234567890123456789012345678901234567890123456789012345678901234"
)

// testSeedBase32 is rfcKeySHA1 in unpadded base32, the form a provisioning URI
// carries.
const testSeedBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// newSeed returns an enclave holding raw. The fixture string is test data, so
// copying it in rather than generating it is fine here.
func newSeed(t *testing.T, raw string) *enclave.MemoryEnclave {
	t.Helper()
	seed, err := enclave.NewMemoryEnclaveCopy([]byte(raw))
	if err != nil {
		t.Fatalf("NewMemoryEnclaveCopy: %v", err)
	}
	t.Cleanup(func() {
		if err := seed.Destroy(); err != nil {
			t.Errorf("Destroy: %v", err)
		}
	})
	return seed
}

// testSeed returns a fresh enclave over the RFC 4226 reference key. Every call
// returns a new enclave, because NewAuthenticator takes ownership of the one
// it is given.
func testSeed(t *testing.T) *enclave.MemoryEnclave {
	t.Helper()
	return newSeed(t, rfcKeySHA1)
}

// testAlgorithm is the digest the suite uses where the choice is incidental to
// what is being tested: RFC 6238's SHA-1 default normally, and SHA-256 when
// the process runs under FIPS 140-only mode, where HMAC-SHA-1 is refused.
// Branching on the runtime rather than a build tag means one test binary
// covers both deployments; see fips.go.
func testAlgorithm() Algorithm {
	if fips140OnlyActive() {
		return AlgorithmSHA256
	}
	return AlgorithmSHA1
}

// testAlgorithms is every digest this process can execute.
func testAlgorithms() []Algorithm {
	if fips140OnlyActive() {
		return []Algorithm{AlgorithmSHA256, AlgorithmSHA512}
	}
	return []Algorithm{AlgorithmSHA1, AlgorithmSHA256, AlgorithmSHA512}
}

// forceFIPSActive makes the package behave as if fips140=only were active for
// the rest of the test, so the refusal branch is exercised in a normal run as
// well as in the FIPS job. It only ever turns the gate ON: turning it off
// under a real fips140=only runtime would let a test reach the crypto/hmac
// panic this package exists to prevent.
func forceFIPSActive(t *testing.T) {
	t.Helper()
	prev := fips140OnlyActive
	fips140OnlyActive = func() bool { return true }
	t.Cleanup(func() { fips140OnlyActive = prev })
}

// codeOf seals a submitted code into an enclave the test owns, or returns nil
// for the empty string, which is the "nothing submitted" case.
func codeOf(t *testing.T, code string) *enclave.MemoryEnclave {
	t.Helper()
	if code == "" {
		return nil
	}
	e, err := enclave.NewMemoryEnclave([]byte(code))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	t.Cleanup(func() {
		if err := e.Destroy(); err != nil {
			t.Errorf("Destroy: %v", err)
		}
	})
	return e
}
