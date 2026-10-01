// FIPS activation gate.
//
// Company FIPS boundary ruling 1 (2026-08-20) is one artifact for both
// markets: every binary is built FIPS-capable and FIPS is *activated at
// deployment* with GODEBUG=fips140=only. Product ruling 7 says what an interop
// surface does when that happens — restrict to approved options, or be
// disabled with a clear typed error. OTP is the first case: RFC 6238 §1.2
// permits SHA-256 and SHA-512 alongside its SHA-1 default, so approved OTP
// works and only SHA-1, an omitted algorithm (whose default is SHA-1), and
// seeds too short to key an approved HMAC are refused.
//
// The refusal has to be this package's. Under fips140=only crypto/hmac does
// not return an error for SHA-1 or for a key under 112 bits — it PANICS — and
// OTP reaches HMAC on every Generate, Authenticate and ValidateCounter, so an
// unrefused configuration turns an ordinary login, which is attacker-reachable
// traffic, into a process crash. This file refuses those configurations with
// a typed error at construction, and again immediately before HMAC is keyed.
// It replaces the fips140only build tag the package used to carry
// (go-auth#20): the same binary now behaves correctly in both deployments.
//
// Activation is detected the way pkg/radius/fips.go does, by executing the
// primitive. crypto/fips140.Enabled() is true of every binary built with
// GOFIPS140 whether or not FIPS was activated, and HMAC-SHA-1 works in all of
// those; gating on it would refuse SHA-1 TOTP — what mainstream authenticator
// apps enroll with — to every deployment of a FIPS-capable artifact. Measured
// on go1.27.1, HMAC-SHA-1 with a 20-byte key:
//
//	build              GODEBUG           Enabled()  HMAC-SHA-1  HMAC-SHA-256, 13-byte key
//	plain              (none)            false      ok          ok
//	plain              fips140=on        true       ok          ok
//	plain              fips140=only      true       panics      panics
//	GOFIPS140=latest   (none)            true       ok          ok
//	GOFIPS140=latest   fips140=on        true       ok          ok
//	GOFIPS140=latest   fips140=only      true       panics      panics

package otp

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- probes the primitive RFC 4226 §5.1 mandates; never used to protect anything
	"errors"
	"fmt"
	"sync"
)

// ErrFIPSUnsupported reports that the process is running under Go's FIPS
// 140-only mode and the configured digest or seed cannot key HMAC under it.
//
// Three configurations hit it. HMAC-SHA-1 — RFC 4226 §5.1's HOTP digest and
// RFC 6238 §1.2's TOTP default — is not an approved FIPS 140-3 MAC; SHA-256
// and SHA-512 are, and RFC 6238 §1.2 permits both. An omitted
// Config.Algorithm is refused too, rather than silently resolved to an
// approved digest: seeds enrolled under the SHA-1 default would then be
// validated with the wrong digest and every login would fail with nothing at
// startup to say why. And FIPS 140-3 sets a 112-bit floor on HMAC keys, so a
// seed shorter than 14 bytes — the widely copied 80-bit "JBSWY3DPEHPK3PXP"
// example among them — needs re-enrollment. See docs/fips.md.
var ErrFIPSUnsupported = errors.New("otp: unavailable under FIPS 140-only mode")

// fips140OnlyActive reports whether this process refuses HMAC-SHA-1, which is
// the signal that FIPS 140-only mode is active.
//
// It is a variable so that the tests can drive both branches without a second
// process; production code never assigns it.
var fips140OnlyActive = sync.OnceValue(hmacSHA1Unavailable)

// hmacSHA1Unavailable computes one HMAC-SHA-1 over a fixed non-secret input
// and reports whether the runtime refused.
//
// The key is 32 bytes deliberately, as in pkg/radius/fips.go: under
// fips140=only a short key panics first for its length, which would make the
// probe report the right answer for the wrong reason and hide a future change
// in what the runtime rejects.
func hmacSHA1Unavailable() (unavailable bool) {
	defer func() {
		if recover() != nil {
			unavailable = true
		}
	}()

	mac := hmac.New(sha1.New, make([]byte, 32))
	mac.Write([]byte("go-auth fips probe"))
	mac.Sum(nil)
	return false
}

// checkFIPSAlgorithmNamed refuses an omitted algorithm under FIPS 140-only
// mode. The RFC default is SHA-1, which the runtime will not execute, and
// substituting an approved digest would silently change how existing
// enrollments validate; failing loud at construction makes the operator choose
// — and re-enroll — deliberately.
func checkFIPSAlgorithmNamed(algo Algorithm) error {
	if algo != "" || !fips140OnlyActive() {
		return nil
	}
	return fmt.Errorf("%w: the algorithm must be set explicitly to SHA256 or SHA512; "+
		"the RFC 6238 §1.2 default, SHA1, is not an approved FIPS 140-3 MAC", ErrFIPSUnsupported)
}

// approvedUnderFIPS is the set of digests crypto/hmac accepts under
// fips140=only: SHA-2 and SHA-3, of which RFC 6238 §1.2 defines the first.
var approvedUnderFIPS = map[Algorithm]bool{
	AlgorithmSHA256: true,
	AlgorithmSHA512: true,
}

// minFIPSSeedBytes is the shortest HMAC key fips140=only accepts: 112 bits.
// Measured against the toolchain rather than assumed — 13 bytes panics inside
// crypto/hmac, 14 does not.
const minFIPSSeedBytes = 14

// checkFIPS refuses a digest or seed length that would panic crypto/hmac in
// this process. It takes a length rather than the seed, so no key material
// crosses this boundary, and it is a no-op unless FIPS 140-only mode is active.
func checkFIPS(algo Algorithm, seedBytes int) error {
	if !fips140OnlyActive() {
		return nil
	}
	if !approvedUnderFIPS[algo] {
		return fmt.Errorf("%w: HMAC-%s is not an approved FIPS 140-3 MAC; "+
			"configure SHA256 or SHA512, both permitted by RFC 6238 §1.2", ErrFIPSUnsupported, algo)
	}
	if seedBytes < minFIPSSeedBytes {
		return fmt.Errorf("%w: seed is %d bits, but FIPS 140-3 requires at least %d for an HMAC key; "+
			"re-enroll with a longer seed (GenerateProtectedSecret emits 160 bits)",
			ErrFIPSUnsupported, seedBytes*8, minFIPSSeedBytes*8)
	}
	return nil
}
