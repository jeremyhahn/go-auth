// FIPS activation gate: under GODEBUG=fips140=only, refuse SHA-1, an omitted algorithm and short seeds before crypto/hmac panics; activation is detected by executing HMAC-SHA-1.

package otp

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- probes the primitive RFC 4226 §5.1 mandates; never used to protect anything
	"errors"
	"fmt"
	"sync"
)

// ErrFIPSUnsupported reports that FIPS 140-only mode refuses the configured digest (SHA-1 or omitted) or a seed under 14 bytes. See docs/fips.md.
var ErrFIPSUnsupported = errors.New("otp: unavailable under FIPS 140-only mode")

// fips140OnlyActive reports whether HMAC-SHA-1 is refused; a variable so tests can drive both branches.
var fips140OnlyActive = sync.OnceValue(hmacSHA1Unavailable)

// hmacSHA1Unavailable runs one HMAC-SHA-1 with a 32-byte key and reports whether the runtime refused.
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

// checkFIPSAlgorithmNamed refuses an omitted algorithm under FIPS 140-only mode rather than silently changing the digest.
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
