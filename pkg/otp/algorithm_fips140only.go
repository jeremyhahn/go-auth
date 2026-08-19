//go:build fips140only

package otp

import "fmt"

// defaultAlgorithm is the digest used when Config.Algorithm is empty.
//
// RFC 6238 §1.2 permits SHA-256 and SHA-512 alongside its SHA-1 default, and
// SHA-256 is the weakest of those Go's fips140=only mode will execute, so a
// FIPS build defaults to it. GetProvisioningURI reports the digest it will
// validate with, so enrollment stays consistent.
const defaultAlgorithm = AlgorithmSHA256

// checkAlgorithmSupported rejects SHA-1 in FIPS-140-only builds.
//
// This has to fail at construction rather than at first use. Under
// GODEBUG=fips140=only, crypto/hmac does not return an error for SHA-1 — it
// panics. Accepting the configuration here would turn an ordinary
// authentication request, which is attacker-reachable traffic, into a process
// crash rather than a rejected login.
func checkAlgorithmSupported(a Algorithm) error {
	if a == AlgorithmSHA1 {
		return fmt.Errorf("%w: algorithm SHA1 cannot be used in a fips140only build "+
			"(FIPS 140-3 admits HMAC over SHA-2/SHA-3 only); use SHA256 or SHA512, "+
			"both permitted by RFC 6238 §1.2", ErrInvalidConfig)
	}
	return nil
}

// minHMACKeyBits is the shortest HMAC key Go's fips140=only mode will accept:
// crypto/hmac panics below 112 bits. Measured against the toolchain rather
// than assumed — 13 bytes panics, 14 does not.
const minHMACKeyBits = 112

// checkSecretSupported rejects secrets too short to key HMAC in FIPS 140-only
// mode.
//
// Like checkAlgorithmSupported this has to fail at construction, and for the
// same reason: crypto/hmac panics rather than returning an error, so a short
// secret accepted here becomes a process crash on the next Generate,
// Authenticate or ValidateCounter — reachable by ordinary authentication
// traffic. The widely copied 80-bit "JBSWY3DPEHPK3PXP" example is exactly this
// case, so applications carrying secrets enrolled from it are the ones at risk;
// they need re-enrollment, which is a failure they must see at startup rather
// than at a login attempt.
//
// It takes a bit count rather than the key itself, so no raw key material
// crosses this boundary.
//
// GenerateSecret emits 160 bits, so secrets this package issued are unaffected.
func checkSecretSupported(bits int) error {
	if bits < minHMACKeyBits {
		return fmt.Errorf("%w: secret decodes to %d bits, but FIPS 140-3 requires "+
			"at least %d for an HMAC key; re-enroll with a longer secret "+
			"(GenerateSecret emits 160 bits)",
			ErrInvalidConfig, bits, minHMACKeyBits)
	}
	return nil
}
