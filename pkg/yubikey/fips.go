// FIPS activation gate for the YubiCloud validator.
//
// Company FIPS boundary ruling 1 (2026-08-20) is one artifact for both markets:
// every binary is built FIPS-capable and FIPS is *activated at deployment*
// with GODEBUG=fips140=only. Product ruling 7 says what an interop surface does
// when that happens — restrict to approved options, or be "disabled with a
// clear typed error".
//
// pkg/yubikey is the restrict case. Yubico Validation Protocol 2.0 signs every
// request and response with HMAC-SHA-1, which fips140=only refuses, so the
// YubiCloud validator (HTTPValidator) is disabled with ErrFIPSUnsupported. The
// rest of the package is untouched: an injected OTPValidator that speaks to an
// approved validation service keeps working. Without the gate a FIPS-activated
// deployment using the package default would construct cleanly and panic
// inside crypto/hmac on the first OTP. This mirrors pkg/radius/fips.go.

package yubikey

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- probes the primitive Yubico Validation Protocol 2.0 mandates; never used to protect anything
	"errors"
	"sync"
)

// ErrFIPSUnsupported reports that the process is running under Go's FIPS
// 140-only mode, in which the YubiCloud validator cannot operate.
//
// Yubico Validation Protocol 2.0 signs every request and response with
// HMAC-SHA-1 and the service accepts no other digest. NewAuthenticator returns
// it when the YubiCloud validator — explicitly or as the package default —
// would be used, and HTTPValidator returns it from every entry point. A caller
// that must validate OTPs under FIPS 140-3 injects an OTPValidator for an
// approved service; see docs/fips.md.
var ErrFIPSUnsupported = errors.New("yubikey: YubiCloud validator unavailable under FIPS 140-only mode: " +
	"Yubico Validation Protocol 2.0 signs with HMAC-SHA-1, which is not an approved primitive")

// fips140OnlyActive reports whether this process refuses HMAC-SHA-1.
//
// It is a variable so that the tests can drive both branches without a second
// process; production code never assigns it.
var fips140OnlyActive = sync.OnceValue(hmacSHA1Unavailable)

// hmacSHA1Unavailable computes one HMAC-SHA-1 over a fixed non-secret input and
// reports whether the runtime refused.
//
// It executes the primitive rather than asking crypto/fips140, for the reasons
// pkg/radius/fips.go measures and records. The key is 32 bytes so that a
// refusal is for the digest and not for a short key.
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

// refusedUnderFIPS reports whether validator is the YubiCloud validator and
// FIPS activation forbids it.
func refusedUnderFIPS(validator OTPValidator) bool {
	_, yubiCloud := validator.(*HTTPValidator)
	return yubiCloud && fips140OnlyActive()
}
