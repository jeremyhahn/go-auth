// FIPS activation gate for the YubiCloud validator.
//
// Every binary is built FIPS-capable and FIPS is activated at deployment with
// GODEBUG=fips140=only. Yubico Validation Protocol 2.0 signs every request and
// response with HMAC-SHA-1, which fips140=only refuses, so the YubiCloud
// validator (HTTPValidator) is disabled with ErrFIPSUnsupported. An injected
// OTPValidator that speaks to an approved validation service keeps working.
// Without the gate the package default would panic inside crypto/hmac on the
// first OTP. Mirrors pkg/radius/fips.go.

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

// refusedUnderFIPS reports whether validator is the YubiCloud validator and
// FIPS activation forbids it.
func refusedUnderFIPS(validator OTPValidator) bool {
	_, yubiCloud := validator.(*HTTPValidator)
	return yubiCloud && fips140OnlyActive()
}
