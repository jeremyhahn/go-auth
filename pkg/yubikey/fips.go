// FIPS activation gate for YubiCloud: its protocol requires HMAC-SHA-1, so HTTPValidator is disabled under GODEBUG=fips140=only; injected validators still work.

package yubikey

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- probes the primitive Yubico Validation Protocol 2.0 mandates; never used to protect anything
	"errors"
	"sync"
)

// ErrFIPSUnsupported reports that FIPS 140-only mode is active and the YubiCloud validator would be used; see docs/fips.md.
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
