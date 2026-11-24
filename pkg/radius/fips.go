// FIPS activation gate: RADIUS needs MD5 and HMAC-MD5 (RFC 2865 §3, RFC 2869 §5.14), so it refuses to start under GODEBUG=fips140=only instead of panicking.

package radius

import (
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- probes the primitive RFC 2869 §5.14 mandates; never used to protect anything
	"errors"
	"sync"
)

// ErrFIPSUnsupported reports that FIPS 140-only mode is active, where RADIUS cannot operate; see docs/fips.md.
var ErrFIPSUnsupported = errors.New("radius: unavailable under FIPS 140-only mode: " +
	"RFC 2865 §3 authenticates every packet with MD5 and RFC 2869 §5.14 signs it with HMAC-MD5, " +
	"neither of which is an approved primitive")

// fips140OnlyActive reports whether HMAC-MD5 is refused; a variable so tests can drive both branches.
var fips140OnlyActive = sync.OnceValue(hmacMD5Unavailable)

// hmacMD5Unavailable runs one HMAC-MD5 with a 32-byte key and reports whether the runtime refused; fips140.Enabled() does not answer this.
func hmacMD5Unavailable() (unavailable bool) {
	defer func() {
		if recover() != nil {
			unavailable = true
		}
	}()

	mac := hmac.New(md5.New, make([]byte, 32))
	mac.Write([]byte("go-auth fips probe"))
	mac.Sum(nil)
	return false
}
