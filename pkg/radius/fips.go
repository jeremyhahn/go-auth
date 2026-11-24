// FIPS activation gate.
//
// Every binary is built FIPS-capable and FIPS is activated at deployment with
// GODEBUG=fips140=only. There is no approved RADIUS: RFC 2865 §3 authenticates
// every packet with MD5, RFC 2869 §5.14 signs it with HMAC-MD5, and RadSec
// (RFC 6614) only wraps the same packet in TLS. When FIPS is activated the
// RADIUS backend is refused at startup with a typed error instead of panicking
// inside crypto/hmac on the first Access-Request. This is the only FIPS
// mechanism in this package; there is no FIPS-only build.

package radius

import (
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- probes the primitive RFC 2869 §5.14 mandates; never used to protect anything
	"errors"
	"sync"
)

// ErrFIPSUnsupported reports that the process is running under Go's FIPS
// 140-only mode, in which the RADIUS backend cannot operate at all.
//
// Every RADIUS packet carries an MD5 Request/Response Authenticator (RFC 2865
// §3) and an HMAC-MD5 Message-Authenticator (RFC 2869 §5.14), so there is no
// configuration, transport or option that avoids the primitive — RadSec
// included. A caller that must authenticate under FIPS 140-3 uses a different
// backend; see docs/fips.md.
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
