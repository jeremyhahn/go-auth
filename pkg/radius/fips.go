// FIPS activation gate.
//
// Company FIPS boundary ruling 1 (2026-08-20) is one artifact for both markets:
// every binary is built FIPS-capable and FIPS is *activated at deployment*
// with GODEBUG=fips140=only. Product ruling 7 says what an interop surface does
// when that happens — restrict to approved options, or be "disabled with a
// clear typed error", naming the RADIUS-MD5 backend as the disabled case.
//
// This file is that gate. It exists because there is no approved RADIUS: RFC
// 2865 §3 authenticates every packet with MD5 and RFC 2869 §5.14 signs it with
// HMAC-MD5, and RadSec (RFC 6614) only wraps the same packet in TLS. Without
// the gate a FIPS-activated deployment configured for RADIUS starts happily and
// panics inside crypto/hmac on the first Access-Request — a runtime crash on a
// login path instead of a refusal at startup.
//
// It is the only FIPS mechanism in this package. There is no FIPS-only build
// shape: ruling 1's single artifact contains RADIUS and refuses to run it when
// FIPS is activated.

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

// fips140OnlyActive reports whether this process refuses HMAC-MD5.
//
// It is a variable so that the tests can drive both branches without a second
// process; production code never assigns it.
var fips140OnlyActive = sync.OnceValue(hmacMD5Unavailable)

// hmacMD5Unavailable computes one HMAC-MD5 over a fixed non-secret input and
// reports whether the runtime refused.
//
// The alternative — crypto/fips140.Enabled() — answers a different question and
// gives the wrong answer to this one. Measured on go1.26.6:
//
//	build              GODEBUG           Enabled()   HMAC-MD5
//	plain              (none)            false       ok
//	plain              fips140=on        true        ok
//	plain              fips140=only      true        panics
//	GOFIPS140=latest   (none)            true        ok
//	GOFIPS140=latest   fips140=on        true        ok
//	GOFIPS140=latest   fips140=only      true        panics
//
// Enabled() reports that the FIPS module is in use, which under ruling 1 is
// true of every binary the company ships whether or not FIPS was activated.
// Gating on it would disable RADIUS in every deployment, including the ones
// entitled to it. Reading GODEBUG from the environment would miss a //go:debug
// directive compiled into the main package. Go 1.26's Enforced() does
// distinguish `only` from `on`, but it reports whether enforcement is on for
// the calling goroutine (WithoutEnforcement switches it off inside a callback)
// and says nothing about which primitives the runtime refuses. Executing the
// primitive is the signal that measures the condition the backend actually
// depends on, whatever set it.
//
// The key is 32 bytes deliberately: under fips140=only a shorter one panics
// first for its length, which would make the probe report the right answer for
// the wrong reason and hide a future change in what the runtime rejects.
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
