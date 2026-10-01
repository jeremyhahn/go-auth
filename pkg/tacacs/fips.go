// FIPS activation gate.
//
// Company FIPS boundary ruling 1 (2026-08-20) is one artifact for both markets:
// every binary is built FIPS-capable and FIPS is *activated at deployment*
// with GODEBUG=fips140=only. Product ruling 7 says what an interop surface does
// when that happens — restrict to approved options, or be "disabled with a
// clear typed error".
//
// This file is that gate, and it has the same shape as pkg/radius/fips.go
// because the reason is the same: there is no approved TACACS+. RFC 8907 §4.5
// obfuscates every packet body with an MD5 keystream, and it is the only body
// encoding the protocol defines for production use (its unencrypted flag is a
// test-only option RFC 8907 says must not be used in production). Without the gate a
// FIPS-activated deployment configured for TACACS+ starts happily and panics
// inside crypto/md5 on the first authentication — a runtime crash on a login
// path instead of a refusal at startup.

package tacacs

import (
	"crypto/md5" // #nosec G501 -- probes the primitive RFC 8907 §4.5 mandates; never used to protect anything
	"errors"
	"sync"
)

// ErrFIPSUnsupported reports that the process is running under Go's FIPS
// 140-only mode, in which the TACACS+ backend cannot operate at all.
//
// Every TACACS+ packet body is obfuscated with an MD5 keystream (RFC 8907
// §4.5), so there is no configuration or option that avoids the primitive. A
// caller that must authenticate under FIPS 140-3 uses a different backend; see
// docs/fips.md.
var ErrFIPSUnsupported = errors.New("tacacs: unavailable under FIPS 140-only mode: " +
	"RFC 8907 §4.5 obfuscates every packet body with an MD5 keystream, " +
	"which is not an approved primitive")

// fips140OnlyActive reports whether this process refuses MD5.
//
// It is a variable so that the tests can drive both branches without a second
// process; production code never assigns it.
var fips140OnlyActive = sync.OnceValue(md5Unavailable)

// md5Unavailable computes one MD5 over a fixed non-secret input and reports
// whether the runtime refused.
//
// It executes the primitive rather than asking crypto/fips140, for the reasons
// pkg/radius/fips.go measures and records: Enabled() is true of every binary
// built with GOFIPS140 whether or not FIPS was activated, and the primitive is
// the condition this backend actually depends on, whatever set it. The probe
// mirrors the keystream's own use — a bare digest, not an HMAC — so it fails
// exactly when tacplus would.
func md5Unavailable() (unavailable bool) {
	defer func() {
		if recover() != nil {
			unavailable = true
		}
	}()

	h := md5.New() // #nosec G401 -- probe only; see above
	h.Write([]byte("go-auth fips probe"))
	h.Sum(nil)
	return false
}
