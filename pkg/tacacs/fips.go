// FIPS activation gate: TACACS+ needs an MD5 keystream (RFC 8907 §4.5), so it refuses to start under GODEBUG=fips140=only instead of panicking.

package tacacs

import (
	"crypto/md5" // #nosec G501 -- probes the primitive RFC 8907 §4.5 mandates; never used to protect anything
	"errors"
	"sync"
)

// ErrFIPSUnsupported reports that FIPS 140-only mode is active, where TACACS+ cannot operate; see docs/fips.md.
var ErrFIPSUnsupported = errors.New("tacacs: unavailable under FIPS 140-only mode: " +
	"RFC 8907 §4.5 obfuscates every packet body with an MD5 keystream, " +
	"which is not an approved primitive")

// fips140OnlyActive reports whether MD5 is refused; a variable so tests can drive both branches.
var fips140OnlyActive = sync.OnceValue(md5Unavailable)

// md5Unavailable runs one bare MD5 and reports whether the runtime refused, as tacplus would hit.
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
