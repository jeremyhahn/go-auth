// FIPS activation gate.
//
// Every binary is built FIPS-capable and FIPS is activated at deployment with
// GODEBUG=fips140=only. There is no approved TACACS+: RFC 8907 §4.5 obfuscates
// every packet body with an MD5 keystream, the only body encoding it defines
// for production use. When FIPS is activated TACACS+ is refused at startup with
// a typed error instead of panicking inside crypto/md5 on the first
// authentication. Same shape as pkg/radius/fips.go.

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
