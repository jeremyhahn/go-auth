package otp

import (
	"crypto/hmac"
	// SHA-1 here is protocol-mandated, not a cipher choice: RFC 4226 §5.1
	// defines HOTP as HMAC-SHA-1 and RFC 6238 §1.2 keeps it as the TOTP
	// default, which is what every mainstream authenticator app enrolls with.
	// It is used only for HMAC, never as a bare hash, and SHA-1 collisions do
	// not carry over to HMAC-SHA1.
	"crypto/sha1" // #nosec G505 -- RFC 4226 §5.1 defines HOTP over HMAC-SHA-1
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"time"
)

// This file is the RFC 4226 / RFC 6238 core: HOTP and TOTP derived in-repo
// from the seed's raw bytes.
//
// It takes the seed as a []byte borrowed from the enclave's WithBytes, so the
// plaintext key is never anywhere but the enclave's locked pages: the
// authenticator opens the enclave, derives a code, and the borrow ends before
// the call returns. A dependency that took the seed as a string — as
// github.com/pquerna/otp did — would have put a fresh decoded copy on the heap
// per authentication; that is why this package derives codes itself.
//
// The one copy that remains is crypto/hmac's: New derives its ipad/opad blocks
// from the key and holds them in the hash state until the collector reclaims
// it. That is inside the Go Cryptographic Module and there is no API to wipe
// it; re-implementing HMAC to avoid it would move the construction outside the
// FIPS boundary, which is a worse trade than one short-lived derivative. The
// hash state here is a local of deriveCode and is unreachable the moment it
// returns.

// hashes maps each supported Algorithm to its digest constructor. It is also
// the set of algorithms the package accepts.
var hashes = map[Algorithm]func() hash.Hash{
	AlgorithmSHA1:   sha1.New,
	AlgorithmSHA256: sha256.New,
	AlgorithmSHA512: sha512.New,
}

// digitsModulus maps each supported code length to 10^digits. It is also the
// set of lengths the package accepts: RFC 4226 §5.3 requires a code of at
// least six digits and names seven and eight as the alternatives.
var digitsModulus = map[uint]uint32{
	6: 1_000_000,
	7: 10_000_000,
	8: 100_000_000,
}

// deriveCode implements the HOTP construction of RFC 4226 §5.3: HMAC the
// counter as a 8-byte big-endian value under the shared seed, take the
// dynamic-truncation offset from the low nibble of the last byte of the MAC,
// read a 31-bit integer from there, and render it modulo 10^digits.
//
// key is borrowed for the duration of the call and is neither retained nor
// copied.
//
// The FIPS check runs here as well as in NewAuthenticator. Construction is
// where a refused configuration is reported, but this is the only place HMAC
// is keyed, so the guard sits beside it: no path that reaches crypto/hmac —
// including one added later that forgets to validate — can reach the panic
// fips140=only raises for SHA-1 or a short key.
func deriveCode(key []byte, counter uint64, digits uint, algo Algorithm) (string, error) {
	if len(key) == 0 {
		return "", fmt.Errorf("%w: seed must not be empty", ErrInvalidConfig)
	}
	modulus, ok := digitsModulus[digits]
	if !ok {
		return "", fmt.Errorf("%w: digits must be 6, 7, or 8", ErrInvalidConfig)
	}
	newHash, ok := hashes[algo]
	if !ok {
		return "", fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidConfig, algo)
	}
	if err := checkFIPS(algo, len(key)); err != nil {
		return "", err
	}

	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	mac := hmac.New(newHash, key)
	mac.Write(counterBytes[:])
	sum := mac.Sum(nil)
	// The MAC is not the key, but it is derived from it under a counter the
	// caller controls; it has served its purpose by the time this returns.
	defer clear(sum)

	// RFC 4226 §5.4: the offset is the low nibble of the final byte, and the
	// four bytes read from it are always within the digest — SHA-1's 20 bytes
	// are the shortest case and 15+4 is the furthest this can reach.
	offset := sum[len(sum)-1] & 0x0f
	truncated := uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	return fmt.Sprintf("%0*d", digits, truncated%modulus), nil
}

// codesMatch compares a submitted code against a derived one in constant time.
// Lengths are compared first because ConstantTimeCompare returns 0 for a
// length mismatch without looking at the contents, which would leak nothing
// but is worth being explicit about.
func codesMatch(derived, submitted string) bool {
	if len(derived) != len(submitted) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(derived), []byte(submitted)) == 1
}

// totpCounter converts a time to the TOTP time-step counter of RFC 6238 §4.2,
// with T0 = 0.
func totpCounter(t time.Time, period uint) uint64 {
	if period == 0 {
		period = 30
	}
	// T0 is the Unix epoch, so a time before it has no time step. Converting
	// the negative second count would wrap to the top of the uint64 range and
	// validate against a window nobody can reach.
	seconds := t.UTC().Unix()
	if seconds < 0 {
		return 0
	}
	return uint64(seconds) / uint64(period)
}

// maxSkew bounds the TOTP validation window, in time steps either side of the
// current one.
//
// RFC 6238 §5.2 asks for the smallest window a deployment can tolerate, and
// names one step as what it expects; this package defaults to one. The limit
// exists for two reasons. A large window is a security choice made by
// accident: at the default 30-second step, ten steps already accept a code
// five minutes old, and a code that stays valid is a code that can be replayed
// or phished and used. And the window is also work — every step is an HMAC
// over the key — so an unbounded Skew turns a configuration mistake into an
// authentication call that occupies its goroutine indefinitely.
//
// Clock drift measured in minutes is a clock problem: run NTP rather than
// widen this.
const maxSkew = 10

// validateTOTP checks code against every time step within skew of t, as
// RFC 6238 §5.2 permits for network and clock drift.
//
// Every candidate is evaluated: the loop does not stop at the first match, so
// the work done is the same whether the code was right, wrong, or right at the
// edge of the window. That keeps the response time from reporting which step
// matched, which is a small amount of information about the client's clock.
func validateTOTP(key []byte, code string, t time.Time, period, skew, digits uint, algo Algorithm) (bool, error) {
	// Config.validate rejects anything above maxSkew, so this clamp is for the
	// callers that do not go through it — and so that no arithmetic below
	// depends on a bound established somewhere else.
	if skew > maxSkew {
		skew = maxSkew
	}
	window := uint64(skew)

	counter := totpCounter(t, period)

	// Guard the subtraction: a counter within skew of the epoch would wrap to
	// the top of the uint64 range and check a window nobody asked for.
	first := uint64(0)
	if counter > window {
		first = counter - window
	}

	matched := false
	for i := uint64(0); i <= 2*window; i++ {
		c := first + i
		if c < first {
			// Past the top of the counter range. Unreachable from a time.Time,
			// which cannot produce a counter within maxSkew of MaxUint64, but
			// the loop must not depend on that to terminate.
			break
		}

		derived, err := deriveCode(key, c, digits, algo)
		if err != nil {
			return false, err
		}
		if codesMatch(derived, code) {
			matched = true
		}
	}
	return matched, nil
}
