package otp

import (
	"crypto/hmac"
	// SHA-1 is protocol-mandated here (RFC 4226 §5.1, RFC 6238 §1.2) and used only in HMAC.
	"crypto/sha1" // #nosec G505 -- RFC 4226 §5.1 defines HOTP over HMAC-SHA-1
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"time"
)

// RFC 4226 / RFC 6238 core: codes are derived from the seed borrowed inside WithBytes; crypto/hmac's ipad/opad state is the one unwipeable copy.

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

// deriveCode implements RFC 4226 §5.3 dynamic truncation over a borrowed key, re-checking FIPS before HMAC is keyed.
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

// codesMatch compares a borrowed submitted code with a derived one in constant time.
func codesMatch(derived string, submitted []byte) bool {
	if len(derived) != len(submitted) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(derived), submitted) == 1
}

// totpCounter converts a time to the RFC 6238 §4.2 time-step counter with T0 = 0.
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

// maxSkew bounds the TOTP window in steps either side of now; a wide window extends replay and costs an HMAC per step.
const maxSkew = 10

// validateTOTP checks every step within skew of t (RFC 6238 §5.2) without stopping early, so timing does not reveal the matching step.
func validateTOTP(key, code []byte, t time.Time, period, skew, digits uint, algo Algorithm) (bool, error) {
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
