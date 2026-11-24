package otp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
)

// seedBytes is the length of a generated seed: 160 bits, RFC 4226 §4 R6's
// recommendation, the HMAC-SHA-1 output size, and comfortably above the
// 112-bit HMAC key floor FIPS 140-3 sets.
const seedBytes = 20

// seedEncoding is the base32 form provisioning URIs carry: RFC 4648 alphabet,
// no padding, per the Key URI Format's "secret" parameter.
var seedEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateProtectedSecret generates a random 160-bit seed directly into a locked, frozen enclave owned by the caller.
func GenerateProtectedSecret() (*enclave.MemoryEnclave, error) {
	seed, err := enclave.NewMemoryEnclaveSized(seedBytes)
	if err != nil {
		return nil, err
	}
	if err := seed.WithBytes(func(b []byte) error {
		_, err := rand.Read(b)
		return err
	}); err != nil {
		return nil, credential.DestroyAll(err, seed)
	}
	if err := seed.Freeze(); err != nil {
		return nil, credential.DestroyAll(err, seed)
	}
	return seed, nil
}

// DecodeSeed decodes a case-insensitive, optionally padded base32 seed into a locked enclave without a heap copy; encoded itself is the caller's residue.
func DecodeSeed(encoded string) (*enclave.MemoryEnclave, error) {
	trimmed := trimBase32(encoded)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: seed must not be empty", ErrInvalidConfig)
	}

	// Reject a trailing group too short for a whole byte, which Go's unpadded decoder would silently drop.
	if n := len(trimmed) % 8; n == 1 || n == 3 || n == 6 {
		return nil, fmt.Errorf("%w: seed must be valid base32: it ends in %d "+
			"characters that do not encode a whole byte", ErrInvalidConfig, n)
	}

	scratch, err := enclave.NewMemoryEnclaveSized(len(trimmed))
	if err != nil {
		return nil, err
	}
	var seed *enclave.MemoryEnclave
	err = scratch.WithBytes(func(text []byte) error {
		// Upper-case in place and check every character first, so CR/LF cannot leave padding bytes in the key.
		for i := range len(trimmed) {
			c := trimmed[i]
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
				return fmt.Errorf("%w: seed must be valid base32: "+
					"character at offset %d is outside the alphabet", ErrInvalidConfig, i)
			}
			text[i] = c
		}

		decoded, err := enclave.NewMemoryEnclaveSized(seedEncoding.DecodedLen(len(text)))
		if err != nil {
			return err
		}
		if err := decoded.WithBytes(func(dst []byte) error {
			n, err := seedEncoding.Decode(dst, text)
			if err != nil {
				return fmt.Errorf("%w: seed must be valid base32: %w", ErrInvalidConfig, err)
			}
			// The alphabet check above makes this unreachable today; it stays
			// so that the seed can never carry bytes the input did not encode.
			if n != len(dst) {
				return fmt.Errorf("%w: seed must be valid base32: decoded %d of %d bytes",
					ErrInvalidConfig, n, len(dst))
			}
			return nil
		}); err != nil {
			return credential.DestroyAll(err, decoded)
		}
		if err := decoded.Freeze(); err != nil {
			return credential.DestroyAll(err, decoded)
		}
		seed = decoded
		return nil
	})
	// The scratch holds the upper-cased encoding: a failure to wipe it fails
	// the decode, and the seed built beside it is not handed out.
	if err = credential.DestroyAll(err, scratch); err != nil {
		return nil, credential.DestroyAll(err, seed)
	}
	return seed, nil
}

// EncodeSecret renders a borrowed seed as unpadded base32; the returned string is an unwipeable copy for enrollment or storage.
func EncodeSecret(seed *enclave.MemoryEnclave) (string, error) {
	if seed == nil {
		return "", fmt.Errorf("%w: seed must not be nil", ErrInvalidConfig)
	}

	var encoded string
	err := seed.WithBytes(func(key []byte) error {
		scratch, err := enclave.NewMemoryEnclaveSized(seedEncoding.EncodedLen(len(key)))
		if err != nil {
			return err
		}
		err = scratch.WithBytes(func(buf []byte) error {
			seedEncoding.Encode(buf, key)
			// Residue: the caller needs the text to render a QR code or store it.
			encoded = string(buf)
			return nil
		})
		return credential.DestroyAll(err, scratch)
	})
	if err != nil {
		return "", err
	}
	return encoded, nil
}

// trimBase32 slices encoded to drop surrounding whitespace and trailing padding without copying.
func trimBase32(encoded string) string {
	return strings.TrimRight(strings.TrimSpace(encoded), "=")
}
