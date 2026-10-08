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

// GenerateProtectedSecret generates a cryptographically random 160-bit seed
// directly into a locked enclave. The key never exists anywhere else: the
// enclave is allocated at its final size, crypto/rand fills the locked pages
// in place inside WithBytes, and the pages are frozen read-only before this
// returns.
//
// The caller owns the result until it hands it to NewAuthenticator in
// Config.Seed, which takes ownership. Callers that need the base32 text to
// enroll the seed — a QR code, a recovery slip, an encrypted column — get it
// from Authenticator.ProvisioningURI or EncodeSecret, which are explicit about
// producing a copy that cannot be wiped.
//
// A refusal to lock memory surfaces as enclave.ErrLockedMemoryUnavailable;
// there is no fallback to ordinary memory.
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

// DecodeSeed decodes a base32 seed — the form a provisioning URI carries and
// the form most stores persist — into a locked enclave.
//
// Nothing about the key reaches ordinary heap: the encoded text is copied into
// a locked scratch enclave, upper-cased there, and decoded from there straight
// into the locked pages of the enclave that is returned. base32.DecodeString
// would instead hand back a plaintext slice for the collector to keep — and so
// would the strings.ToUpper and []byte conversion an ordinary normalization
// step needs.
//
// encoded itself is a Go string and cannot be wiped. That is the one residue,
// and it is the caller's: a seed read from a configuration file or a database
// already exists in that form. Use GenerateProtectedSecret for a seed this
// process is creating, which has no string form at all until something asks
// for one.
//
// Padding is optional and the input is case-insensitive, matching what
// provisioning tools emit. An unpadded final group that encodes whole bytes is
// accepted for the same reason; one too short to encode a whole byte is not,
// and is the one case Go's unpadded decoder would discard silently.
func DecodeSeed(encoded string) (*enclave.MemoryEnclave, error) {
	trimmed := trimBase32(encoded)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: seed must not be empty", ErrInvalidConfig)
	}

	// Go's unpadded decoder discards a trailing group too short to encode a
	// whole byte rather than rejecting it, so "<seed>A" decodes to exactly the
	// key "<seed>" does. A seed carrying a stray character would then be
	// accepted here and produce codes the enrolled authenticator never agrees
	// with — a failure at every login, with nothing at construction to say why.
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
		// Upper-case in place rather than with strings.ToUpper, which would
		// allocate a second copy of the encoded seed on the heap.
		//
		// Every character is checked against the alphabet here, before the
		// output is sized: Go's decoder skips CR and LF without counting them,
		// so an embedded newline would leave zero bytes past the decoded seed
		// in a buffer sized from the input length -- a longer key than the one
		// enrolled, and one that could pass the FIPS minimum it does not meet.
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

// EncodeSecret renders a seed as unpadded base32, the form a provisioning URI
// and most persistent stores carry. It borrows the seed and leaves it alive.
//
// This deliberately takes the key out of protected memory: the result is an
// immutable Go string that cannot be wiped and lives until the collector
// reclaims it. It exists for the two moments that genuinely need the encoded
// form — showing a newly generated seed to the user to enroll, and persisting
// it — and is the documented residue of both. The encoding itself happens in a
// locked scratch enclave, so the string is the only unprotected copy.
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

// trimBase32 returns encoded without surrounding whitespace or trailing
// padding. It slices the input rather than building a new string, so no copy
// of the encoded seed is made: the result shares the caller's backing array,
// which the caller already holds.
func trimBase32(encoded string) string {
	return strings.TrimRight(strings.TrimSpace(encoded), "=")
}
