package otp

import (
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-auth/pkg/secret"
)

// NewProtectedSecret decodes a base32 shared secret into protected memory.
//
// It is the constructor for Config.SecretKey and the replacement for putting
// the same value in Config.Secret. Nothing about the key reaches ordinary
// heap: the encoded text is copied into a locked scratch buffer, normalized
// there, and decoded from there straight into the locked buffer that is then
// sealed. base32.DecodeString, which is what the string path reaches for,
// would instead hand back a plaintext slice for the collector to keep — and so
// would the strings.ToUpper and []byte conversion an ordinary normalization
// step needs.
//
// base32Secret itself is a Go string and cannot be wiped. This constructor
// therefore narrows an existing exposure — a secret read from a configuration
// file or a database — rather than eliminating it. Use GenerateProtectedSecret
// for a key this process is creating, which has no plaintext string form at
// all until something asks for one.
//
// Padding is optional and the input is upper-cased, matching what the string
// path accepted and what provisioning tools emit.
func NewProtectedSecret(base32Secret string) (*secret.Secret, error) {
	trimmed := trimBase32(base32Secret)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: secret must not be empty", ErrInvalidConfig)
	}

	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)

	var sec *secret.Secret
	err := secret.Scratch(len(trimmed), func(encoded []byte) error {
		// Upper-case in place rather than with strings.ToUpper, which would
		// allocate a second copy of the encoded secret on the heap.
		n := 0
		for i := 0; i < len(trimmed); i++ {
			c := trimmed[i]
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			encoded[n] = c
			n++
		}
		encoded = encoded[:n]

		decoded, err := secret.NewWith(encoding.DecodedLen(len(encoded)), func(buf []byte) (int, error) {
			written, err := encoding.Decode(buf, encoded)
			if err != nil {
				return 0, fmt.Errorf("%w: secret must be valid base32: %v", ErrInvalidConfig, err)
			}
			return written, nil
		})
		if err != nil {
			return err
		}
		sec = decoded
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sec, nil
}

// GenerateProtectedSecret generates a cryptographically random 160-bit shared
// secret in protected memory. It is the protected counterpart of
// GenerateSecret: the same key strength, RFC 4226 §4 R6's recommendation
// comfortably exceeded, but the key is written straight into the enclave and
// never has a plaintext form on the heap.
//
// Callers that need the base32 text to enroll the key — a QR code, a recovery
// slip, an encrypted column in a database — get it from
// Authenticator.GetProvisioningURI or EncodeSecret, which are explicit about
// producing a copy that cannot be wiped.
func GenerateProtectedSecret() (*secret.Secret, error) {
	return secret.NewRandom(20)
}

// EncodeSecret renders a protected key back into the unpadded base32 form used
// by provisioning URIs and by Config.Secret.
//
// This deliberately takes the key out of protected memory: the result is an
// immutable Go string that cannot be wiped and lives until the collector
// reclaims it. It exists for the two moments that genuinely need the encoded
// form — enrolling a newly generated key with the user, and persisting it —
// and should not be used to feed the key back into an API that takes a string.
func EncodeSecret(key *secret.Secret) (string, error) {
	if key == nil {
		return "", fmt.Errorf("%w: secret must not be nil", ErrInvalidConfig)
	}

	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	var encoded string
	err := key.Open(func(k []byte) error {
		return secret.Scratch(encoding.EncodedLen(len(k)), func(buf []byte) error {
			encoding.Encode(buf, k)
			encoded = string(buf)
			return nil
		})
	})
	if err != nil {
		return "", fmt.Errorf("otp: encode secret: %w", err)
	}
	return encoded, nil
}

// trimBase32 returns base32Secret without surrounding whitespace or trailing
// padding. It slices the input rather than building a new string, so no copy
// of the encoded secret is made: the result shares the caller's backing array,
// which the caller already holds.
func trimBase32(base32Secret string) string {
	trimmed := strings.TrimSpace(base32Secret)
	return strings.TrimRight(trimmed, "=")
}

// generateProtected derives a code from the sealed key. It is Generate's
// protected-secret branch.
func (a *Authenticator) generateProtected(counter uint64) (string, error) {
	var code string
	err := a.key.Open(func(key []byte) error {
		derived, err := deriveCode(key, counter, a.cfg.Digits, a.cfg.Algorithm)
		if err != nil {
			return err
		}
		code = derived
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("otp: failed to generate code: %w", err)
	}
	return code, nil
}

// authenticateProtectedTOTP validates a TOTP code against the sealed key. It
// is the protected-secret branch of Authenticate.
func (a *Authenticator) authenticateProtectedTOTP(code string, now time.Time) error {
	var valid bool
	err := a.key.Open(func(key []byte) error {
		var err error
		valid, err = validateTOTP(key, code, now, a.cfg.Period, a.cfg.Skew, a.cfg.Digits, a.cfg.Algorithm)
		return err
	})
	if err != nil {
		return fmt.Errorf("%w: validation failed: %v", ErrInvalidCode, err)
	}
	if !valid {
		return ErrInvalidCode
	}
	return nil
}

// authenticateProtectedHOTP validates an HOTP code at counter against the
// sealed key. It is the protected-secret branch of Authenticate and
// ValidateCounter.
func (a *Authenticator) authenticateProtectedHOTP(code string, counter uint64) error {
	derived, err := a.generateProtected(counter)
	if err != nil {
		return fmt.Errorf("%w: validation failed: %v", ErrInvalidCode, err)
	}
	if !codesMatch(derived, code) {
		return ErrInvalidCode
	}
	return nil
}

// provisioningSecret returns the base32 secret for the provisioning URI,
// whichever path the authenticator was built on. A sealed key that cannot be
// opened — because the caller destroyed it, or because memguard's session was
// purged — is an error rather than an empty parameter: a URI without a usable
// secret looks enrollable and is not.
func (a *Authenticator) provisioningSecret() (string, error) {
	if a.key == nil {
		return a.cfg.Secret, nil
	}
	return EncodeSecret(a.key)
}
