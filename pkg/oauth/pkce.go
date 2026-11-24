package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
)

// PKCE verifier bounds (RFC 7636 §4.1); generated verifiers are 32 random bytes as 43 base64url characters.
const (
	pkceVerifierBytes  = 32
	pkceVerifierLen    = 43 // base64.RawURLEncoding.EncodedLen(pkceVerifierBytes)
	pkceMinVerifierLen = 43
	pkceMaxVerifierLen = 128
)

// ErrVerifierConsumed indicates a PKCE verifier used twice or after Destroy.
var ErrVerifierConsumed = errors.New("oauth: pkce code verifier already consumed")

// Verifier is a single-use PKCE code verifier held in a locked enclave; it never returns its value and is safe for concurrent use.
type Verifier struct {
	mu     sync.Mutex
	sealed *enclave.MemoryEnclave
}

// NewVerifier wraps a caller-held verifier enclave after checking RFC 7636 §4.1 and takes ownership of it on every path.
func NewVerifier(codeVerifier *enclave.MemoryEnclave) (*Verifier, error) {
	if err := codeVerifier.WithBytes(validatePKCEVerifier); err != nil {
		return nil, errors.Join(ErrInvalidConfiguration, credential.DestroyAll(err, codeVerifier))
	}

	return &Verifier{sealed: codeVerifier}, nil
}

// consume takes the sealed verifier out of v and hands ownership to the caller,
// which must destroy it. It is the single-use gate: exactly one caller can win,
// whatever the concurrency, and every later call reports ErrVerifierConsumed.
func (v *Verifier) consume() (*enclave.MemoryEnclave, error) {
	if v == nil {
		return nil, ErrVerifierConsumed
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.sealed == nil {
		return nil, ErrVerifierConsumed
	}

	sealed := v.sealed
	v.sealed = nil
	return sealed, nil
}

// open calls fn with the verifier bytes without consuming it; unexported on purpose.
func (v *Verifier) open(fn func(codeVerifier []byte) error) error {
	if v == nil {
		return ErrVerifierConsumed
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.sealed == nil {
		return ErrVerifierConsumed
	}
	return v.sealed.WithBytes(fn)
}

// Size reports the length of the verifier in characters, and 0 once it has been
// consumed or destroyed.
func (v *Verifier) Size() int {
	if v == nil {
		return 0
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	return v.sealed.Size()
}

// Destroy releases the verifier; idempotent and safe to defer next to BuildAuthURLPKCE.
func (v *Verifier) Destroy() error {
	sealed, err := v.consume()
	if err != nil {
		return nil
	}
	return sealed.Destroy()
}

// String renders a redaction rather than a value, so a stray %v, %s or log field
// cannot print a credential.
func (v *Verifier) String() string {
	return "oauth.Verifier(redacted)"
}

// GoString is String's counterpart for %#v.
func (v *Verifier) GoString() string {
	return "oauth.Verifier(redacted)"
}

// BuildAuthURLPKCE builds the authorization URL and returns a verifier generated in locked memory; the caller destroys it if the exchange never happens.
func (a *Authenticator) BuildAuthURLPKCE(state string, additionalParams map[string]string) (authURL string, verifier *Verifier, err error) {
	if a.config.Flow != FlowAuthorizationCode {
		return "", nil, fmt.Errorf("%w: authorization code flow not configured", ErrFlowNotSupported)
	}

	if a.flows == nil {
		return "", nil, fmt.Errorf("%w: flow handler not initialized", ErrInvalidConfiguration)
	}

	verifier, challenge, err := newVerifier()
	if err != nil {
		return "", nil, err
	}

	authURL, err = a.flows.buildAuthURL(state, challenge, additionalParams)
	if err != nil {
		if derr := verifier.Destroy(); derr != nil {
			err = errors.Join(err, derr)
		}
		return "", nil, err
	}

	return authURL, verifier, nil
}

// ExchangeAuthorizationCodePKCE exchanges a code using the verifier, consuming and destroying it; a second use gets ErrVerifierConsumed.
func (a *Authenticator) ExchangeAuthorizationCodePKCE(ctx context.Context, code string, verifier *Verifier) (token *Token, err error) {
	sealed, err := verifier.consume()
	if err != nil {
		// Both sentinels are wrapped: a caller reacting to a failed exchange
		// still needs to tell a replay from a network error.
		return nil, fmt.Errorf("%w: %w", ErrTokenExchangeFailed, err)
	}
	defer func() {
		derr := sealed.Destroy()
		if derr == nil {
			return
		}
		// A verifier that could not be wiped fails the exchange, and the token
		// it produced is destroyed rather than handed out.
		err = errors.Join(err, derr)
		if token != nil {
			err = errors.Join(err, token.Destroy())
			token = nil
		}
	}()

	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if a.config.Flow != FlowAuthorizationCode {
		return nil, fmt.Errorf("%w: authorization code flow not configured", ErrFlowNotSupported)
	}

	if a.flows == nil {
		return nil, fmt.Errorf("%w: flow handler not initialized", ErrInvalidConfiguration)
	}

	return a.flows.exchangeAuthorizationCodePKCE(ctx, code, sealed)
}

// newVerifier generates a code verifier and its S256 code challenge.
func newVerifier() (*Verifier, string, error) {
	sealed, challenge, err := newPKCEVerifier()
	if err != nil {
		return nil, "", err
	}
	return &Verifier{sealed: sealed}, challenge, nil
}

// newPKCEVerifier generates a verifier in locked memory and derives its S256 challenge.
func newPKCEVerifier() (*enclave.MemoryEnclave, string, error) {
	raw, err := enclave.NewMemoryEnclaveSized(pkceVerifierBytes)
	if err != nil {
		return nil, "", errors.Join(ErrInvalidConfiguration, err)
	}

	verifier, err := enclave.NewMemoryEnclaveSized(pkceVerifierLen)
	if err != nil {
		return nil, "", errors.Join(ErrInvalidConfiguration, credential.DestroyAll(err, raw))
	}

	err = raw.WithBytes(func(r []byte) error {
		if _, err := rand.Read(r); err != nil {
			return err
		}
		return verifier.WithBytes(func(v []byte) error {
			base64.RawURLEncoding.Encode(v, r)
			return nil
		})
	})
	if err == nil {
		err = verifier.Freeze()
	}
	if err != nil {
		return nil, "", errors.Join(ErrInvalidConfiguration, credential.DestroyAll(err, raw, verifier))
	}

	// The scratch held the raw random bytes: a failure to wipe it fails the
	// verifier, which is destroyed with it rather than handed out.
	if err := raw.Destroy(); err != nil {
		return nil, "", errors.Join(ErrInvalidConfiguration, credential.DestroyAll(err, verifier))
	}

	challenge, err := pkceChallenge(verifier)
	if err != nil {
		return nil, "", credential.DestroyAll(err, verifier)
	}

	return verifier, challenge, nil
}

// pkceChallenge derives the S256 challenge (RFC 7636 §4.2) inside the verifier's enclave.
func pkceChallenge(verifier *enclave.MemoryEnclave) (string, error) {
	var challenge string
	err := verifier.WithBytes(func(v []byte) error {
		if err := validatePKCEVerifier(v); err != nil {
			return err
		}
		sum := sha256.Sum256(v)
		challenge = base64.RawURLEncoding.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		return "", errors.Join(ErrInvalidConfiguration, err)
	}
	return challenge, nil
}

// validatePKCEVerifier checks RFC 7636 §4.1 length and unreserved characters, so the verifier needs no escaping; the error never names it.
func validatePKCEVerifier(v []byte) error {
	if len(v) < pkceMinVerifierLen || len(v) > pkceMaxVerifierLen {
		return fmt.Errorf("code verifier must be %d to %d characters, got %d",
			pkceMinVerifierLen, pkceMaxVerifierLen, len(v))
	}

	for _, c := range v {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return errors.New("code verifier holds a character outside the RFC 7636 unreserved set")
		}
	}

	return nil
}
