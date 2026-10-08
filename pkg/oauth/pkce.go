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

// PKCE code verifier shape (RFC 7636 §4.1). The generated verifier is 32 random
// bytes rendered as unpadded base64url — 43 characters, the shortest the RFC
// admits, carrying the full 256 bits of entropy §7.1 asks for. The bounds apply
// to any verifier this package accepts, including one a caller built itself.
const (
	pkceVerifierBytes  = 32
	pkceVerifierLen    = 43 // base64.RawURLEncoding.EncodedLen(pkceVerifierBytes)
	pkceMinVerifierLen = 43
	pkceMaxVerifierLen = 128
)

// ErrVerifierConsumed indicates a PKCE code verifier was used a second time, or
// after it was destroyed. RFC 7636 gives a verifier exactly one authorization
// code to redeem, so a second use is a defect in the caller, a replay, or two
// callbacks racing for one login.
var ErrVerifierConsumed = errors.New("oauth: pkce code verifier already consumed")

// Verifier is a PKCE code verifier: a bearer credential for the length of an
// authorization-code flow, held in protected memory and redeemable exactly once.
//
// Whoever holds a verifier can redeem an intercepted authorization code, which
// is the attack PKCE exists to stop, so a Verifier never yields its value by
// return. The bytes live in a locked enclave and are read only inside a call
// that this type controls the lifetime of.
//
// Single use is enforced, not documented: ExchangeAuthorizationCodePKCE takes
// the sealed value out of the Verifier under a lock before it opens or sends
// anything, so two goroutines racing to redeem one verifier cannot both reach
// the token endpoint. The loser gets ErrVerifierConsumed.
//
// The zero value is not usable. A *Verifier is safe for concurrent use, and
// every method is safe to call on a nil *Verifier.
type Verifier struct {
	mu     sync.Mutex
	sealed *enclave.MemoryEnclave
}

// NewVerifier wraps a code verifier the caller already holds in an enclave and
// checks it against RFC 7636 §4.1.
//
// It is for an application that keeps its own sealed copy of a verifier — for
// example one restored from an encrypted session store into locked memory — and
// needs to redeem it with ExchangeAuthorizationCodePKCE. NewVerifier TAKES
// OWNERSHIP of codeVerifier on every return path: on success the Verifier owns
// it, and on error it is destroyed before NewVerifier returns.
//
// Nothing gives the value back out: there is no exported way to read a
// Verifier, because the only thing a verifier is for is the one exchange.
//
// Prefer BuildAuthURLPKCE, which generates the verifier straight into protected
// memory and never has any other form of it at all.
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

// open calls fn with the verifier inside an enclave session, without consuming
// it. It is unexported on purpose: deriving the challenge and asserting on the
// verifier in this package's own tests are the only things that should be able
// to see the bytes at all. There is no exported counterpart, deliberately.
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

// Destroy releases the verifier. It is idempotent, safe on a nil *Verifier, and
// safe to defer next to BuildAuthURLPKCE: the exchange consumes the verifier, so
// a deferred Destroy after a successful exchange is a no-op, and on every path
// that never reaches the exchange it is what ends the credential's life. The
// error is go-enclave's Destroy report: nil for an ordinary release.
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

// BuildAuthURLPKCE builds the authorization URL for the authorization code flow
// and returns the PKCE code verifier in protected memory.
//
// A code verifier is a bearer credential for the length of the flow: whoever holds it can redeem
// an intercepted authorization code, which is the entire attack PKCE exists to
// stop. This constructor generates it inside a locked enclave and derives the
// S256 challenge from the enclave, so the verifier has no plaintext form on the
// Go heap at any point.
//
// state should be a random value the caller keeps to defeat CSRF; it is not a
// secret and is carried in the URL.
//
// additionalParams may not set a parameter the library owns — including
// code_challenge and code_challenge_method, which would silently decouple the
// URL from the returned verifier and make the exchange fail later, at the token
// endpoint, for no visible reason. Those keys are rejected rather than applied.
//
// The returned verifier belongs to the caller. Pass it to
// ExchangeAuthorizationCodePKCE, which consumes it, and destroy it yourself on
// any path that never reaches the exchange — an abandoned login, a callback that
// fails its state check, a session that expires:
//
//	authURL, verifier, err := auth.BuildAuthURLPKCE(state, nil)
//	if err != nil {
//	    return err
//	}
//	defer verifier.Destroy() // no-op once the exchange has consumed it
//
// A Verifier cannot be written to an out-of-process session store: an enclave is
// process memory, not a serializable value, and nothing exported reads a
// Verifier's value back out. Hold it in an in-process map keyed by state.
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

// ExchangeAuthorizationCodePKCE exchanges an authorization code for tokens,
// taking the PKCE code verifier from protected memory.
//
// It is the counterpart of BuildAuthURLPKCE. The verifier is copied out of its
// enclave into a locked request body and never into an ordinary string.
//
// The verifier is consumed: this call takes it out of the Verifier under a lock
// before it opens or sends anything, and destroys it before returning — on
// success and on failure alike. RFC 7636 gives a verifier exactly one
// authorization code to redeem, so there is nothing a second call could
// legitimately do with it; taking it up front is also what stops two goroutines
// racing on one login from both reaching the token endpoint. The loser, and any
// later call, gets ErrVerifierConsumed wrapped in ErrTokenExchangeFailed.
// Verifier.Destroy is idempotent, so a caller's own defer remains correct.
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

// newPKCEVerifier generates a code verifier in protected memory and derives its
// S256 code challenge.
//
// The random bytes are read into a locked scratch enclave and base64url-encoded
// straight into the locked pages of the verifier's own enclave, which is then
// frozen, so neither the raw bytes nor their encoded form is ever written to
// ordinary heap.
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

// pkceChallenge derives the S256 code challenge (RFC 7636 §4.2) from a verifier
// held in protected memory.
//
// The digest is taken over the locked pages of the enclave; only the challenge
// leaves as a string, and a challenge is a public value that travels in the
// authorization URL by design.
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

// validatePKCEVerifier checks a verifier against RFC 7636 §4.1: 43 to 128
// characters drawn from the unreserved set ALPHA / DIGIT / "-" / "." / "_" / "~".
//
// The exchange depends on this check rather than on escaping. Every character
// admitted here is left untouched by application/x-www-form-urlencoded encoding,
// which is what lets the verifier be copied from its enclave straight into the
// request body: escaping it would mean allocating an escaped copy on the heap,
// and that copy is exactly what protecting the verifier is meant to prevent.
// Anything outside the set is rejected, never escaped.
//
// The verifier is not named in the error — it is the secret being checked.
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
