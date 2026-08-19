package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-auth/pkg/secret"
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
// return. The bytes live in a memguard enclave and are read only inside a call
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
	sealed *secret.Secret
}

// NewVerifier seals an existing code verifier and checks it against RFC 7636
// §4.1.
//
// It is the migration path: an application still on the deprecated string form
// of the flow — BuildAuthURL with usePKCE, or a verifier it already has in a
// session — seals it here and redeems it with ExchangeAuthorizationCodePKCE.
//
// This constructor only takes plaintext in. Nothing gives it back out: there is
// no exported way to read a Verifier's value, because a Go string cannot be
// wiped and an escape hatch that produced one would undo what the enclave is
// for. Sealing a value that is already in the clear narrows an exposure that has
// already happened; handing one out would create a new one.
//
// Prefer BuildAuthURLPKCE, which generates the verifier straight into protected
// memory and never has a string form of it at all.
func NewVerifier(codeVerifier string) (*Verifier, error) {
	if err := validatePKCEVerifier([]byte(codeVerifier)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfiguration, err)
	}

	sealed, err := secret.NewString(codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("%w: sealing PKCE code verifier: %v", ErrInvalidConfiguration, err)
	}

	return &Verifier{sealed: sealed}, nil
}

// consume takes the sealed verifier out of v and hands ownership to the caller,
// which must destroy it. It is the single-use gate: exactly one caller can win,
// whatever the concurrency, and every later call reports ErrVerifierConsumed.
func (v *Verifier) consume() (*secret.Secret, error) {
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
	return v.sealed.Open(fn)
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
// that never reaches the exchange it is what ends the credential's life.
func (v *Verifier) Destroy() {
	sealed, err := v.consume()
	if err != nil {
		return
	}
	sealed.Destroy()
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
// It is the replacement for BuildAuthURL(state, true, params). A code verifier
// is a bearer credential for the length of the flow: whoever holds it can redeem
// an intercepted authorization code, which is the entire attack PKCE exists to
// stop. This constructor generates it inside a memguard enclave and derives the
// S256 challenge from the enclave, so the verifier has no plaintext form on the
// Go heap at any point — unlike the string BuildAuthURL has to return.
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
// Verifier's value back out. Hold it in an in-process map keyed by state. An
// application that cannot do that is on the deprecated string flow — BuildAuthURL
// with usePKCE — until the coordinated breaking release; NewVerifier seals what
// it gets back so the redemption half is at least protected.
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
		verifier.Destroy()
		return "", nil, err
	}

	return authURL, verifier, nil
}

// ExchangeAuthorizationCodePKCE exchanges an authorization code for tokens,
// taking the PKCE code verifier from protected memory.
//
// It is the replacement for ExchangeAuthorizationCode(ctx, code, verifierString)
// and the counterpart of BuildAuthURLPKCE. The verifier is copied out of its
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
func (a *Authenticator) ExchangeAuthorizationCodePKCE(ctx context.Context, code string, verifier *Verifier) (*Token, error) {
	sealed, err := verifier.consume()
	if err != nil {
		// Both sentinels are wrapped: a caller reacting to a failed exchange
		// still needs to tell a replay from a network error.
		return nil, fmt.Errorf("%w: %w", ErrTokenExchangeFailed, err)
	}
	defer sealed.Destroy()

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
// The random bytes are read into a locked scratch buffer and base64url-encoded
// straight into the locked buffer that is then sealed, so neither the raw bytes
// nor their encoded form is ever written to ordinary heap.
func newPKCEVerifier() (*secret.Secret, string, error) {
	verifier, err := secret.NewWith(pkceVerifierLen, func(buf []byte) (int, error) {
		err := secret.Scratch(pkceVerifierBytes, func(raw []byte) error {
			if _, err := rand.Read(raw); err != nil {
				return fmt.Errorf("%w: generating PKCE code verifier: %v", ErrInvalidConfiguration, err)
			}
			base64.RawURLEncoding.Encode(buf, raw)
			return nil
		})
		if err != nil {
			return 0, err
		}
		return pkceVerifierLen, nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("%w: sealing PKCE code verifier: %v", ErrInvalidConfiguration, err)
	}

	challenge, err := pkceChallenge(verifier)
	if err != nil {
		verifier.Destroy()
		return nil, "", err
	}

	return verifier, challenge, nil
}

// pkceChallenge derives the S256 code challenge (RFC 7636 §4.2) from a verifier
// held in protected memory.
//
// The digest is taken over the locked buffer of an open enclave; only the
// challenge leaves as a string, and a challenge is a public value that travels
// in the authorization URL by design.
func pkceChallenge(verifier *secret.Secret) (string, error) {
	var challenge string
	err := verifier.Open(func(v []byte) error {
		if err := validatePKCEVerifier(v); err != nil {
			return err
		}
		sum := sha256.Sum256(v)
		challenge = base64.RawURLEncoding.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("%w: deriving PKCE code challenge: %v", ErrInvalidConfiguration, err)
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

// generatePKCE generates a code verifier and challenge as strings.
//
// It backs BuildAuthURL's exported string signature and nothing else. The
// verifier is generated in protected memory exactly as BuildAuthURLPKCE's is,
// but OpenString then copies it into an immutable Go string that cannot be wiped
// and survives until the collector reclaims it. That copy is the reason the
// string path is deprecated.
func generatePKCE() (verifier, challenge string, err error) {
	sealed, challenge, err := newPKCEVerifier()
	if err != nil {
		return "", "", err
	}
	defer sealed.Destroy()

	if err := sealed.OpenString(func(v string) error {
		verifier = v
		return nil
	}); err != nil {
		return "", "", fmt.Errorf("%w: reading PKCE code verifier: %v", ErrInvalidConfiguration, err)
	}

	return verifier, challenge, nil
}
