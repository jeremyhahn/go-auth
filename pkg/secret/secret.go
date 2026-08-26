package secret

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-enclave"
)

// Errors returned by this package.
var (
	// ErrNilSecret indicates a nil *Secret was used.
	ErrNilSecret = errors.New("secret: secret is nil")
	// ErrDestroyed indicates the secret cannot be opened because it was
	// released by Destroy, or because it is a zero-value Secret that was
	// never sealed by a constructor.
	ErrDestroyed = errors.New("secret: secret has been destroyed")
	// ErrEmpty indicates an empty value was offered to a constructor. A
	// zero-length secret is always a configuration mistake, and an enclave
	// cannot hold a zero-length value either.
	ErrEmpty = errors.New("secret: value must not be empty")
)

// Secret is credential material — a key, password, shared secret or token —
// held in protected memory for its whole lifetime.
//
// The value lives in a go-enclave MemoryEnclave: page-aligned, mlock(2)ed so it
// is never paged to swap, marked MADV_DONTDUMP so it is excluded from core
// dumps, and fenced between inaccessible guard pages with a canary. It is read
// only through a borrow held under the enclave's own lock, and no method exposes
// the plaintext by return value, so it cannot outlive the call that asked for
// it.
//
// Unlike the memguard enclave this package used before, a MemoryEnclave holds
// its locked region for its whole lifetime rather than decrypting into a fresh
// locked buffer on every Open. A repeated or concurrent Open therefore allocates
// no locked memory, and an mlock failure surfaces as a typed error from the
// constructor — never as a process-wide purge that would destroy every other
// secret in the process and panic the caller. That is what closes the
// login-path memlock-exhaustion DoS (go-auth #21).
//
// The zero value is not usable; construct one with New, NewString, NewRandom
// or NewWith. A *Secret is safe for concurrent use.
type Secret struct {
	mu      sync.RWMutex
	enclave *enclave.MemoryEnclave
	size    int
}

// New seals b and returns it as a Secret.
//
// b is wiped before New returns: the caller hands over ownership of the bytes
// rather than sharing them, which is what keeps a second, unprotected copy
// from surviving the call. Callers that still need the value afterwards must
// open the returned Secret for it.
//
// It returns ErrEmpty for an empty value and, when the kernel refuses to lock
// the pages, an error matching enclave.ErrLockedMemoryUnavailable — the caller
// can test for it with errors.Is.
func New(b []byte) (*Secret, error) {
	if len(b) == 0 {
		return nil, ErrEmpty
	}
	size := len(b)
	// NewMemoryEnclave takes ownership of b and wipes it, including on the
	// locked-memory-refusal path, so no unprotected copy survives this call.
	e, err := enclave.NewMemoryEnclave(b)
	if err != nil {
		return nil, err
	}
	return &Secret{enclave: e, size: size}, nil
}

// NewString seals the bytes of s and returns them as a Secret.
//
// It exists to migrate call sites that already hold a credential in a Go
// string — configuration files, environment variables, existing exported
// APIs. A string is immutable and cannot be wiped, so the caller's copy stays
// in memory until the collector reclaims it: this constructor limits the
// exposure of a value already in the clear, it does not undo it. Prefer New,
// NewRandom or NewWith, which never let the plaintext reach ordinary heap.
func NewString(s string) (*Secret, error) {
	if s == "" {
		return nil, ErrEmpty
	}
	return New([]byte(s))
}

// NewRandom seals size bytes read from crypto/rand.
//
// The random bytes are generated directly into protected memory, so a key
// created this way has no plaintext copy on the Go heap at any point.
func NewRandom(size int) (*Secret, error) {
	return NewWith(size, func(buf []byte) (int, error) {
		if _, err := rand.Read(buf); err != nil {
			return 0, fmt.Errorf("secret: read random bytes: %w", err)
		}
		return len(buf), nil
	})
}

// NewWith seals a value produced in place.
//
// It allocates a locked buffer of size bytes, passes it to fill, and seals the
// first n bytes that fill reports written. The buffer is wiped and unmapped
// before NewWith returns, whatever fill does. Use it for values derived from
// an encoded form — a base32 OTP seed, a base64 API key — so the decoded key
// is written straight into protected memory instead of a heap slice that has
// to be remembered about later.
//
// size is an upper bound: fill may report fewer bytes, as a decoder that
// allowed for padding does.
func NewWith(size int, fill func(buf []byte) (n int, err error)) (*Secret, error) {
	if size < 1 {
		return nil, ErrEmpty
	}
	if fill == nil {
		return nil, errors.New("secret: fill function must not be nil")
	}

	// A sized enclave is locked, writable memory the caller fills in place; the
	// material never touches ordinary heap. It is scratch here: the sealed
	// Secret is a second enclave holding exactly the n bytes fill produced, so
	// a fill that wrote fewer than size bytes (base32 padding) does not leave
	// trailing zeros in the secret.
	scratch, err := enclave.NewMemoryEnclaveSized(size)
	if err != nil {
		return nil, err
	}
	defer scratch.Destroy()

	var sealed *Secret
	err = scratch.WithBytes(func(buf []byte) error {
		n, ferr := fill(buf)
		if ferr != nil {
			return ferr
		}
		if n < 1 {
			return ErrEmpty
		}
		if n > size {
			return fmt.Errorf("secret: fill wrote %d bytes into a %d byte buffer", n, size)
		}
		// NewMemoryEnclave copies buf[:n] into its own locked region and wipes
		// buf[:n] as it goes; scratch.Destroy wipes whatever is left.
		e, cerr := enclave.NewMemoryEnclave(buf[:n])
		if cerr != nil {
			return cerr
		}
		sealed = &Secret{enclave: e, size: n}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sealed, nil
}

// Scratch calls fn with a locked buffer of size bytes, wiped and unmapped
// before Scratch returns.
//
// It is the counterpart to NewWith for a value that is only wanted for the
// length of one operation: decoding a sealed API key out of its base64
// transport form to key an HMAC, for instance, where the decoded key must
// never touch ordinary heap but does not need to be sealed itself.
func Scratch(size int, fn func(buf []byte) error) error {
	if size < 1 {
		return ErrEmpty
	}
	if fn == nil {
		return errors.New("secret: scratch function must not be nil")
	}

	e, err := enclave.NewMemoryEnclaveSized(size)
	if err != nil {
		return err
	}
	defer e.Destroy()

	return e.WithBytes(fn)
}

// Open calls fn with the sealed value and returns fn's error.
//
// The slice fn receives is a borrow of the locked pages, valid only for the
// duration of the call: the enclave holds its read lock across fn, so a
// concurrent Destroy waits rather than unmapping the pages underneath it.
// Retaining the slice, or anything that aliases it, is a use-after-free once
// the borrow ends, so anything derived from the key that must outlive fn has to
// be copied out deliberately — and is then the caller's to protect.
//
// Open allocates no locked memory: it borrows the region the secret already
// holds. A destroyed or zero-value Secret returns ErrDestroyed.
func (s *Secret) Open(fn func(key []byte) error) error {
	if s == nil {
		return ErrNilSecret
	}
	if fn == nil {
		return errors.New("secret: open function must not be nil")
	}

	s.mu.RLock()
	e := s.enclave
	s.mu.RUnlock()

	if e == nil {
		return ErrDestroyed
	}

	// WithBytes returns fn's error unchanged, so an errors.Is check on its
	// return cannot tell an enclave-destroyed REFUSAL (fn never ran) from a fn
	// that itself returned enclave.ErrEnclaveDestroyed. Track whether fn ran:
	// WithBytes calls fn only when the region is live, so ran==false is the
	// only case that is genuinely a destroyed enclave — one that this Secret's
	// snapshot missed because a concurrent Destroy raced in. When fn ran, its
	// error is returned verbatim, whatever it is.
	ran := false
	var fnErr error
	err := e.WithBytes(func(key []byte) error {
		ran = true
		fnErr = fn(key)
		return fnErr
	})
	if !ran {
		if errors.Is(err, enclave.ErrEnclaveDestroyed) {
			return ErrDestroyed
		}
		return err
	}
	return fnErr
}

// OpenString calls fn with the secret as a Go string.
//
// It is the boundary escape hatch, for third-party APIs that take a credential
// as a string and cannot be given bytes — go-ldap's Bind is the case this
// package was written around. The string is an immutable heap copy that cannot
// be wiped: it is unreachable once fn returns, but it survives until the
// collector reclaims it, and it may be duplicated by the callee. Use Open
// wherever the callee accepts a []byte.
func (s *Secret) OpenString(fn func(key string) error) error {
	if fn == nil {
		return errors.New("secret: open function must not be nil")
	}
	return s.Open(func(key []byte) error {
		return fn(string(key))
	})
}

// Size reports the length of the sealed value in bytes. It is the one property
// of the secret that can be read without opening it, because callers need it
// for the strength checks a policy makes at construction time. A nil or
// destroyed Secret reports 0.
func (s *Secret) Size() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.enclave == nil {
		return 0
	}
	return s.size
}

// Destroy releases the secret, wiping and unmapping its locked pages.
// Subsequent calls to Open return ErrDestroyed, and Size reports 0. It is
// idempotent and safe to call on a nil *Secret, so it works as a defer next to
// construction.
//
// Unlike the memguard-backed version this replaced, Destroy actually zeroizes:
// a MemoryEnclave holds its plaintext for its whole lifetime, so dropping the
// reference is not enough — Destroy wipes the pages and hands them back to the
// kernel. Leaking the reference instead would keep the credential resident and
// hold a locked-memory reservation for the life of the process.
func (s *Secret) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Release the region BEFORE dropping the handle. MemoryEnclave.Destroy
	// panics if it cannot unmap the pages, and deliberately keeps the mapping
	// alive so the release can be retried; dropping the reference first would
	// strand that locked, still-resident region for the life of the process.
	// A nil *MemoryEnclave Destroys as a no-op, so the idempotent and
	// never-sealed cases fall through safely. Only once Destroy returns do we
	// detach.
	s.enclave.Destroy()
	s.enclave = nil
	s.size = 0
}

// String renders the secret as a redaction rather than a value, so that a
// stray %v, %s or structured-log field cannot print a credential. There is no
// formatting verb that yields the plaintext; Open is the only way to reach it.
func (s *Secret) String() string {
	return "secret.Secret(redacted)"
}

// GoString is String's counterpart for %#v, which formats a struct field by
// field and would otherwise print the enclave's internals.
func (s *Secret) GoString() string {
	return "secret.Secret(redacted)"
}
