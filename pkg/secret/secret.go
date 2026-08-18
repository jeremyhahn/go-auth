package secret

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/awnumar/memguard"
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
	// zero-length secret is always a configuration mistake, and memguard
	// cannot allocate a zero-length buffer for one either.
	ErrEmpty = errors.New("secret: value must not be empty")
	// ErrOpen indicates the sealed value could not be decrypted. It is
	// returned after memguard's session key has been rotated by Purge, which
	// invalidates every Secret created before the call.
	ErrOpen = errors.New("secret: cannot open sealed value")
)

// Secret is credential material — a key, password, shared secret or token —
// held in protected memory for its whole lifetime.
//
// The value is sealed in a memguard enclave: encrypted at rest under a session
// key that itself lives in locked, guarded, non-swappable memory. It is
// decrypted only for the duration of a single Open call, into a locked buffer
// that is wiped and unmapped before Open returns. No method exposes the
// plaintext by return value, so it cannot outlive the call that asked for it.
//
// The zero value is not usable; construct one with New, NewString, NewRandom
// or NewWith. A *Secret is safe for concurrent use.
type Secret struct {
	mu      sync.RWMutex
	enclave *memguard.Enclave
	size    int
}

// New seals b and returns it as a Secret.
//
// b is wiped before New returns: the caller hands over ownership of the bytes
// rather than sharing them, which is what keeps a second, unprotected copy
// from surviving the call. Callers that still need the value afterwards must
// open the returned Secret for it.
func New(b []byte) (*Secret, error) {
	if len(b) == 0 {
		return nil, ErrEmpty
	}
	size := len(b)
	// NewEnclave wipes the source slice as part of sealing it.
	return &Secret{enclave: memguard.NewEnclave(b), size: size}, nil
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

	buf := memguard.NewBuffer(size)
	defer buf.Destroy()

	n, err := fill(buf.Bytes())
	if err != nil {
		return nil, err
	}
	if n < 1 {
		return nil, ErrEmpty
	}
	if n > size {
		return nil, fmt.Errorf("secret: fill wrote %d bytes into a %d byte buffer", n, size)
	}

	// NewEnclave copies out of the locked buffer and wipes what it copied;
	// the deferred Destroy wipes and unmaps the rest.
	return &Secret{enclave: memguard.NewEnclave(buf.Bytes()[:n]), size: n}, nil
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

	buf := memguard.NewBuffer(size)
	defer buf.Destroy()

	return fn(buf.Bytes())
}

// Open decrypts the secret into a locked buffer, calls fn with it, and
// destroys the buffer before returning — including when fn panics or returns
// an error.
//
// The slice fn receives is valid only for the duration of the call. Retaining
// it, or anything that aliases it, is a use-after-free of unmapped memory
// rather than a stale read, so anything derived from the key that must outlive
// fn has to be copied out deliberately — and is then the caller's to protect.
func (s *Secret) Open(fn func(key []byte) error) error {
	if s == nil {
		return ErrNilSecret
	}
	if fn == nil {
		return errors.New("secret: open function must not be nil")
	}

	s.mu.RLock()
	enclave := s.enclave
	s.mu.RUnlock()

	if enclave == nil {
		return ErrDestroyed
	}

	buf, err := enclave.Open()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOpen, err)
	}
	defer buf.Destroy()

	return fn(buf.Bytes())
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

// Destroy releases the secret. Subsequent calls to Open return ErrDestroyed,
// and Size reports 0. It is idempotent and safe to call on a nil *Secret, so
// it works as a defer next to construction.
//
// The plaintext is not waiting to be wiped by this call: it only ever exists
// inside the locked buffer of an in-flight Open, which that Open destroys.
// What Destroy drops is the sealed value and the ability to open it again. The
// session key that the ciphertext was sealed under is wiped by Purge, which
// belongs to the program's shutdown path.
func (s *Secret) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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

// Purge wipes memguard's session key and every locked buffer in the process,
// then installs a fresh key. It belongs in a program's shutdown path — after
// it returns, every Secret created before the call fails to open with ErrOpen,
// including secrets held by other libraries in the same process.
//
// This is deliberately not called by any authenticator in this module: which
// goroutine owns process shutdown is the application's decision, not a
// library's.
func Purge() {
	memguard.Purge()
}
