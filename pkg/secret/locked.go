package secret

import (
	"errors"
	"sync"

	"github.com/jeremyhahn/go-enclave"
)

// ErrLockedDestroyed indicates the locked buffer was released by Destroy.
var ErrLockedDestroyed = errors.New("secret: locked buffer has been destroyed")

// Locked is credential material held in a locked buffer that stays readable
// for as long as the Locked itself does.
//
// It is the answer for a value that has to be readable by code which offers no
// scope to read it in — a third-party client that keeps the key for the life of
// a connection and uses it from goroutines it does not join. A Secret cannot
// serve that: its plaintext exists only inside an Open, and a caller that kept
// the slice past the call would be reading unmapped memory. The alternative,
// handing such code an ordinary heap copy, puts the plaintext where it can be
// swapped, dumped, and duplicated by the collector.
//
// The buffer is page-aligned and mlock(2)ed, so the kernel will not page it to
// swap, is marked MADV_DONTDUMP so it is excluded from core dumps, and sits
// between two inaccessible guard pages with a canary. It is not sealed the way
// a Secret is: the plaintext is resident for the lifetime of the Locked, which
// is the price of it being readable at a moment the holder does not choose. The
// pages stay writable — as the memguard buffer this replaced did — so a stray
// write through the exposed slice corrupts the material rather than faulting;
// treat Bytes as read-only.
//
// Prefer Secret. Reach for Locked only where a dependency's lifetime makes
// Secret unusable, and say in a comment which dependency and why.
//
// A *Locked is safe for concurrent use; the bytes it exposes are as safe as
// their reader makes them.
type Locked struct {
	mu      sync.RWMutex
	enclave *enclave.MemoryEnclave
}

// Lock copies the secret into a locked buffer and returns it.
//
// The Secret is untouched and can still be opened; the returned Locked is an
// independent, longer-lived view of the same value, and the caller owns it.
// Destroy it when the component holding it is done — but not while anything
// may still read the bytes, since Destroy unmaps them.
func (s *Secret) Lock() (*Locked, error) {
	if s == nil {
		return nil, ErrNilSecret
	}

	var locked *Locked
	err := s.Open(func(key []byte) error {
		// A sized enclave is locked, writable memory; copy the secret's bytes
		// into it in place so the plaintext never reaches ordinary heap. This
		// borrow runs inside the Secret's own borrow, which go-enclave permits:
		// the two enclaves have independent locks.
		e, cerr := enclave.NewMemoryEnclaveSized(len(key))
		if cerr != nil {
			return cerr
		}
		if werr := e.WithBytes(func(dst []byte) error {
			copy(dst, key)
			return nil
		}); werr != nil {
			e.Destroy()
			return werr
		}
		locked = &Locked{enclave: e}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return locked, nil
}

// Bytes returns the locked buffer's contents.
//
// The slice is valid until Destroy, which unmaps it: a reader that outlives
// the Locked faults rather than reading stale bytes, so the lifetime of a
// Locked must cover every goroutine that can reach these bytes. Bytes returns
// nil once the buffer has been destroyed, but that does not help a caller who
// kept an earlier slice.
func (l *Locked) Bytes() []byte {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.enclave == nil || !l.enclave.IsAlive() {
		return nil
	}
	// Open hands back a view that aliases the locked pages and outlives the
	// enclave's lock — exactly the long-lived readability Locked promises. It is
	// safe here because only this Locked's Destroy unmaps these pages, and the
	// library never calls the process-wide sweep that is Open's other hazard.
	b, err := l.enclave.Open()
	if err != nil {
		return nil
	}
	return b
}

// Size reports the length of the value in bytes. A nil or destroyed Locked
// reports 0.
func (l *Locked) Size() int {
	if l == nil {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.enclave == nil {
		return 0
	}
	return l.enclave.Size()
}

// Destroy wipes and unmaps the buffer. It is idempotent and safe to call on a
// nil *Locked.
//
// Call it only when nothing can still be reading Bytes: this unmaps the pages,
// so a live reader faults the process rather than reading stale bytes. Where
// the readers belong to a dependency that does not join them, there is no such
// moment, and the honest answer is not to offer a release at all — that is
// what pkg/tacacs does — rather than to expose one whose safety the caller
// cannot establish.
func (l *Locked) Destroy() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// A nil *MemoryEnclave Destroys as a no-op, so the idempotent case is safe.
	l.enclave.Destroy()
	l.enclave = nil
}

// String renders a redaction rather than the value, so a stray %v or %s cannot
// print a credential.
func (l *Locked) String() string {
	return "secret.Locked(redacted)"
}

// GoString is String's counterpart for %#v.
func (l *Locked) GoString() string {
	return "secret.Locked(redacted)"
}
