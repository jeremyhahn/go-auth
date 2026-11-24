// Package credential holds shared helpers for go-enclave credentials, including the lend-as-string path registered in docs/security/credential-residues.md.
package credential

import (
	"errors"
	"unsafe"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Require returns missing for a nil enclave, and missing joined with enclave.ErrEnclaveDestroyed for a destroyed one.
func Require(e *enclave.MemoryEnclave, missing error) error {
	if e == nil {
		return missing
	}
	if !e.IsAlive() {
		return errors.Join(missing, enclave.ErrEnclaveDestroyed)
	}
	return nil
}

// DestroyAll destroys every enclave in es and folds any Destroy failure into err, which is returned unchanged when all succeed.
func DestroyAll(err error, es ...*enclave.MemoryEnclave) error {
	for _, e := range es {
		if derr := e.Destroy(); derr != nil {
			err = errors.Join(err, derr)
		}
	}
	return err
}

// WithTransientString lends e's material to fn as a string backed by a buffer zeroed on return; fn must not retain it or call methods on e.
func WithTransientString(e *enclave.MemoryEnclave, fn func(string) error) error {
	return e.WithBytes(func(b []byte) error {
		buf := make([]byte, len(b))
		copy(buf, b)
		defer enclave.Wipe(buf)
		// #nosec G103 -- the string aliases buf so that the wipe above reaches
		// the only copy this package makes; see the function comment.
		return fn(unsafe.String(unsafe.SliceData(buf), len(buf)))
	})
}
