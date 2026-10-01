// Package credential holds the two helpers every go-auth backend shares for
// credentials held in go-enclave memory: the argument check, and the one
// sanctioned way to lend a credential to a dependency that only accepts a Go
// string.
//
// Every credential in go-auth is a *enclave.MemoryEnclave. Backends borrow
// the plaintext through WithBytes, which scopes it to a callback over the
// locked pages. A few third-party APIs take a string and nothing else —
// go-ldap's Bind, tacplus's Continue, msteinert/pam's conversation reply and
// miekg/pkcs11's Login. WithTransientString is the shape those sites use, and
// docs/security/credential-residues.md registers each of them.
package credential

import (
	"errors"
	"unsafe"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Require reports whether e is usable as a credential argument.
//
// A nil enclave returns missing unchanged, so the caller's sentinel keeps
// meaning "nothing was supplied". A destroyed enclave returns missing joined
// with enclave.ErrEnclaveDestroyed: the caller supplied a credential and
// then gave up its material, which is a lifecycle bug on their side rather
// than an absent field, and errors.Is can tell the two apart.
//
// go-enclave refuses to build an enclave over empty material
// (enclave.ErrEmptyEnclave), so a live enclave is never empty and there is no
// third case to check.
func Require(e *enclave.MemoryEnclave, missing error) error {
	if e == nil {
		return missing
	}
	if !e.IsAlive() {
		return errors.Join(missing, enclave.ErrEnclaveDestroyed)
	}
	return nil
}

// WithTransientString lends fn the material of e as a Go string, for the one
// call into a dependency that accepts nothing else, and wipes that string's
// bytes when fn returns.
//
// The string is backed by a heap buffer this function allocates, fills from
// inside e.WithBytes and zeroes before returning, on every path. Converting
// with string(b) or calling OpenString would leave an immutable copy behind
// until the collector reuses it; this leaves a buffer of zeros. What it cannot
// reach is whatever the dependency copies out of the string during the call —
// a BER packet, a C.CString, a protocol buffer. Those copies are the residue
// each call site names.
//
// The string must not outlive fn. The sites that use this were checked at
// their pinned versions to copy the string synchronously and keep no
// reference; a reference that survived anyway would read zeros rather than
// the credential, which is the safe failure. The bytes are mutated after the
// string has been handed out, which Go's string immutability does not
// anticipate, so a dependency that used the string as a map key across the
// call would break — none of the registered ones does.
//
// fn runs while e's read lock is held: it must not call methods on e, and a
// Destroy of e waits for fn to return. e is borrowed and is not destroyed.
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
