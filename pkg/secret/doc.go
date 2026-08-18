// Package secret holds credential material in protected memory.
//
// # The rule
//
// Every key, password, shared secret and token this module holds for longer
// than a single call lives in a Secret, and is released when the component
// holding it is done with it. It is never kept in a Go string, and never in a
// plain []byte on the heap. A string cannot be wiped at all; a heap []byte can
// be wiped only if every copy of it is accounted for, and it can be paged to
// swap or captured in a core dump before that happens.
//
// A Secret is a memguard enclave: the value is encrypted at rest under a
// session key held in locked, guarded, non-swappable memory, and is decrypted
// only for the duration of one Open call, into a locked buffer that is wiped
// and unmapped before Open returns.
//
//	sec, err := secret.NewString(os.Getenv("RADIUS_SECRET"))
//	if err != nil {
//	    return err
//	}
//	defer sec.Destroy()
//
//	err = sec.Open(func(key []byte) error {
//	    // key is valid here and nowhere else.
//	    return send(newPacket(key))
//	})
//
// # Choosing a constructor
//
// NewWith and NewRandom never let the plaintext reach ordinary heap: the value
// is produced directly inside the locked buffer that is then sealed. Prefer
// them when this module is the one creating or decoding the key —
// otp.GenerateProtectedSecret and otp.NewProtectedSecret are both built on
// them.
//
// New takes ownership of a []byte and wipes it, which is the right constructor
// for a key read from a file or a network response into a buffer the caller
// controls.
//
// NewString is the migration bridge for a credential that is already in a Go
// string, which is where most configuration arrives. The string itself cannot
// be wiped, so this narrows an exposure rather than removing it; the enclave
// still limits the value's residency to the moments it is in use, and it keeps
// the credential out of every struct dump and log line in between.
//
// # What it does not defend against
//
// An attacker who can execute code in this process, or attach a debugger to
// it, can wait for an Open and read the buffer. Protected memory is a defense
// against a value's *residency* — swap, core dumps, crash reporters, heap
// snapshots, and the long tail of copies a garbage-collected runtime leaves
// behind — not against a live adversary inside the address space.
//
// Values derived from a secret are not covered by it either. A Secret protects
// the key; the packet it authenticates, the code it derives, and any copy a
// third-party library takes are outside the enclave.
//
// # Operational requirements
//
// memguard locks its pages with mlock(2), which is bounded by RLIMIT_MEMLOCK.
// Exhausting that limit is fatal: memguard purges the session and panics
// rather than continuing with a page that could be swapped. One locked
// allocation is made per concurrent Open and freed at the end of it, so the
// requirement scales with in-flight authentications, not with the number of
// secrets held. Deployments that authenticate concurrently should raise the
// limit — 64 MiB is generous — rather than discover it under load. A container
// with the default 8 MiB has room for roughly two thousand simultaneous opens.
//
// Purge is exposed for the shutdown path. It wipes the session key, which
// invalidates every Secret in the process, so it belongs to the program that
// owns the process lifetime and never to a library.
package secret
