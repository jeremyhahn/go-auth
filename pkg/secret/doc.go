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
// A Secret is a go-enclave MemoryEnclave: the value lives in page-aligned,
// mlock(2)ed, non-swappable memory, fenced between inaccessible guard pages
// with a canary and marked MADV_DONTDUMP so it is excluded from core dumps. It
// is read only through a borrow held under the enclave's lock, for the duration
// of one Open call. The region is held for the secret's whole lifetime rather
// than re-mapped per Open, so a repeated or concurrent Open allocates no locked
// memory.
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
// An enclave locks its pages with mlock(2), which is bounded by RLIMIT_MEMLOCK.
// Locked memory is allocated once, when a Secret is constructed, and released
// when it is destroyed — not per Open. The requirement therefore scales with
// the number of secrets held, a small and bounded figure, and NOT with the
// number of in-flight authentications: an authentication borrows the region the
// secret already holds and allocates nothing. This is the difference that
// closes the login-path memlock-exhaustion DoS (go-auth #21), where the
// previous memguard backing mapped a fresh locked buffer on every Open and, on
// exhausting the limit, purged every protected buffer in the process and
// panicked. go-enclave instead returns a typed error matching
// enclave.ErrLockedMemoryUnavailable from the constructor, touching no other
// secret.
//
// Deployments should still raise RLIMIT_MEMLOCK above the kernel default rather
// than discover it under load: size it for the credentials held plus headroom.
// The default 8 MiB holds far more small secrets than a single process needs,
// but a container image that drops the limit to a few pages can starve
// construction, and that now fails closed with an error instead of crashing.
//
// There is no process-wide purge. Wiping every enclave at shutdown is a
// deliberate, ordered act that belongs to the program owning the process
// lifetime (go-enclave's WipeAll), never to a library; this package destroys
// only the secrets it is handed, when their holders release them.
package secret
