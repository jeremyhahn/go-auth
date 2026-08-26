//go:build linux

package secret

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/sys/unix"
)

// TestConstructorFailsClosedWhenLockedMemoryExhausted is the direct regression
// for go-auth #21. The memguard backing this replaced mapped a fresh locked
// buffer on every Open and, on hitting RLIMIT_MEMLOCK, purged every protected
// buffer in the process and panicked the goroutine that tripped it — a
// login-path DoS, since login is reachable before authentication. go-enclave
// instead fails the allocating constructor with a typed error and touches no
// other secret. This test lowers RLIMIT_MEMLOCK so a lock cannot succeed and
// requires each constructor to return enclave.ErrLockedMemoryUnavailable rather
// than crash.
func TestConstructorFailsClosedWhenLockedMemoryExhausted(t *testing.T) {
	// No t.Parallel: this changes a process-global limit. The secret package's
	// tests run sequentially, and the deferred restore returns the limit before
	// the next test.
	var orig unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &orig); err != nil {
		t.Skipf("cannot read RLIMIT_MEMLOCK: %v", err)
	}
	// Lowering the soft limit is always permitted; raising it back to the same
	// hard limit in the deferred restore is too.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 0, Max: orig.Max}); err != nil {
		t.Skipf("cannot lower RLIMIT_MEMLOCK (need CAP_SYS_RESOURCE to restore, or a permissive host): %v", err)
	}
	defer func() {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &orig); err != nil {
			t.Errorf("failed to restore RLIMIT_MEMLOCK to %+v: %v", orig, err)
		}
	}()

	// Several whole pages, so a kernel that permits a page or two of slack at a
	// zero limit still cannot satisfy the lock.
	large := bytes.Repeat([]byte("k"), 256*1024)

	assertLocked := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Skipf("%s: host locked memory at RLIMIT_MEMLOCK=0; cannot exercise the exhaustion path here", name)
		}
		if !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
			t.Fatalf("%s under exhausted RLIMIT_MEMLOCK = %v, want enclave.ErrLockedMemoryUnavailable", name, err)
		}
	}

	_, err := New(append([]byte(nil), large...))
	assertLocked("New", err)

	_, err = NewWith(len(large), func(buf []byte) (int, error) { return copy(buf, large), nil })
	assertLocked("NewWith", err)

	err = Scratch(len(large), func([]byte) error {
		t.Fatal("Scratch ran its callback despite locked-memory exhaustion")
		return nil
	})
	assertLocked("Scratch", err)
}
