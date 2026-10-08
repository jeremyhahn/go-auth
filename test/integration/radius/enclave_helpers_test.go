//go:build integration

package radius_test

import (
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// sealed returns s in an enclave, or nil for the empty string, which is the
// "nothing supplied" case. The cleanup is a no-op for an enclave an
// authenticator has already taken over and destroyed.
func sealed(t *testing.T, s string) *enclave.MemoryEnclave {
	t.Helper()
	if s == "" {
		return nil
	}
	e, err := enclave.NewMemoryEnclave([]byte(s))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	t.Cleanup(func() {
		if err := e.Destroy(); err != nil {
			t.Errorf("Destroy: %v", err)
		}
	})
	return e
}
