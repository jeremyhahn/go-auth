package ldapauth

import (
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// pw seals s into an enclave the test owns; the cleanup is a no-op for an
// enclave an authenticator has already destroyed.
func pw(t *testing.T, s string) *enclave.MemoryEnclave {
	t.Helper()
	e, err := enclave.NewMemoryEnclaveFromString(s)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveFromString: %v", err)
	}
	t.Cleanup(e.Destroy)
	return e
}
