package yubikey

import (
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// sealed returns s in an enclave, or nil for the empty string, which is the
// "nothing supplied" case. The cleanup is a no-op for an enclave an
// authenticator has already destroyed.
func sealed(t *testing.T, s string) *enclave.MemoryEnclave {
	t.Helper()
	if s == "" {
		return nil
	}
	e, err := enclave.NewMemoryEnclaveFromString(s)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveFromString: %v", err)
	}
	t.Cleanup(e.Destroy)
	return e
}
