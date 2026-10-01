package credential

import (
	"errors"
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

var errMissing = errors.New("test: credential required")

func TestRequire(t *testing.T) {
	live, err := enclave.NewMemoryEnclaveFromString("pw")
	if err != nil {
		t.Fatalf("NewMemoryEnclaveFromString: %v", err)
	}
	defer live.Destroy()

	dead, err := enclave.NewMemoryEnclaveFromString("pw")
	if err != nil {
		t.Fatalf("NewMemoryEnclaveFromString: %v", err)
	}
	dead.Destroy()

	if err := Require(live, errMissing); err != nil {
		t.Fatalf("Require(live) = %v, want nil", err)
	}
	if err := Require(nil, errMissing); !errors.Is(err, errMissing) || errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("Require(nil) = %v, want only the missing sentinel", err)
	}
	err = Require(dead, errMissing)
	if !errors.Is(err, errMissing) || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("Require(destroyed) = %v, want the missing sentinel joined with ErrEnclaveDestroyed", err)
	}
}

// TestWithTransientStringWipesTheCopy proves the one heap copy a string-only
// dependency forces is zeroed when the borrow ends: a reference retained past
// fn reads zeros, not the credential.
func TestWithTransientStringWipesTheCopy(t *testing.T) {
	e, err := enclave.NewMemoryEnclaveFromString("hunter2")
	if err != nil {
		t.Fatalf("NewMemoryEnclaveFromString: %v", err)
	}
	defer e.Destroy()

	var retained string
	if err := WithTransientString(e, func(s string) error {
		if s != "hunter2" {
			t.Fatalf("fn saw %q, want the credential", s)
		}
		retained = s
		return nil
	}); err != nil {
		t.Fatalf("WithTransientString: %v", err)
	}

	if retained != strings.Repeat("\x00", len("hunter2")) {
		t.Fatalf("retained string = %q after the borrow, want zeros", retained)
	}
	if !e.IsAlive() {
		t.Fatal("WithTransientString destroyed a borrowed enclave")
	}
}

func TestWithTransientStringPropagatesErrors(t *testing.T) {
	e, err := enclave.NewMemoryEnclaveFromString("pw")
	if err != nil {
		t.Fatalf("NewMemoryEnclaveFromString: %v", err)
	}
	defer e.Destroy()

	sentinel := errors.New("fn failed")
	var retained string
	err = WithTransientString(e, func(s string) error {
		retained = s
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want fn's error", err)
	}
	if retained != "\x00\x00" {
		t.Fatalf("retained string = %q after a failed borrow, want zeros", retained)
	}

	e.Destroy()
	called := false
	err = WithTransientString(e, func(string) error { called = true; return nil })
	if !errors.Is(err, enclave.ErrEnclaveDestroyed) || called {
		t.Fatalf("destroyed enclave: err = %v, called = %v; want ErrEnclaveDestroyed and no call", err, called)
	}
}
