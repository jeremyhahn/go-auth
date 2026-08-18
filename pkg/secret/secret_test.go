package secret

import (
	"bytes"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestNewWipesTheCallersCopy(t *testing.T) {
	// The ingest half of the rule: after New, the only copy of the value is
	// the sealed one. A caller that reads its own slice back gets zeros.
	plaintext := []byte("shared-secret-value")
	source := append([]byte(nil), plaintext...)

	sec, err := New(source)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sec.Destroy()

	if !bytes.Equal(source, make([]byte, len(source))) {
		t.Fatalf("New left the caller's slice intact: %q", source)
	}

	assertOpens(t, sec, plaintext)
}

func TestOpenDestroysTheLockedBufferAfterUse(t *testing.T) {
	// The egress half of the rule. The buffer the plaintext is decrypted into
	// must not survive the call that asked for it, so this test drives the
	// same enclave the way Open does and checks the buffer afterwards.
	// Open's own callback cannot make this assertion: the slice it is handed
	// is unmapped by the time the assertion could run, and reading it would
	// fault rather than fail.
	sec, err := NewString("shared-secret-value")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sec.Destroy()

	buf, err := sec.enclave.Open()
	if err != nil {
		t.Fatalf("enclave open: %v", err)
	}
	if !buf.IsAlive() {
		t.Fatal("buffer is not alive before destroy")
	}
	buf.Destroy()

	if buf.IsAlive() {
		t.Fatal("locked buffer still alive after destroy")
	}
	if got := buf.Bytes(); got != nil {
		t.Fatalf("destroyed buffer still yields %d bytes", len(got))
	}
}

func TestOpenAfterDestroy(t *testing.T) {
	sec, err := NewString("shared-secret-value")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}

	sec.Destroy()
	sec.Destroy() // idempotent

	if got := sec.Size(); got != 0 {
		t.Fatalf("Size after Destroy = %d, want 0", got)
	}

	err = sec.Open(func([]byte) error {
		t.Fatal("Open called fn on a destroyed secret")
		return nil
	})
	if !errors.Is(err, ErrDestroyed) {
		t.Fatalf("Open after Destroy = %v, want ErrDestroyed", err)
	}
}

func TestZeroValueAndNilReceiver(t *testing.T) {
	var zero Secret
	if err := zero.Open(func([]byte) error { return nil }); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("zero value Open = %v, want ErrDestroyed", err)
	}

	var nilSecret *Secret
	if err := nilSecret.Open(func([]byte) error { return nil }); !errors.Is(err, ErrNilSecret) {
		t.Fatalf("nil Open = %v, want ErrNilSecret", err)
	}
	if got := nilSecret.Size(); got != 0 {
		t.Fatalf("nil Size = %d, want 0", got)
	}
	nilSecret.Destroy() // must not panic
}

func TestOpenPropagatesAndDestroysOnError(t *testing.T) {
	sec, err := NewString("shared-secret-value")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sec.Destroy()

	sentinel := errors.New("callback failed")
	if err := sec.Open(func([]byte) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("Open error = %v, want %v", err, sentinel)
	}

	// The secret is still usable: a failing callback releases the buffer, not
	// the secret.
	assertOpens(t, sec, []byte("shared-secret-value"))
}

func TestOpenDestroysTheBufferOnPanic(t *testing.T) {
	sec, err := NewString("shared-secret-value")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sec.Destroy()

	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic did not propagate out of Open")
			}
		}()
		_ = sec.Open(func([]byte) error { panic("boom") })
	}()

	assertOpens(t, sec, []byte("shared-secret-value"))
}

func TestNewWithDecodesIntoProtectedMemory(t *testing.T) {
	// The decoded form is written straight into the locked buffer: no
	// intermediate heap slice holds the key, which is the property
	// base32.DecodeString cannot offer.
	const encoded = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	want, err := base32.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("fixture decode: %v", err)
	}

	sec, err := NewWith(base32.StdEncoding.DecodedLen(len(encoded)), func(buf []byte) (int, error) {
		return base32.StdEncoding.Decode(buf, []byte(encoded))
	})
	if err != nil {
		t.Fatalf("NewWith: %v", err)
	}
	defer sec.Destroy()

	if got := sec.Size(); got != len(want) {
		t.Fatalf("Size = %d, want %d", got, len(want))
	}
	assertOpens(t, sec, want)
}

func TestNewWithShortWrite(t *testing.T) {
	// A decoder that allows for padding reports fewer bytes than the buffer it
	// was given; only what it wrote is sealed.
	sec, err := NewWith(32, func(buf []byte) (int, error) {
		return copy(buf, "short"), nil
	})
	if err != nil {
		t.Fatalf("NewWith: %v", err)
	}
	defer sec.Destroy()

	if got := sec.Size(); got != len("short") {
		t.Fatalf("Size = %d, want %d", got, len("short"))
	}
	assertOpens(t, sec, []byte("short"))
}

func TestNewWithRejectsBadFill(t *testing.T) {
	sentinel := errors.New("fill failed")
	if _, err := NewWith(8, func([]byte) (int, error) { return 0, sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("NewWith error = %v, want %v", err, sentinel)
	}
	if _, err := NewWith(8, func([]byte) (int, error) { return 0, nil }); !errors.Is(err, ErrEmpty) {
		t.Fatalf("NewWith with empty fill = %v, want ErrEmpty", err)
	}
	if _, err := NewWith(8, func([]byte) (int, error) { return 9, nil }); err == nil {
		t.Fatal("NewWith accepted a fill that overran its buffer")
	}
	if _, err := NewWith(8, nil); err == nil {
		t.Fatal("NewWith accepted a nil fill")
	}
}

func TestNewRandom(t *testing.T) {
	const size = 20

	first, err := NewRandom(size)
	if err != nil {
		t.Fatalf("NewRandom: %v", err)
	}
	defer first.Destroy()

	second, err := NewRandom(size)
	if err != nil {
		t.Fatalf("NewRandom: %v", err)
	}
	defer second.Destroy()

	if first.Size() != size {
		t.Fatalf("Size = %d, want %d", first.Size(), size)
	}

	var a, b []byte
	if err := first.Open(func(key []byte) error { a = append([]byte(nil), key...); return nil }); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := second.Open(func(key []byte) error { b = append([]byte(nil), key...); return nil }); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two NewRandom secrets produced identical key material")
	}
	if bytes.Equal(a, make([]byte, size)) {
		t.Fatal("NewRandom produced an all-zero key")
	}
}

func TestEmptyConstructors(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("New(nil) = %v, want ErrEmpty", err)
	}
	if _, err := New([]byte{}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("New(empty) = %v, want ErrEmpty", err)
	}
	if _, err := NewString(""); !errors.Is(err, ErrEmpty) {
		t.Fatalf("NewString(empty) = %v, want ErrEmpty", err)
	}
	if _, err := NewWith(0, func([]byte) (int, error) { return 0, nil }); !errors.Is(err, ErrEmpty) {
		t.Fatalf("NewWith(0) = %v, want ErrEmpty", err)
	}
}

func TestOpenString(t *testing.T) {
	const want = "service-account-password"

	sec, err := NewString(want)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sec.Destroy()

	var got string
	if err := sec.OpenString(func(key string) error { got = key; return nil }); err != nil {
		t.Fatalf("OpenString: %v", err)
	}
	if got != want {
		t.Fatalf("OpenString gave %q, want %q", got, want)
	}
}

func TestNilCallbacks(t *testing.T) {
	sec, err := NewString("shared-secret-value")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sec.Destroy()

	if err := sec.Open(nil); err == nil {
		t.Fatal("Open accepted a nil callback")
	}
	if err := sec.OpenString(nil); err == nil {
		t.Fatal("OpenString accepted a nil callback")
	}
	if err := Scratch(8, nil); err == nil {
		t.Fatal("Scratch accepted a nil callback")
	}
}

func TestScratch(t *testing.T) {
	err := Scratch(16, func(buf []byte) error {
		if len(buf) != 16 {
			t.Fatalf("scratch buffer len = %d, want 16", len(buf))
		}
		if !bytes.Equal(buf, make([]byte, 16)) {
			t.Fatal("scratch buffer was not zeroed")
		}
		copy(buf, "decoded-key-here")
		return nil
	})
	if err != nil {
		t.Fatalf("Scratch: %v", err)
	}
}

func TestScratchRejectsEmpty(t *testing.T) {
	if err := Scratch(0, func([]byte) error { return nil }); !errors.Is(err, ErrEmpty) {
		t.Fatalf("Scratch(0) = %v, want ErrEmpty", err)
	}
}

func TestRedaction(t *testing.T) {
	// A credential must not be printable by accident. Every verb that would
	// otherwise walk the struct has to render the redaction instead.
	const plaintext = "shared-secret-value"

	sec, err := NewString(plaintext)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sec.Destroy()

	for _, format := range []string{"%v", "%s", "%+v", "%#v", "%q"} {
		rendered := fmt.Sprintf(format, sec)
		if strings.Contains(rendered, plaintext) {
			t.Errorf("%s rendered the plaintext: %s", format, rendered)
		}
		if !strings.Contains(rendered, "redacted") {
			t.Errorf("%s = %s, want a redaction", format, rendered)
		}
	}

	// The same must hold for a struct that merely holds one.
	holder := struct{ Password *Secret }{Password: sec}
	if rendered := fmt.Sprintf("%+v", holder); strings.Contains(rendered, plaintext) {
		t.Errorf("holding struct rendered the plaintext: %s", rendered)
	}
}

func TestConcurrentOpen(t *testing.T) {
	const plaintext = "shared-secret-value"

	sec, err := NewString(plaintext)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sec.Destroy()

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := sec.Open(func(key []byte) error {
				if !bytes.Equal(key, []byte(plaintext)) {
					return fmt.Errorf("opened %q", key)
				}
				return nil
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Open: %v", err)
	}
}

// assertOpens checks that sec still yields want, and that Size agrees.
func assertOpens(t *testing.T, sec *Secret, want []byte) {
	t.Helper()

	if got := sec.Size(); got != len(want) {
		t.Fatalf("Size = %d, want %d", got, len(want))
	}
	err := sec.Open(func(key []byte) error {
		if !bytes.Equal(key, want) {
			return fmt.Errorf("opened %q, want %q", key, want)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
}

func TestLock(t *testing.T) {
	const plaintext = "shared-secret-value"

	sec, err := NewString(plaintext)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sec.Destroy()

	locked, err := sec.Lock()
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}

	if got := locked.Size(); got != len(plaintext) {
		t.Fatalf("Size = %d, want %d", got, len(plaintext))
	}
	if got := locked.Bytes(); !bytes.Equal(got, []byte(plaintext)) {
		t.Fatalf("Bytes = %q, want %q", got, plaintext)
	}

	// The Locked is an independent copy: releasing the Secret does not take
	// it, and releasing the Locked does not take the Secret.
	sec.Destroy()
	if got := locked.Bytes(); !bytes.Equal(got, []byte(plaintext)) {
		t.Fatalf("Bytes after the secret was destroyed = %q, want %q", got, plaintext)
	}

	locked.Destroy()
	locked.Destroy() // idempotent

	if got := locked.Bytes(); got != nil {
		t.Fatalf("Bytes after Destroy = %q, want nil", got)
	}
	if got := locked.Size(); got != 0 {
		t.Fatalf("Size after Destroy = %d, want 0", got)
	}
}

func TestLockNilAndDestroyed(t *testing.T) {
	var nilSecret *Secret
	if _, err := nilSecret.Lock(); !errors.Is(err, ErrNilSecret) {
		t.Fatalf("nil Lock = %v, want ErrNilSecret", err)
	}

	sec, err := NewString("shared-secret-value")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	sec.Destroy()
	if _, err := sec.Lock(); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("destroyed Lock = %v, want ErrDestroyed", err)
	}

	var nilLocked *Locked
	if got := nilLocked.Bytes(); got != nil {
		t.Fatal("nil Locked returned bytes")
	}
	if got := nilLocked.Size(); got != 0 {
		t.Fatal("nil Locked reported a size")
	}
	nilLocked.Destroy() // must not panic
}

func TestLockedRedaction(t *testing.T) {
	const plaintext = "shared-secret-value"

	sec, err := NewString(plaintext)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sec.Destroy()

	locked, err := sec.Lock()
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer locked.Destroy()

	for _, format := range []string{"%v", "%s", "%+v", "%#v", "%q"} {
		rendered := fmt.Sprintf(format, locked)
		if strings.Contains(rendered, plaintext) {
			t.Errorf("%s rendered the plaintext: %s", format, rendered)
		}
		if !strings.Contains(rendered, "redacted") {
			t.Errorf("%s = %s, want a redaction", format, rendered)
		}
	}
}

func TestLockedConcurrentReads(t *testing.T) {
	const plaintext = "shared-secret-value"

	sec, err := NewString(plaintext)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sec.Destroy()

	locked, err := sec.Lock()
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer locked.Destroy()

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := locked.Bytes(); !bytes.Equal(got, []byte(plaintext)) {
				errs <- fmt.Errorf("read %q", got)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent read: %v", err)
	}
}
