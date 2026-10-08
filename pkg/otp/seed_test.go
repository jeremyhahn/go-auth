package otp

import (
	"bytes"
	"encoding/base32"
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// base32Of encodes an RFC test-vector key, which the RFCs give as ASCII.
func base32Of(key string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(key))
}

// openSeed returns a copy of the seed's bytes for comparison. Test-only: the
// whole point of the package is that production code never does this.
func openSeed(t *testing.T, seed *enclave.MemoryEnclave) []byte {
	t.Helper()
	var out []byte
	if err := seed.WithBytes(func(b []byte) error {
		out = bytes.Clone(b)
		return nil
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	return out
}

func TestDecodeSeed(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"unpadded", "JBSWY3DPEHPK3PXP", "Hello!\xde\xad\xbe\xef"},
		{"lower case", "jbswy3dpehpk3pxp", "Hello!\xde\xad\xbe\xef"},
		{"padded", base32.StdEncoding.EncodeToString([]byte("hello")), "hello"},
		{"surrounding space", "  JBSWY3DPEHPK3PXP  ", "Hello!\xde\xad\xbe\xef"},
		{"RFC 4226 seed", testSeedBase32, rfcKeySHA1},
		// The four unpadded final groups that do encode whole bytes. They are
		// what provisioning tools emit, so rejecting a short trailing group
		// must not catch them: 2, 4, 5 and 7 characters carry 1, 2, 3 and 4
		// bytes respectively.
		{"partial group of 2", base32Of("a"), "a"},
		{"partial group of 4", base32Of("ab"), "ab"},
		{"partial group of 5", base32Of("abc"), "abc"},
		{"partial group of 7", base32Of("abcd"), "abcd"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seed, err := DecodeSeed(tc.input)
			if err != nil {
				t.Fatalf("DecodeSeed: %v", err)
			}
			defer seed.Destroy()

			if got := openSeed(t, seed); string(got) != tc.want {
				t.Fatalf("decoded %q, want %q", got, tc.want)
			}
			if seed.Size() != len(tc.want) {
				t.Errorf("Size = %d, want %d", seed.Size(), len(tc.want))
			}
		})
	}
}

func TestDecodeSeedRejects(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		// '1' and '8' are outside the base32 alphabet; '=' alone normalizes to
		// an empty seed.
		{"empty", ""},
		{"whitespace only", "   "},
		{"padding only", "="},
		{"not base32", "not base32!"},
		{"misplaced padding", "MZ=XW6YTB"},
		{"digit outside the alphabet", "ABCDEF1H"},
		{"digit outside the alphabet, unpadded length", "JBSWY3DPEHPK3P8"},
		{"valid prefix then bad", testSeedBase32 + "@@@@@@@@"},
		// Go's base32 decoder skips CR and LF without counting them, so a
		// buffer sized from the input length kept zero bytes past the decoded
		// seed: this one would have become a 15-byte key instead of 10, passing
		// the FIPS 112-bit minimum and changing the codes it derives.
		{"embedded newlines", "JBSWY3DP\n\n\n\n\n\n\n\nEHPK3PXP"},
		{"embedded carriage return", "JBSWY3DP\rEHPK3PXP"},
		{"embedded space", "JBSWY3DP EHPK3PXP"},
		// Final groups of 1, 3 and 6 characters cannot encode a whole byte.
		// Go's unpadded decoder drops them and returns no error, so
		// "JBSWY3DPEHPK3PXP" and "JBSWY3DPEHPK3PXPA" would otherwise yield the
		// same key and one stray character would silently enroll a different
		// seed than the user scanned.
		{"trailing group of 1", "JBSWY3DPEHPK3PXPA"},
		{"trailing group of 3", "JBSWY3DPEHPK3PXPABC"},
		{"trailing group of 6", "JBSWY3DPEHPK3PXPABCDEF"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seed, err := DecodeSeed(tc.input)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("DecodeSeed(%q) = %v, want ErrInvalidConfig", tc.input, err)
			}
			if seed != nil {
				t.Errorf("DecodeSeed(%q) returned an enclave alongside the error", tc.input)
			}
		})
	}
}

// TestDecodeSeedTrailingGroupIsNotSilentlyDropped is the regression the
// rejection exists for: without it Go's unpadded decoder returns the same key
// for a seed and for that seed plus a stray character, so an enrollment typo
// becomes a login failure with nothing at construction to explain it.
func TestDecodeSeedTrailingGroupIsNotSilentlyDropped(t *testing.T) {
	const valid = "JBSWY3DPEHPK3PXP"

	// Proof the underlying decoder really does drop it: same bytes, no error.
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	a, err := encoding.DecodeString(valid)
	if err != nil {
		t.Fatalf("decode %q: %v", valid, err)
	}
	b, err := encoding.DecodeString(valid + "A")
	if err != nil {
		t.Fatalf("decode %q: %v", valid+"A", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("premise no longer holds: %q and %q decode differently", valid, valid+"A")
	}

	if _, err := DecodeSeed(valid + "A"); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("DecodeSeed(%q) = %v, want ErrInvalidConfig", valid+"A", err)
	}

	// And across every final-group length, acceptance follows exactly the
	// groups that encode whole bytes.
	const suffix = "ABCDEFG"
	for rem := range 8 {
		text := testSeedBase32 + suffix[:rem]
		wantAccept := rem != 1 && rem != 3 && rem != 6
		seed, err := DecodeSeed(text)
		if (err == nil) != wantAccept {
			t.Errorf("len mod 8 = %d: DecodeSeed = %v, want accept=%v", rem, err, wantAccept)
		}
		seed.Destroy()
	}
}

func TestGenerateProtectedSecret(t *testing.T) {
	seed, err := GenerateProtectedSecret()
	if err != nil {
		t.Fatalf("GenerateProtectedSecret: %v", err)
	}
	defer seed.Destroy()

	if got := seed.Size(); got != 20 {
		t.Fatalf("Size = %d, want 20 (160 bits)", got)
	}

	other, err := GenerateProtectedSecret()
	if err != nil {
		t.Fatalf("GenerateProtectedSecret: %v", err)
	}
	defer other.Destroy()
	if bytes.Equal(openSeed(t, seed), openSeed(t, other)) {
		t.Fatal("two generated seeds are identical")
	}
	if bytes.Equal(openSeed(t, seed), make([]byte, 20)) {
		t.Fatal("generated seed is all zeroes: the fill did not reach the enclave")
	}

	// The encoded form round-trips: a seed generated in protected memory can
	// still be enrolled and re-imported, and derives the same codes.
	encoded, err := EncodeSecret(seed)
	if err != nil {
		t.Fatalf("EncodeSecret: %v", err)
	}
	reimported, err := DecodeSeed(encoded)
	if err != nil {
		t.Fatalf("DecodeSeed: %v", err)
	}
	same, err := reimported.EqualTo(openSeed(t, seed))
	if err != nil {
		t.Fatalf("EqualTo: %v", err)
	}
	if !same {
		t.Fatal("re-imported seed differs from the original")
	}

	first, err := NewAuthenticator(Config{Type: TypeHOTP, Seed: seed, Algorithm: testAlgorithm()})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer func() { _ = first.Close() }()
	second, err := NewAuthenticator(Config{Type: TypeHOTP, Seed: reimported, Algorithm: testAlgorithm()})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer func() { _ = second.Close() }()

	a, err := first.Generate(3)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := second.Generate(3)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if a != b {
		t.Fatalf("round-tripped seed produced %s, original produced %s", b, a)
	}
}

func TestEncodeSecret(t *testing.T) {
	seed := testSeed(t)
	encoded, err := EncodeSecret(seed)
	if err != nil {
		t.Fatalf("EncodeSecret: %v", err)
	}
	if encoded != testSeedBase32 {
		t.Fatalf("EncodeSecret = %q, want %q", encoded, testSeedBase32)
	}
	// Encoding borrows the seed; it does not consume it.
	if !seed.IsAlive() {
		t.Fatal("EncodeSecret destroyed the seed")
	}

	if _, err := EncodeSecret(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("EncodeSecret(nil) = %v, want ErrInvalidConfig", err)
	}

	seed.Destroy()
	if _, err := EncodeSecret(seed); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("EncodeSecret(destroyed) = %v, want ErrEnclaveDestroyed", err)
	}
}

// TestSeedNeverRendered checks the seed's own formatting stays redacted when
// it rides along in a Config, which is the shape most likely to reach a log.
func TestSeedNeverRendered(t *testing.T) {
	cfg := Config{Type: TypeTOTP, Seed: testSeed(t)}
	rendered := fmt.Sprintf("%v %+v", cfg, cfg)
	for _, form := range []string{rfcKeySHA1, testSeedBase32} {
		if bytes.Contains([]byte(rendered), []byte(form)) {
			t.Errorf("Config rendered the seed %q: %s", form, rendered)
		}
	}
}
