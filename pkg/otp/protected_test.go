// The tests here cover the protected-secret path with this package's default
// digest, SHA-1 (RFC 4226 §5.1, RFC 6238 §1.2), and with the RFC test vectors,
// which are defined over SHA-1 as well. GODEBUG=fips140=only refuses to key
// HMAC with SHA-1, so they are excluded from that build;
// protected_fips140only_test.go covers the same path with SHA-256 there.

//go:build !fips140only

package otp

import (
	"bytes"
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-auth/pkg/secret"
)

// base32Of encodes an RFC test-vector key, which the RFCs give as ASCII.
func base32Of(key string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(key))
}

const (
	rfcKeySHA1   = "12345678901234567890"
	rfcKeySHA256 = "12345678901234567890123456789012"
	rfcKeySHA512 = "1234567890123456789012345678901234567890123456789012345678901234"
)

// TestDeriveCodeRFC4226Vectors checks the HOTP core against the reference
// values in RFC 4226 Appendix D. This is what says the in-repo derivation is
// the standard one and not merely self-consistent.
func TestDeriveCodeRFC4226Vectors(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}

	for counter, code := range want {
		got, err := deriveCode([]byte(rfcKeySHA1), uint64(counter), 6, AlgorithmSHA1)
		if err != nil {
			t.Fatalf("counter %d: %v", counter, err)
		}
		if got != code {
			t.Errorf("counter %d = %s, want %s", counter, got, code)
		}
	}
}

// TestDeriveCodeRFC6238Vectors checks the TOTP core against RFC 6238
// Appendix B, which covers all three digests at 8 digits.
func TestDeriveCodeRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		sha1 string
		s256 string
		s512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}

	for _, tc := range cases {
		counter := totpCounter(time.Unix(tc.unix, 0).UTC(), 30)

		for _, sub := range []struct {
			name string
			key  string
			algo Algorithm
			want string
		}{
			{"SHA1", rfcKeySHA1, AlgorithmSHA1, tc.sha1},
			{"SHA256", rfcKeySHA256, AlgorithmSHA256, tc.s256},
			{"SHA512", rfcKeySHA512, AlgorithmSHA512, tc.s512},
		} {
			got, err := deriveCode([]byte(sub.key), counter, 8, sub.algo)
			if err != nil {
				t.Fatalf("%s at %d: %v", sub.name, tc.unix, err)
			}
			if got != sub.want {
				t.Errorf("%s at %d = %s, want %s", sub.name, tc.unix, got, sub.want)
			}
		}
	}
}

func TestDeriveCodeRejectsBadInput(t *testing.T) {
	if _, err := deriveCode(nil, 0, 6, AlgorithmSHA1); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("empty key = %v, want ErrInvalidConfig", err)
	}
	if _, err := deriveCode([]byte(rfcKeySHA1), 0, 9, AlgorithmSHA1); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("9 digits = %v, want ErrInvalidConfig", err)
	}
	if _, err := deriveCode([]byte(rfcKeySHA1), 0, 6, Algorithm("MD5")); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("unknown algorithm = %v, want ErrInvalidConfig", err)
	}
}

func TestValidateTOTPSkewWindow(t *testing.T) {
	key := []byte(rfcKeySHA1)
	now := time.Unix(1111111109, 0).UTC()

	// A code from the step before and the step after must both validate at
	// skew 1, and neither at skew 0.
	for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		code, err := deriveCode(key, totpCounter(now.Add(offset), 30), 8, AlgorithmSHA1)
		if err != nil {
			t.Fatalf("derive: %v", err)
		}

		valid, err := validateTOTP(key, code, now, 30, 1, 8, AlgorithmSHA1)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if !valid {
			t.Errorf("code at offset %s rejected inside the skew window", offset)
		}

		valid, err = validateTOTP(key, code, now, 30, 0, 8, AlgorithmSHA1)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if valid != (offset == 0) {
			t.Errorf("code at offset %s with skew 0: valid = %v, want %v", offset, valid, offset == 0)
		}
	}

	// Two steps out is outside a skew of 1.
	code, err := deriveCode(key, totpCounter(now.Add(60*time.Second), 30), 8, AlgorithmSHA1)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	valid, err := validateTOTP(key, code, now, 30, 1, 8, AlgorithmSHA1)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if valid {
		t.Error("code two steps out was accepted at skew 1")
	}
}

// TestSkewIsBounded covers both halves of the guard: a configuration asking
// for a window this package will not honor is rejected at construction, and
// the derivation itself cannot be made to iterate an unbounded number of
// steps — including at the very top of the counter range, where an unchecked
// `c <= last` loop would never terminate.
func TestSkewIsBounded(t *testing.T) {
	key, err := NewProtectedSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("NewProtectedSecret: %v", err)
	}
	defer key.Destroy()

	if _, err := NewAuthenticator(Config{Type: TypeTOTP, SecretKey: key, Skew: maxSkew}); err != nil {
		t.Fatalf("skew of %d rejected: %v", maxSkew, err)
	}
	if _, err := NewAuthenticator(Config{Type: TypeTOTP, SecretKey: key, Skew: maxSkew + 1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("skew of %d = %v, want ErrInvalidConfig", maxSkew+1, err)
	}
	// The deprecated string path is validated by the same rule.
	if _, err := NewAuthenticator(Config{Type: TypeTOTP, Secret: "JBSWY3DPEHPK3PXP", Skew: 1 << 40}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("huge skew on the string path = %v, want ErrInvalidConfig", err)
	}

	// Directly, with a skew no configuration could get past validate and a
	// time at the top of what a counter can represent. Any wrap in the loop
	// bounds would hang this test rather than fail it.
	done := make(chan struct{})
	go func() {
		defer close(done)

		raw := []byte(rfcKeySHA1)
		now := time.Unix(1111111109, 0).UTC()
		code, err := deriveCode(raw, totpCounter(now, 30), 6, AlgorithmSHA1)
		if err != nil {
			t.Errorf("derive: %v", err)
			return
		}
		valid, err := validateTOTP(raw, code, now, 30, math.MaxUint32, 6, AlgorithmSHA1)
		if err != nil {
			t.Errorf("validate: %v", err)
			return
		}
		if !valid {
			t.Error("clamped skew dropped the current time step")
		}

		// A time step near the top of the range: first+i must not wrap.
		if _, err := validateTOTP(raw, code, time.Unix(math.MaxInt64/int64(time.Second), 0).UTC(), 1, maxSkew, 6, AlgorithmSHA1); err != nil {
			t.Errorf("validate at the top of the counter range: %v", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("validateTOTP did not terminate")
	}
}

func TestValidateTOTPNearEpoch(t *testing.T) {
	// The skew window is clamped at zero: subtracting past the epoch would
	// wrap a uint64 and check the top of the counter range.
	key := []byte(rfcKeySHA1)
	now := time.Unix(0, 0).UTC()

	code, err := deriveCode(key, 0, 6, AlgorithmSHA1)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	valid, err := validateTOTP(key, code, now, 30, 5, 6, AlgorithmSHA1)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !valid {
		t.Error("code at the epoch was rejected")
	}
}

// TestProtectedMatchesStringPath is the compatibility proof: a secret enrolled
// against the deprecated string path produces the same codes on the protected
// path, so migrating a Config does not invalidate anyone's authenticator app.
func TestProtectedMatchesStringPath(t *testing.T) {
	const encoded = "JBSWY3DPEHPK3PXP"

	for _, algo := range []Algorithm{AlgorithmSHA1, AlgorithmSHA256, AlgorithmSHA512} {
		for _, digits := range []uint{6, 7, 8} {
			legacy, err := NewAuthenticator(Config{
				Type: TypeHOTP, Secret: encoded, Digits: digits, Algorithm: algo,
			})
			if err != nil {
				t.Fatalf("legacy authenticator: %v", err)
			}

			key, err := NewProtectedSecret(encoded)
			if err != nil {
				t.Fatalf("NewProtectedSecret: %v", err)
			}
			protected, err := NewAuthenticator(Config{
				Type: TypeHOTP, SecretKey: key, Digits: digits, Algorithm: algo,
			})
			if err != nil {
				t.Fatalf("protected authenticator: %v", err)
			}

			for counter := uint64(0); counter < 5; counter++ {
				want, err := legacy.Generate(counter)
				if err != nil {
					t.Fatalf("legacy generate: %v", err)
				}
				got, err := protected.Generate(counter)
				if err != nil {
					t.Fatalf("protected generate: %v", err)
				}
				if got != want {
					t.Errorf("%s/%d digits counter %d: protected %s, string path %s",
						algo, digits, counter, got, want)
				}
			}
			key.Destroy()
		}
	}
}

func TestProtectedTOTPAuthenticate(t *testing.T) {
	key, err := GenerateProtectedSecret()
	if err != nil {
		t.Fatalf("GenerateProtectedSecret: %v", err)
	}
	defer key.Destroy()

	auth, err := NewAuthenticator(Config{
		Type:      TypeTOTP,
		SecretKey: key,
		Issuer:    "MyApp",
		Algorithm: AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	code, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := auth.Authenticate(context.Background(), code); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := auth.Authenticate(context.Background(), "000000"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("Authenticate with a wrong code = %v, want ErrInvalidCode", err)
	}
	if err := auth.Authenticate(context.Background(), "   "); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("Authenticate with a blank code = %v, want ErrInvalidCode", err)
	}
}

func TestProtectedHOTPAuthenticateAndValidateCounter(t *testing.T) {
	key, err := NewProtectedSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("NewProtectedSecret: %v", err)
	}
	defer key.Destroy()

	auth, err := NewAuthenticator(Config{Type: TypeHOTP, SecretKey: key, Counter: 7})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	code, err := auth.Generate(7)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := auth.Authenticate(context.Background(), code); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	next, err := auth.ValidateCounter(context.Background(), code, 7)
	if err != nil {
		t.Fatalf("ValidateCounter: %v", err)
	}
	if next != 8 {
		t.Fatalf("ValidateCounter returned %d, want 8", next)
	}
	if _, err := auth.ValidateCounter(context.Background(), code, 9); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("ValidateCounter at the wrong counter = %v, want ErrInvalidCode", err)
	}
}

// TestAuthenticatorKeepsNoPlaintextCopy is the verification the issue asks for:
// after the key has been used, nothing in the authenticator can produce it
// again once the caller destroys the secret. A cached plaintext copy anywhere
// in the type — a decoded []byte, a string field, a memoised hash state —
// would let these calls keep succeeding.
func TestAuthenticatorKeepsNoPlaintextCopy(t *testing.T) {
	const encoded = "JBSWY3DPEHPK3PXP"

	key, err := NewProtectedSecret(encoded)
	if err != nil {
		t.Fatalf("NewProtectedSecret: %v", err)
	}

	auth, err := NewAuthenticator(Config{Type: TypeHOTP, SecretKey: key, Counter: 1})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	code, err := auth.Generate(1)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := auth.Authenticate(context.Background(), code); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// The rendered authenticator must not contain the secret in any form: not
	// the base32 text, not the decoded key bytes.
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		t.Fatalf("fixture decode: %v", err)
	}
	rendered := fmt.Sprintf("%#v %+v", auth, auth)
	if strings.Contains(rendered, encoded) {
		t.Errorf("authenticator rendered the base32 secret: %s", rendered)
	}
	if strings.Contains(rendered, string(decoded)) {
		t.Errorf("authenticator rendered the decoded key: %s", rendered)
	}

	// Releasing the secret must take the authenticator's ability to derive
	// codes with it.
	key.Destroy()

	if _, err := auth.Generate(1); err == nil {
		t.Error("Generate still produced a code after the secret was destroyed")
	}
	if err := auth.Authenticate(context.Background(), code); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("Authenticate after destroy = %v, want ErrInvalidCode", err)
	}
	if _, err := auth.ValidateCounter(context.Background(), code, 1); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("ValidateCounter after destroy = %v, want ErrInvalidCode", err)
	}
}

func TestProtectedProvisioningURI(t *testing.T) {
	const encoded = "JBSWY3DPEHPK3PXP"

	key, err := NewProtectedSecret(encoded)
	if err != nil {
		t.Fatalf("NewProtectedSecret: %v", err)
	}
	defer key.Destroy()

	auth, err := NewAuthenticator(Config{
		Type:        TypeTOTP,
		SecretKey:   key,
		Issuer:      "MyApp",
		AccountName: "user@example.com",
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	uri, err := auth.ProvisioningURI()
	if err != nil {
		t.Fatalf("ProvisioningURI: %v", err)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse URI: %v", err)
	}
	if got := parsed.Query().Get("secret"); got != encoded {
		t.Fatalf("provisioning secret = %q, want %q", got, encoded)
	}
	if deprecated := auth.GetProvisioningURI(); deprecated != uri {
		t.Fatalf("GetProvisioningURI = %q, want %q", deprecated, uri)
	}
}

// TestProvisioningURIReportsAnUnreadableSecret pins the failure mode: a URI
// that carries no secret still looks like an enrollment, so it must not be
// produced. The error-returning method says why, and the deprecated one
// returns nothing at all rather than something unusable.
func TestProvisioningURIReportsAnUnreadableSecret(t *testing.T) {
	key, err := NewProtectedSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("NewProtectedSecret: %v", err)
	}

	auth, err := NewAuthenticator(Config{
		Type:        TypeTOTP,
		SecretKey:   key,
		Issuer:      "MyApp",
		AccountName: "user@example.com",
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	key.Destroy()

	uri, err := auth.ProvisioningURI()
	if !errors.Is(err, secret.ErrDestroyed) {
		t.Fatalf("ProvisioningURI error = %v, want ErrDestroyed", err)
	}
	if uri != "" {
		t.Fatalf("ProvisioningURI returned %q alongside an error", uri)
	}
	if got := auth.GetProvisioningURI(); got != "" {
		t.Fatalf("GetProvisioningURI = %q, want an empty string", got)
	}

	var nilAuth *Authenticator
	if _, err := nilAuth.ProvisioningURI(); !errors.Is(err, ErrNilAuthenticator) {
		t.Fatalf("nil ProvisioningURI = %v, want ErrNilAuthenticator", err)
	}
	if got := nilAuth.GetProvisioningURI(); got != "" {
		t.Fatalf("nil GetProvisioningURI = %q, want an empty string", got)
	}
}

func TestNewProtectedSecret(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"unpadded", "JBSWY3DPEHPK3PXP", "Hello!\xde\xad\xbe\xef"},
		{"lower case", "jbswy3dpehpk3pxp", "Hello!\xde\xad\xbe\xef"},
		{"padded", base32.StdEncoding.EncodeToString([]byte("hello")), "hello"},
		{"surrounding space", "  JBSWY3DPEHPK3PXP  ", "Hello!\xde\xad\xbe\xef"},
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
			sec, err := NewProtectedSecret(tc.input)
			if err != nil {
				t.Fatalf("NewProtectedSecret: %v", err)
			}
			defer sec.Destroy()

			err = sec.Open(func(key []byte) error {
				if string(key) != tc.want {
					return fmt.Errorf("decoded %q, want %q", key, tc.want)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNewProtectedSecretRejects(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		// '1' and '8' are outside the base32 alphabet; '=' alone normalizes to
		// an empty secret. An unpadded input that is a valid partial group is
		// not an error — it is what provisioning tools emit, and what the
		// string path hands to github.com/pquerna/otp, which pads it before
		// decoding. TestNewProtectedSecret covers those.
		{"empty", ""},
		{"whitespace only", "   "},
		{"padding only", "="},
		{"not base32", "not base32!"},
		{"digit outside the alphabet", "ABCDEF1H"},
		{"digit outside the alphabet, unpadded length", "JBSWY3DPEHPK3P8"},
		// Final groups of 1, 3 and 6 characters cannot encode a whole byte.
		// Go's unpadded decoder drops them and returns no error, so
		// "JBSWY3DPEHPK3PXP" and "JBSWY3DPEHPK3PXPA" would otherwise yield the
		// same key and one stray character would silently enroll a different
		// secret than the user scanned.
		{"trailing group of 1", "JBSWY3DPEHPK3PXPA"},
		{"trailing group of 3", "JBSWY3DPEHPK3PXPABC"},
		{"trailing group of 6", "JBSWY3DPEHPK3PXPABCDEF"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewProtectedSecret(tc.input); !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("NewProtectedSecret(%q) = %v, want ErrInvalidConfig", tc.input, err)
			}
		})
	}
}

// TestNewProtectedSecretTrailingGroupIsNotSilentlyDropped is the regression the
// rejection exists for: without it Go's unpadded decoder returns the same key
// for a secret and for that secret plus a stray character, so an enrollment
// typo becomes a login failure with nothing at construction to explain it.
func TestNewProtectedSecretTrailingGroupIsNotSilentlyDropped(t *testing.T) {
	const valid = "JBSWY3DPEHPK3PXP"

	good, err := NewProtectedSecret(valid)
	if err != nil {
		t.Fatalf("NewProtectedSecret(%q): %v", valid, err)
	}
	defer good.Destroy()

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

	if _, err := NewProtectedSecret(valid + "A"); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("NewProtectedSecret(%q) = %v, want ErrInvalidConfig", valid+"A", err)
	}
}

func TestGenerateProtectedSecret(t *testing.T) {
	key, err := GenerateProtectedSecret()
	if err != nil {
		t.Fatalf("GenerateProtectedSecret: %v", err)
	}
	defer key.Destroy()

	if got := key.Size(); got != 20 {
		t.Fatalf("Size = %d, want 20 (160 bits)", got)
	}

	// The encoded form round-trips: a key generated in protected memory can
	// still be enrolled and re-imported.
	encoded, err := EncodeSecret(key)
	if err != nil {
		t.Fatalf("EncodeSecret: %v", err)
	}
	reimported, err := NewProtectedSecret(encoded)
	if err != nil {
		t.Fatalf("NewProtectedSecret: %v", err)
	}
	defer reimported.Destroy()

	first, err := NewAuthenticator(Config{Type: TypeHOTP, SecretKey: key})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	second, err := NewAuthenticator(Config{Type: TypeHOTP, SecretKey: reimported})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	a, err := first.Generate(3)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := second.Generate(3)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if a != b {
		t.Fatalf("round-tripped secret produced %s, original produced %s", b, a)
	}
}

func TestEncodeSecretRejectsNil(t *testing.T) {
	if _, err := EncodeSecret(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("EncodeSecret(nil) = %v, want ErrInvalidConfig", err)
	}

	destroyed, err := NewProtectedSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("NewProtectedSecret: %v", err)
	}
	destroyed.Destroy()
	if _, err := EncodeSecret(destroyed); !errors.Is(err, secret.ErrDestroyed) {
		t.Fatalf("EncodeSecret(destroyed) = %v, want ErrDestroyed", err)
	}
}

func TestConfigRejectsBothSecretForms(t *testing.T) {
	key, err := NewProtectedSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("NewProtectedSecret: %v", err)
	}
	defer key.Destroy()

	_, err = NewAuthenticator(Config{Type: TypeTOTP, Secret: "JBSWY3DPEHPK3PXP", SecretKey: key})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("both secret forms = %v, want ErrInvalidConfig", err)
	}
}

func TestConfigRejectsDestroyedSecret(t *testing.T) {
	key, err := NewProtectedSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("NewProtectedSecret: %v", err)
	}
	key.Destroy()

	if _, err := NewAuthenticator(Config{Type: TypeTOTP, SecretKey: key}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("destroyed secret = %v, want ErrInvalidConfig", err)
	}
}
