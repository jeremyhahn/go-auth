// The YubiCloud signature tests are excluded from fips140only builds: Yubico
// Validation Protocol 2.0 signs every request and response with HMAC-SHA-1,
// which GODEBUG=fips140=only refuses to execute.

//go:build !fips140only

package yubikey

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- the test signs the way the protocol does
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	secretpkg "github.com/jeremyhahn/go-auth/pkg/secret"
)

// TestComputeSignatureMatchesTheProtocol pins the wire format across the move
// to protected memory: the signature is still HMAC-SHA1 over the sorted
// parameter list, keyed by the base64-decoded API key (Yubico Validation
// Protocol 2.0 §Generating signatures).
func TestComputeSignatureMatchesTheProtocol(t *testing.T) {
	values := url.Values{}
	values.Set("id", "1234")
	values.Set("otp", "ccccccbdefgh")
	values.Set("nonce", "abcdefghijklmnop")
	values.Set("timestamp", "1")

	rawKey := []byte("my-api-key-bytes")
	encoded := base64.StdEncoding.EncodeToString(rawKey)

	sealed, err := secretpkg.NewString(encoded)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sealed.Destroy()

	got, err := computeSignature(values, sealed)
	if err != nil {
		t.Fatalf("computeSignature: %v", err)
	}
	if want := referenceSignature(values, rawKey); got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}

	// A key that is not base64 is signed with its own bytes, which is what
	// this package did before the key moved into protected memory.
	plain, err := secretpkg.NewString("not base64 at all!!")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer plain.Destroy()

	got, err = computeSignature(values, plain)
	if err != nil {
		t.Fatalf("computeSignature: %v", err)
	}
	if want := referenceSignature(values, []byte("not base64 at all!!")); got != want {
		t.Fatalf("raw-key signature = %q, want %q", got, want)
	}
}

// TestComputeSignatureWithShortRawKey covers the boundary where base64 cannot
// carry a byte: a one-character key decodes to nothing, so it can only be a raw
// key, and the raw-key fallback has to be reached rather than the scratch
// allocation failing first. Config.validate accepts such a key, so rejecting it
// here would break every authentication for that configuration.
func TestComputeSignatureWithShortRawKey(t *testing.T) {
	values := url.Values{}
	values.Set("id", "1234")
	values.Set("otp", "ccccccbdefgh")

	for _, raw := range []string{"x", "yz", "abc"} {
		sealed, err := secretpkg.NewString(raw)
		if err != nil {
			t.Fatalf("NewString(%q): %v", raw, err)
		}

		got, err := computeSignature(values, sealed)
		if err != nil {
			t.Fatalf("computeSignature(%q): %v", raw, err)
		}

		// "yz" and "abc" are not valid base64 either, so every one of these
		// signs with its own bytes.
		if want := referenceSignature(values, []byte(raw)); got != want {
			t.Errorf("signature for raw key %q = %q, want %q", raw, got, want)
		}
		sealed.Destroy()
	}
}

func TestComputeSignatureWithDestroyedKey(t *testing.T) {
	sealed, err := secretpkg.NewString("bXktYXBpLWtleQ==")
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	sealed.Destroy()

	if _, err := computeSignature(url.Values{}, sealed); !errors.Is(err, secretpkg.ErrDestroyed) {
		t.Fatalf("computeSignature with a destroyed key = %v, want ErrDestroyed", err)
	}
}

// TestValidateProtectedRoundTrip exercises the whole YubiCloud exchange
// against a server that checks the request signature and signs its reply, with
// the API key never leaving protected memory on this side.
func TestValidateProtectedRoundTrip(t *testing.T) {
	rawKey := []byte("my-api-key-bytes")
	encoded := base64.StdEncoding.EncodeToString(rawKey)
	const otp = "ccccccbdefgh"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		signature := query.Get("h")
		query.Del("h")
		if want := referenceSignature(query, rawKey); signature != want {
			http.Error(w, "bad signature", http.StatusBadRequest)
			return
		}

		reply := url.Values{}
		reply.Set("status", "OK")
		reply.Set("nonce", query.Get("nonce"))
		reply.Set("otp", query.Get("otp"))

		body := fmt.Sprintf("status=OK\nnonce=%s\notp=%s\nh=%s\n",
			reply.Get("nonce"), reply.Get("otp"), referenceSignature(reply, rawKey))
		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer server.Close()

	sealed, err := secretpkg.NewString(encoded)
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer sealed.Destroy()

	validator := NewHTTPValidator(server.Client(), server.URL)
	if err := validator.ValidateProtected(context.Background(), "1234", sealed, otp); err != nil {
		t.Fatalf("ValidateProtected: %v", err)
	}

	// The deprecated string entry point seals the key and reaches the same
	// place.
	if err := validator.Validate(context.Background(), "1234", encoded, otp); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// A wrong key produces a request the server refuses to answer.
	wrong, err := secretpkg.NewString(base64.StdEncoding.EncodeToString([]byte("wrong-api-key!!!")))
	if err != nil {
		t.Fatalf("NewString: %v", err)
	}
	defer wrong.Destroy()
	if err := validator.ValidateProtected(context.Background(), "1234", wrong, otp); err == nil {
		t.Fatal("a request signed with the wrong key was accepted")
	}
}

// referenceSignature computes the Yubico signature independently of the
// implementation under test.
func referenceSignature(values url.Values, key []byte) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		if k == "h" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+strings.Join(values[k], ""))
	}

	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(strings.Join(parts, "&")))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
