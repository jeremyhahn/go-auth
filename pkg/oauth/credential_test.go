package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// sealedForTest seals s for a test and destroys it when the test ends. An
// empty s yields nil: an enclave cannot be empty, and an empty credential is
// no credential.
func sealedForTest(t testing.TB, s string) *enclave.MemoryEnclave {
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

// openedForTest reads an enclave's material back for an assertion.
func openedForTest(t *testing.T, e *enclave.MemoryEnclave) string {
	t.Helper()
	s, err := e.OpenString()
	if err != nil {
		t.Fatalf("OpenString: %v", err)
	}
	return s
}

func TestFormEscapeMatchesQueryEscape(t *testing.T) {
	inputs := []string{
		"plain",
		"with space",
		"a+b/c=d&e",
		"unreserved-._~",
		"percent%25",
		"ünïcødé",
		"\x00\x01\x7f\xff",
	}

	// Every single byte, so no character class is left to a table someone
	// forgot to extend.
	var all []byte
	for b := 0; b < 256; b++ {
		all = append(all, byte(b))
	}
	inputs = append(inputs, string(all))

	for _, in := range inputs {
		want := url.QueryEscape(in)
		if got := formEscapedLen([]byte(in)); got != len(want) {
			t.Errorf("formEscapedLen(%q) = %d, want %d", in, got, len(want))
		}
		dst := make([]byte, len(want))
		if n := formEscapeInto(dst, []byte(in)); n != len(want) || string(dst[:n]) != want {
			t.Errorf("formEscapeInto(%q) = %q, want %q", in, dst[:n], want)
		}
	}
}

func TestWithFormBodyAssemblesPublicAndSealedFields(t *testing.T) {
	public := url.Values{}
	public.Set("grant_type", "refresh_token")
	public.Set("client_id", "client one")

	refresh := sealedForTest(t, "rt/with+symbols=&")
	clientSecret := sealedForTest(t, "s3cr3t value")

	var got string
	err := withFormBody(public, []sealedFormField{
		{name: "refresh_token", value: refresh},
		{name: "client_secret", value: clientSecret},
	}, func(body []byte) error {
		got = string(body)
		return nil
	})
	if err != nil {
		t.Fatalf("withFormBody() failed: %v", err)
	}

	form, err := url.ParseQuery(got)
	if err != nil {
		t.Fatalf("body %q is not a valid form: %v", got, err)
	}
	want := map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     "client one",
		"refresh_token": "rt/with+symbols=&",
		"client_secret": "s3cr3t value",
	}
	for k, v := range want {
		if form.Get(k) != v {
			t.Errorf("form[%q] = %q, want %q", k, form.Get(k), v)
		}
	}
	if len(form) != len(want) {
		t.Errorf("form has %d fields, want %d: %q", len(form), len(want), got)
	}

	// The fields are borrowed, not consumed.
	if !refresh.IsAlive() || !clientSecret.IsAlive() {
		t.Error("withFormBody destroyed a borrowed credential")
	}
}

func TestWithFormBodyWithoutPublicFields(t *testing.T) {
	token := sealedForTest(t, "abc")

	var got string
	if err := withFormBody(url.Values{}, []sealedFormField{{name: "token", value: token}}, func(body []byte) error {
		got = string(body)
		return nil
	}); err != nil {
		t.Fatalf("withFormBody() failed: %v", err)
	}
	if got != "token=abc" {
		t.Errorf("body = %q, want %q", got, "token=abc")
	}
}

func TestWithFormBodyRefusesAMissingCredential(t *testing.T) {
	destroyed := sealedForTest(t, "gone")
	destroyed.Destroy()

	for name, value := range map[string]*enclave.MemoryEnclave{"nil": nil, "destroyed": destroyed} {
		t.Run(name, func(t *testing.T) {
			called := false
			err := withFormBody(url.Values{"a": {"b"}}, []sealedFormField{{name: "client_secret", value: value}}, func([]byte) error {
				called = true
				return nil
			})
			if !errors.Is(err, ErrCredentialUnavailable) {
				t.Errorf("withFormBody() = %v, want ErrCredentialUnavailable", err)
			}
			if called {
				t.Error("withFormBody() sent a body without the credential")
			}
		})
	}
}

func TestWithFormBodyPropagatesTheCallbackError(t *testing.T) {
	sentinel := errors.New("send failed")
	err := withFormBody(url.Values{"a": {"b"}}, nil, func([]byte) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Errorf("withFormBody() = %v, want the callback's error", err)
	}
}

func TestUnquoteJSONStringMatchesEncodingJSON(t *testing.T) {
	inputs := []string{
		`""`,
		`"plain"`,
		`"slash\/escaped"`,
		`"quote\" backslash\\"`,
		`"\b\f\n\r\t"`,
		`"Aé中"`,
		`"😀 surrogate pair"`,
		`"\ud83d lone high surrogate"`,
		`"\ude00 lone low surrogate"`,
		`"raw ünïcødé"`,
	}

	for _, in := range inputs {
		var want string
		if err := json.Unmarshal([]byte(in), &want); err != nil {
			t.Fatalf("json.Unmarshal(%s): %v", in, err)
		}

		n, err := unquoteJSONString([]byte(in), nil)
		if err != nil {
			t.Errorf("unquoteJSONString(%s) count failed: %v", in, err)
			continue
		}
		if n != len(want) {
			t.Errorf("unquoteJSONString(%s) counted %d, want %d", in, n, len(want))
			continue
		}

		dst := make([]byte, n)
		if m, err := unquoteJSONString([]byte(in), dst); err != nil || m != n || string(dst) != want {
			t.Errorf("unquoteJSONString(%s) = %q, %v; want %q", in, dst[:m], err, want)
		}
	}
}

func TestUnquoteJSONStringRejectsNonStrings(t *testing.T) {
	for _, in := range []string{``, `"`, `123`, `{"a":1}`, `"bad \x escape"`, `"short \u12"`} {
		if _, err := unquoteJSONString([]byte(in), nil); !errors.Is(err, ErrMalformedTokenResponse) {
			t.Errorf("unquoteJSONString(%s) = %v, want ErrMalformedTokenResponse", in, err)
		}
	}
}

func TestSealJSONString(t *testing.T) {
	e, err := sealJSONString(json.RawMessage(`"a\/b"`))
	if err != nil {
		t.Fatalf("sealJSONString() failed: %v", err)
	}
	defer e.Destroy()
	if got := openedForTest(t, e); got != "a/b" {
		t.Errorf("sealed %q, want %q", got, "a/b")
	}

	// Absent, null and empty all mean "no credential": an enclave cannot be
	// empty, and an empty token is no token.
	for _, absent := range []string{``, `null`, `""`} {
		e, err := sealJSONString(json.RawMessage(absent))
		if err != nil || e != nil {
			t.Errorf("sealJSONString(%q) = %v, %v; want nil, nil", absent, e, err)
		}
	}

	if _, err := sealJSONString(json.RawMessage(`42`)); !errors.Is(err, ErrMalformedTokenResponse) {
		t.Errorf("sealJSONString(42) = %v, want ErrMalformedTokenResponse", err)
	}
}

func TestTokenFingerprint(t *testing.T) {
	token := sealedForTest(t, "bearer-value")

	got, err := tokenFingerprint(token)
	if err != nil {
		t.Fatalf("tokenFingerprint() failed: %v", err)
	}
	sum := sha256.Sum256([]byte("bearer-value"))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
		t.Errorf("tokenFingerprint() = %q, want %q", got, want)
	}
	if strings.Contains(got, "bearer-value") {
		t.Error("fingerprint carries the token")
	}

	token.Destroy()
	if _, err := tokenFingerprint(token); !errors.Is(err, ErrMissingToken) {
		t.Errorf("tokenFingerprint(destroyed) = %v, want ErrMissingToken", err)
	}
}

func TestSealAndOpenJSONRoundTrip(t *testing.T) {
	in := &TokenClaims{Subject: "sub", Email: "e@example.com", Custom: map[string]interface{}{"tenant": "t1"}}

	e, err := sealJSON(enclave.NewMemoryEnclave, in)
	if err != nil {
		t.Fatalf("sealJSON() failed: %v", err)
	}
	defer e.Destroy()

	var out TokenClaims
	if err := openJSON(e, &out); err != nil {
		t.Fatalf("openJSON() failed: %v", err)
	}
	if out.Subject != "sub" || out.Email != "e@example.com" || out.Custom["tenant"] != "t1" {
		t.Errorf("round trip = %+v", out)
	}

	e.Destroy()
	if err := openJSON(e, &out); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Errorf("openJSON(destroyed) = %v, want ErrEnclaveDestroyed", err)
	}
}
