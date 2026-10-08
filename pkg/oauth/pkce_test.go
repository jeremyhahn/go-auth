package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// constantVerifier is the code verifier this package used to emit: the byte
// sequence 0x00..0x1f, identical in every process and every deployment, which
// gave the authorization-code flow exactly the security of no PKCE at all
// (issue #9).
const constantVerifier = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

// newRecordingTokenEndpoint returns a token endpoint that counts the requests it
// receives. Tests that expect a call to fail before the network use it to prove
// the failure was a refusal and not a round trip — and to keep a regression from
// turning a unit test into a real dial.
func newRecordingTokenEndpoint(t *testing.T) (*httptest.Server, *int) {
	t.Helper()

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "unexpected-token",
			"token_type":   "Bearer",
		}); err != nil {
			t.Errorf("failed to encode token response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	return server, &calls
}

func pkceTestConfig(t *testing.T, tokenURL string) *Config {
	t.Helper()

	return &Config{
		Provider:     newTestProvider("https://example.test/auth", tokenURL),
		ClientID:     "test-client",
		ClientSecret: sealedForTest(t, "test-secret"),
		Flow:         FlowAuthorizationCode,
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}
}

// challengeOf derives the S256 challenge of a verifier that is already in plain
// memory — a fixture, or a value a test server received over the wire. Never
// call it on bytes taken out of an enclave.
func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestBuildAuthURLPKCEVerifierIsRandom is the regression test for issue #9. It
// asserts through the enclave: the verifier is never copied into plain memory,
// only fingerprinted and compared inside an open session
// (conventions/testing-guidelines.md, "Secrets in Tests").
func TestBuildAuthURLPKCEVerifierIsRandom(t *testing.T) {
	auth, err := NewAuthenticator(pkceTestConfig(t, "https://example.test/token"))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		authURL, verifier, err := auth.BuildAuthURLPKCE("random-state", nil)
		if err != nil {
			t.Fatalf("BuildAuthURLPKCE() failed: %v", err)
		}

		if got := verifier.Size(); got != pkceVerifierLen {
			t.Errorf("verifier.Size() = %d, want %d", got, pkceVerifierLen)
		}

		parsed, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("Failed to parse auth URL: %v", err)
		}
		challenge := parsed.Query().Get("code_challenge")

		var fingerprint string
		err = verifier.open(func(v []byte) error {
			if bytes.Equal(v, []byte(constantVerifier)) {
				t.Error("Code verifier is the hardcoded 0x00..0x1f constant")
			}
			if err := validatePKCEVerifier(v); err != nil {
				t.Errorf("Generated verifier is not RFC 7636 valid: %v", err)
			}

			sum := sha256.Sum256(v)
			fingerprint = hex.EncodeToString(sum[:])
			if want := base64.RawURLEncoding.EncodeToString(sum[:]); challenge != want {
				t.Errorf("code_challenge = %q, want base64url(SHA256(verifier)) = %q", challenge, want)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("verifier.open() failed: %v", err)
		}
		verifier.Destroy()

		if seen[fingerprint] {
			t.Fatal("Code verifier repeated across calls")
		}
		seen[fingerprint] = true
	}
}

// TestBuildAuthURLWithoutPKCECarriesNoChallenge pins the flow without PKCE: it
// involves no secret and no challenge.
func TestBuildAuthURLWithoutPKCECarriesNoChallenge(t *testing.T) {
	auth, err := NewAuthenticator(pkceTestConfig(t, "https://example.test/token"))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	authURL, err := auth.BuildAuthURL("random-state", nil)
	if err != nil {
		t.Fatalf("BuildAuthURL() failed: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}
	if challenge := parsed.Query().Get("code_challenge"); challenge != "" {
		t.Errorf("Expected no code_challenge, got %q", challenge)
	}
}

// TestExchangeAuthorizationCodePKCESendsTheVerifier proves the whole round trip:
// the verifier the token endpoint receives is the one the authorization URL
// committed to, and it survives being assembled into the request body by hand
// rather than by url.Values.
func TestExchangeAuthorizationCodePKCESendsTheVerifier(t *testing.T) {
	var form url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("token endpoint could not parse the request body: %v", err)
		}
		form = r.PostForm

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}); err != nil {
			t.Errorf("failed to encode token response: %v", err)
		}
	}))
	defer server.Close()

	auth, err := NewAuthenticator(pkceTestConfig(t, server.URL+"/token"))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	authURL, verifier, err := auth.BuildAuthURLPKCE("random-state", nil)
	if err != nil {
		t.Fatalf("BuildAuthURLPKCE() failed: %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}
	challenge := parsed.Query().Get("code_challenge")

	token, err := auth.ExchangeAuthorizationCodePKCE(context.Background(), "test-code", verifier)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCodePKCE() failed: %v", err)
	}
	if openedForTest(t, token.AccessToken()) != "test-access-token" {
		t.Errorf("AccessToken = %q, want %q", openedForTest(t, token.AccessToken()), "test-access-token")
	}

	// The received verifier is the relying party's copy, not one taken out of
	// the enclave: hashing it is how the token endpoint itself checks PKCE.
	received := form.Get("code_verifier")
	if received == "" {
		t.Fatal("token endpoint received no code_verifier")
	}
	if got := challengeOf(received); got != challenge {
		t.Errorf("received verifier hashes to %q, want the committed challenge %q", got, challenge)
	}
	if len(form["code_verifier"]) != 1 {
		t.Errorf("Expected exactly one code_verifier field, got %d", len(form["code_verifier"]))
	}

	// The rest of the body must survive hand-assembly intact.
	for field, want := range map[string]string{
		"grant_type":    "authorization_code",
		"code":          "test-code",
		"client_id":     "test-client",
		"client_secret": "test-secret",
		"redirect_uri":  "http://localhost:8080/callback",
	} {
		if got := form.Get(field); got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
	}

	// The exchange consumes the verifier: RFC 7636 gives it one code to redeem.
	if size := verifier.Size(); size != 0 {
		t.Errorf("verifier.Size() after the exchange = %d, want 0 (destroyed)", size)
	}
	if _, err := auth.ExchangeAuthorizationCodePKCE(context.Background(), "test-code", verifier); !errors.Is(err, ErrTokenExchangeFailed) {
		t.Errorf("Reusing a consumed verifier = %v, want ErrTokenExchangeFailed", err)
	}
}

// TestNewVerifierRejectsBadVerifiers keeps the public constructor fail-closed:
// a verifier that is malformed, or that holds anything form encoding would have
// to escape, never becomes a Verifier at all.
func TestNewVerifierRejectsBadVerifiers(t *testing.T) {
	for _, value := range []string{
		"",
		strings.Repeat("a", 42),
		strings.Repeat("a", 129),
		strings.Repeat("a", 42) + "%",
		strings.Repeat("a", 42) + "&",
		strings.Repeat("a", 42) + " ",
	} {
		sealed := sealedForTest(t, value)
		if _, err := NewVerifier(sealed); !errors.Is(err, ErrInvalidConfiguration) {
			t.Errorf("NewVerifier(%d chars) = %v, want ErrInvalidConfiguration", len(value), err)
		}
		// NewVerifier owns what it is given on every path, so a rejected
		// verifier is destroyed rather than left with the caller.
		if sealed.IsAlive() {
			t.Errorf("NewVerifier(%d chars) rejected the verifier but left it alive", len(value))
		}
	}
}

// TestExchangeAuthorizationCodePKCERejectsBadVerifiers is the second gate: even
// a Verifier assembled inside this package, bypassing NewVerifier's check, is
// refused before the request rather than escaped into the body.
func TestExchangeAuthorizationCodePKCERejectsBadVerifiers(t *testing.T) {
	server, calls := newRecordingTokenEndpoint(t)

	auth, err := NewAuthenticator(pkceTestConfig(t, server.URL+"/token"))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	consumed, _, err := newVerifier()
	if err != nil {
		t.Fatalf("newVerifier() failed: %v", err)
	}
	consumed.Destroy()

	cases := []struct {
		name     string
		verifier func(t *testing.T) *Verifier
	}{
		{"nil", func(*testing.T) *Verifier { return nil }},
		{"consumed", func(*testing.T) *Verifier { return consumed }},
		{"too short", unvalidatedVerifier(strings.Repeat("a", 42))},
		{"too long", unvalidatedVerifier(strings.Repeat("a", 129))},
		{"needs escaping", unvalidatedVerifier(strings.Repeat("a", 42) + "%")},
		{"holds a separator", unvalidatedVerifier(strings.Repeat("a", 42) + "&")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := tc.verifier(t)
			if _, err := auth.ExchangeAuthorizationCodePKCE(context.Background(), "test-code", verifier); !errors.Is(err, ErrTokenExchangeFailed) {
				t.Errorf("ExchangeAuthorizationCodePKCE() = %v, want ErrTokenExchangeFailed", err)
			}
		})
	}

	if *calls != 0 {
		t.Errorf("A rejected verifier still reached the token endpoint %d time(s)", *calls)
	}
}

// unvalidatedVerifier builds a Verifier around a value NewVerifier would have
// refused, so the exchange's own check is exercised rather than shadowed.
func unvalidatedVerifier(value string) func(t *testing.T) *Verifier {
	return func(t *testing.T) *Verifier {
		t.Helper()

		sealed, err := enclave.NewMemoryEnclave([]byte(value))
		if err != nil {
			t.Fatalf("NewMemoryEnclave: %v", err)
		}
		return &Verifier{sealed: sealed}
	}
}

// TestValidatePKCEVerifier pins RFC 7636 §4.1 exactly, because the exchange
// relies on it instead of escaping: a character this admits and form encoding
// would escape is a corrupted request body, not a cosmetic bug.
//
// The lengths here are the RFC's literals, not the package's constants. A test
// written against the constants moves whenever they do and cannot catch a bound
// that drifts away from the spec.
func TestValidatePKCEVerifier(t *testing.T) {
	if pkceMinVerifierLen != 43 || pkceMaxVerifierLen != 128 {
		t.Fatalf("verifier bounds are %d..%d, RFC 7636 §4.1 says 43..128",
			pkceMinVerifierLen, pkceMaxVerifierLen)
	}
	if pkceVerifierLen != base64.RawURLEncoding.EncodedLen(pkceVerifierBytes) {
		t.Fatalf("pkceVerifierLen = %d, want the encoded length of %d bytes",
			pkceVerifierLen, pkceVerifierBytes)
	}

	valid := []string{
		strings.Repeat("a", 43),
		strings.Repeat("a", 128),
		strings.Repeat("a", 39) + "-._~",
		strings.Repeat("Z", 42) + "9",
	}
	for _, v := range valid {
		if err := validatePKCEVerifier([]byte(v)); err != nil {
			t.Errorf("validatePKCEVerifier(%d chars) = %v, want nil", len(v), err)
		}
	}

	invalid := []string{
		"",
		strings.Repeat("a", 42),
		strings.Repeat("a", 129),
	}
	// Every byte outside the unreserved set must be rejected, not escaped.
	for c := 0; c < 256; c++ {
		b := byte(c)
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		case b == '-', b == '.', b == '_', b == '~':
		default:
			invalid = append(invalid, strings.Repeat("a", 42)+string(b))
		}
	}

	for _, v := range invalid {
		if err := validatePKCEVerifier([]byte(v)); err == nil {
			t.Errorf("validatePKCEVerifier(%d chars, %q) = nil, want an error", len(v), v)
		}
	}
}

// TestPKCEVerifierSurvivesFormEncoding is the assumption validatePKCEVerifier
// exists to hold: url.Values.Encode leaves every admitted character alone, so
// copying the verifier into the body is equivalent to encoding it.
func TestPKCEVerifierSurvivesFormEncoding(t *testing.T) {
	unreserved := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"

	if err := validatePKCEVerifier([]byte(unreserved)); err != nil {
		t.Fatalf("the unreserved set is not a valid verifier: %v", err)
	}

	encoded := url.Values{"code_verifier": {unreserved}}.Encode()
	if want := "code_verifier=" + unreserved; encoded != want {
		t.Errorf("form encoding altered the verifier:\n got %q\nwant %q", encoded, want)
	}
}

// TestBuildAuthURLPKCERequiresTheAuthorizationCodeFlow keeps the guard that the
// deprecated method has.
func TestBuildAuthURLPKCERequiresTheAuthorizationCodeFlow(t *testing.T) {
	server, calls := newRecordingTokenEndpoint(t)

	config := pkceTestConfig(t, server.URL+"/token")
	config.Flow = FlowClientCredentials

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	if _, _, err := auth.BuildAuthURLPKCE("random-state", nil); !errors.Is(err, ErrFlowNotSupported) {
		t.Errorf("BuildAuthURLPKCE() = %v, want ErrFlowNotSupported", err)
	}

	verifier, _, err := newVerifier()
	if err != nil {
		t.Fatalf("newVerifier() failed: %v", err)
	}
	if _, err := auth.ExchangeAuthorizationCodePKCE(context.Background(), "test-code", verifier); !errors.Is(err, ErrFlowNotSupported) {
		t.Errorf("ExchangeAuthorizationCodePKCE() = %v, want ErrFlowNotSupported", err)
	}
	if size := verifier.Size(); size != 0 {
		t.Errorf("A rejected exchange left the verifier alive (Size = %d)", size)
	}
	if *calls != 0 {
		t.Errorf("A rejected exchange still reached the token endpoint %d time(s)", *calls)
	}
}

// TestExchangeAuthorizationCodePKCERequiresACode keeps the empty-code guard the
// string path has, and proves it does not spend the verifier on a request it
// was never going to make.
func TestExchangeAuthorizationCodePKCERequiresACode(t *testing.T) {
	server, calls := newRecordingTokenEndpoint(t)

	auth, err := NewAuthenticator(pkceTestConfig(t, server.URL+"/token"))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	verifier, _, err := newVerifier()
	if err != nil {
		t.Fatalf("newVerifier() failed: %v", err)
	}

	if _, err := auth.ExchangeAuthorizationCodePKCE(context.Background(), "   ", verifier); !errors.Is(err, ErrTokenExchangeFailed) {
		t.Errorf("ExchangeAuthorizationCodePKCE() = %v, want ErrTokenExchangeFailed", err)
	}
	if *calls != 0 {
		t.Errorf("An empty authorization code still reached the token endpoint %d time(s)", *calls)
	}
}

// TestExchangeAuthorizationCodePKCEHonoursContext makes sure the protected path
// checks the context the way the string path does.
func TestExchangeAuthorizationCodePKCEHonoursContext(t *testing.T) {
	server, calls := newRecordingTokenEndpoint(t)

	auth, err := NewAuthenticator(pkceTestConfig(t, server.URL+"/token"))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	verifier, _, err := newVerifier()
	if err != nil {
		t.Fatalf("newVerifier() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := auth.ExchangeAuthorizationCodePKCE(ctx, "test-code", verifier); !errors.Is(err, context.Canceled) {
		t.Errorf("ExchangeAuthorizationCodePKCE() = %v, want context.Canceled", err)
	}
	if *calls != 0 {
		t.Errorf("A canceled context still reached the token endpoint %d time(s)", *calls)
	}
}

// TestRequestBodyRefusesReadsAfterRelease is the guard on the locked request
// body. net/http can return a response before it has finished writing the body,
// so the transport may read after the exchange has returned and unmapped the
// buffer. A read then has to fail, not touch the memory.
func TestRequestBodyRefusesReadsAfterRelease(t *testing.T) {
	body := &requestBody{buf: []byte("grant_type=authorization_code")}

	buf := make([]byte, 8)
	if n, err := body.Read(buf); err != nil || n != 8 {
		t.Fatalf("Read() = %d, %v, want 8, nil", n, err)
	}

	body.release()

	if n, err := body.Read(buf); err == nil {
		t.Errorf("Read() after release = %d, nil, want an error", n)
	} else if errors.Is(err, io.EOF) {
		t.Error("Read() after release reported EOF, which a transport treats as a complete body")
	}

	body.release() // idempotent
}

// TestRequestBodyRewindReplaysTheWholeBody covers the redirect path: GetBody has
// to hand back a reader positioned at the start.
func TestRequestBodyRewindReplaysTheWholeBody(t *testing.T) {
	const payload = "grant_type=authorization_code&code=abc"
	body := &requestBody{buf: []byte(payload)}

	first, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(first) != payload {
		t.Fatalf("first read = %q, want %q", first, payload)
	}

	second, err := io.ReadAll(body.rewind())
	if err != nil {
		t.Fatalf("ReadAll after rewind: %v", err)
	}
	if string(second) != payload {
		t.Errorf("replayed body = %q, want %q", second, payload)
	}
}

// TestTokenRequestIsLengthDelimited pins the framing. A body read from a reader
// net/http does not recognize would be sent chunked, which a token endpoint is
// under no obligation to accept.
func TestTokenRequestIsLengthDelimited(t *testing.T) {
	var length int64
	var transferEncoding []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		length = r.ContentLength
		transferEncoding = r.TransferEncoding

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
		}); err != nil {
			t.Errorf("failed to encode token response: %v", err)
		}
	}))
	defer server.Close()

	auth, err := NewAuthenticator(pkceTestConfig(t, server.URL+"/token"))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	_, verifier, err := auth.BuildAuthURLPKCE("random-state", nil)
	if err != nil {
		t.Fatalf("BuildAuthURLPKCE() failed: %v", err)
	}
	if _, err := auth.ExchangeAuthorizationCodePKCE(context.Background(), "test-code", verifier); err != nil {
		t.Fatalf("ExchangeAuthorizationCodePKCE() failed: %v", err)
	}

	if length <= 0 {
		t.Errorf("token request Content-Length = %d, want the body length", length)
	}
	if len(transferEncoding) != 0 {
		t.Errorf("token request was sent with Transfer-Encoding %v, want length-delimited", transferEncoding)
	}
}

// bodyRetainingClient keeps the request it was handed instead of consuming it,
// standing in for a transport that is still writing the body when Do returns.
type bodyRetainingClient struct {
	req *http.Request
}

func (c *bodyRetainingClient) Do(req *http.Request) (*http.Response, error) {
	c.req = req

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"access_token":"test-access-token","token_type":"Bearer"}`)),
	}, nil
}

// TestExchangeReleasesTheRequestBody proves the guard is armed: the exchange
// releases the borrowed body before it returns, so a transport that reads late
// gets an error rather than the locked buffer the exchange is about to unmap.
func TestExchangeReleasesTheRequestBody(t *testing.T) {
	client := &bodyRetainingClient{}
	handler := newFlowHandler(pkceTestConfig(t, "https://example.test/token"), client)

	sealed, _, err := newPKCEVerifier()
	if err != nil {
		t.Fatalf("newPKCEVerifier() failed: %v", err)
	}
	defer sealed.Destroy()

	if _, err := handler.exchangeAuthorizationCodePKCE(context.Background(), "test-code", sealed); err != nil {
		t.Fatalf("exchangeAuthorizationCodePKCE() failed: %v", err)
	}

	if client.req == nil {
		t.Fatal("the exchange made no request")
	}
	if _, err := client.req.Body.Read(make([]byte, 1)); err == nil {
		t.Error("the request body was still readable after the exchange returned")
	} else if errors.Is(err, io.EOF) {
		t.Error("the request body reported EOF after the exchange returned, which a transport reads as a complete body")
	}
}

// TestExchangeAuthorizationCodePKCEIsSingleUseUnderConcurrency is the race the
// consume-under-lock design exists for. The first exchange is held inside the
// token endpoint while a second call is made with the same verifier: the second
// must be refused before it reaches the network, so one login cannot produce two
// redemption attempts.
func TestExchangeAuthorizationCodePKCEIsSingleUseUnderConcurrency(t *testing.T) {
	var mu sync.Mutex
	calls := 0

	arrived := make(chan struct{})
	release := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()

		if first {
			close(arrived)
			<-release
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
		}); err != nil {
			t.Errorf("failed to encode token response: %v", err)
		}
	}))
	defer server.Close()

	auth, err := NewAuthenticator(pkceTestConfig(t, server.URL+"/token"))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	_, verifier, err := auth.BuildAuthURLPKCE("random-state", nil)
	if err != nil {
		t.Fatalf("BuildAuthURLPKCE() failed: %v", err)
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := auth.ExchangeAuthorizationCodePKCE(context.Background(), "test-code", verifier)
		firstDone <- err
	}()

	// The first exchange is now inside the handler, holding the connection: its
	// verifier is already consumed, and its request has not finished.
	<-arrived

	if _, err := auth.ExchangeAuthorizationCodePKCE(context.Background(), "test-code", verifier); !errors.Is(err, ErrVerifierConsumed) {
		t.Errorf("Concurrent second exchange = %v, want ErrVerifierConsumed", err)
	} else if !errors.Is(err, ErrTokenExchangeFailed) {
		t.Errorf("Concurrent second exchange = %v, want it to also be an ErrTokenExchangeFailed", err)
	}

	close(release)

	if err := <-firstDone; err != nil {
		t.Fatalf("First exchange failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("The token endpoint saw %d redemption attempts for one verifier, want 1", calls)
	}
}

// TestNewVerifierRedeemsACallerSealedVerifier covers a verifier the caller
// already holds in an enclave — restored from its own sealed session store, say.
// NewVerifier takes the enclave over and the exchange consumes it; nothing comes
// back out.
func TestNewVerifierRedeemsACallerSealedVerifier(t *testing.T) {
	var form url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		form = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-access-token","token_type":"Bearer"}`))
	}))
	defer server.Close()

	auth, err := NewAuthenticator(pkceTestConfig(t, server.URL+"/token"))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	defer auth.Close()

	const value = "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEF"
	held := sealedForTest(t, value)

	verifier, err := NewVerifier(held)
	if err != nil {
		t.Fatalf("NewVerifier() failed: %v", err)
	}
	if verifier.Size() != len(value) {
		t.Errorf("Verifier Size = %d, want %d", verifier.Size(), len(value))
	}

	token, err := auth.ExchangeAuthorizationCodePKCE(context.Background(), "test-code", verifier)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCodePKCE() failed: %v", err)
	}
	defer token.Destroy()

	if got := form.Get("code_verifier"); got != value {
		t.Errorf("token endpoint received code_verifier %q, want %q", got, value)
	}
	if verifier.Size() != 0 || held.IsAlive() {
		t.Error("the exchange did not consume and destroy the verifier")
	}
}

// TestVerifierHasNoPlaintextExport pins the invariant the review turned on: no
// exported method hands a Verifier's value to caller code. A future convenience
// that reintroduces one has to delete this test to do it.
func TestVerifierHasNoPlaintextExport(t *testing.T) {
	verifierType := reflect.TypeOf(&Verifier{})

	allowed := map[string]bool{
		"Size":     true,
		"Destroy":  true,
		"String":   true,
		"GoString": true,
	}

	for i := 0; i < verifierType.NumMethod(); i++ {
		if name := verifierType.Method(i).Name; !allowed[name] {
			t.Errorf("Verifier has an unexpected exported method %q: a Verifier must not be able to hand its value to caller code", name)
		}
	}
}

// TestVerifierRedactsWhenFormatted keeps a stray %v or log field from printing a
// credential.
func TestVerifierRedactsWhenFormatted(t *testing.T) {
	verifier, err := NewVerifier(sealedForTest(t, strings.Repeat("a", 43)))
	if err != nil {
		t.Fatalf("NewVerifier() failed: %v", err)
	}
	defer verifier.Destroy()

	for _, rendered := range []string{
		fmt.Sprintf("%v", verifier),
		fmt.Sprintf("%s", verifier),
		fmt.Sprintf("%#v", verifier),
		fmt.Sprintf("%+v", verifier),
	} {
		if strings.Contains(rendered, strings.Repeat("a", 43)) {
			t.Errorf("A formatted Verifier printed the code verifier: %s", rendered)
		}
	}
}

// TestBuildAuthURLRejectsReservedParams fails closed on a caller that would
// otherwise decouple the authorization URL from the state or the verifier it was
// handed — silently, with the failure surfacing much later at the token endpoint.
func TestBuildAuthURLRejectsReservedParams(t *testing.T) {
	auth, err := NewAuthenticator(pkceTestConfig(t, "https://example.test/token"))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	reserved := []string{
		"code_challenge",
		"code_challenge_method",
		"state",
		"client_id",
		"redirect_uri",
		"response_type",
		"scope",
	}

	for _, key := range reserved {
		params := map[string]string{key: "attacker-supplied"}

		if _, _, err := auth.BuildAuthURLPKCE("random-state", params); !errors.Is(err, ErrInvalidConfiguration) {
			t.Errorf("BuildAuthURLPKCE(%q) = %v, want ErrInvalidConfiguration", key, err)
		}
		if _, err := auth.BuildAuthURL("random-state", params); !errors.Is(err, ErrInvalidConfiguration) {
			t.Errorf("BuildAuthURL(%q) = %v, want ErrInvalidConfiguration", key, err)
		}
	}

	// A provider-specific parameter is still allowed: this is a reserved-key
	// check, not an allowlist.
	if _, _, err := auth.BuildAuthURLPKCE("random-state", map[string]string{"prompt": "consent"}); err != nil {
		t.Errorf("BuildAuthURLPKCE with a provider parameter failed: %v", err)
	}
}

// TestBuildAuthURLPKCEDoesNotLeakTheVerifierOnAnError pins the cleanup path: a
// URL that is never built must not leave a live credential behind.
func TestBuildAuthURLPKCEDoesNotLeakTheVerifierOnAnError(t *testing.T) {
	auth, err := NewAuthenticator(pkceTestConfig(t, "https://example.test/token"))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	_, verifier, err := auth.BuildAuthURLPKCE("random-state", map[string]string{"code_challenge": "attacker-supplied"})
	if err == nil {
		t.Fatal("BuildAuthURLPKCE() accepted a reserved parameter")
	}
	if verifier != nil {
		t.Errorf("BuildAuthURLPKCE() returned a verifier alongside an error: %v", verifier)
	}
}
