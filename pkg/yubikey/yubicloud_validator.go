// The YubiCloud validator is in every build and refuses to run when FIPS is
// activated.
//
// Yubico Validation Protocol 2.0 signs every request and response with
// HMAC-SHA-1 over the sorted parameter list (computeSignature below), and the
// service rejects any other digest. Go's fips140=only mode admits HMAC over
// SHA-2 and SHA-3 only, so under that activation every entry point here
// returns ErrFIPSUnsupported (fips.go) instead of reaching the HMAC, and
// NewAuthenticator refuses to construct around this validator. init() still
// installs it as the package default in every build. The rest of pkg/yubikey
// is unaffected: an injected OTPValidator that speaks to an approved
// validation service works normally. See docs/fips.md.

package yubikey

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	// SHA-1 is protocol-mandated: Yubico Validation Protocol 2.0 signs with HMAC-SHA1, used only in HMAC.
	"crypto/sha1" // #nosec G505 -- Yubico Validation Protocol 2.0 signs with HMAC-SHA1 by definition
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
)

var (
	// ErrResponseNonceMismatch indicates the validation service answered a
	// request other than the one sent.
	ErrResponseNonceMismatch = errors.New("yubikey: response nonce mismatch")
	// ErrResponseOTPMismatch indicates the validation service answered for an
	// OTP other than the one sent.
	ErrResponseOTPMismatch = errors.New("yubikey: response otp mismatch")
	// ErrResponseSignatureInvalid indicates the response was not signed with
	// the configured API key.
	ErrResponseSignatureInvalid = errors.New("yubikey: response signature invalid")
)

// HTTPValidator validates YubiKey OTPs against the public YubiCloud service.
type HTTPValidator struct {
	client   *http.Client
	endpoint string
}

// NewHTTPValidator constructs a validator that talks to the YubiCloud API. If
// client is nil http.DefaultClient is used. Endpoint can be left empty to use
// the default Yubico verify URL.
func NewHTTPValidator(client *http.Client, endpoint string) *HTTPValidator {
	if client == nil {
		client = http.DefaultClient
	}
	if endpoint == "" {
		endpoint = "https://api.yubico.com/wsapi/2.0/verify"
	}
	return &HTTPValidator{client: client, endpoint: endpoint}
}

func init() {
	systemValidator = NewHTTPValidator(nil, "")
}

// Validate implements OTPValidator: it signs the request and verifies the
// response signature with the API key borrowed from its enclave, and never
// materializes the key as a string.
//
// The OTP has to travel in the request's query string, so it is lent to
// net/url and net/http as a string that is wiped when Validate returns; their
// own copies (the encoded URL, the request line) are residue R5.
//
// Under FIPS activation it returns ErrFIPSUnsupported before any request is
// built or sent.
func (v *HTTPValidator) Validate(ctx context.Context, clientID string, apiKey, otp *enclave.MemoryEnclave) error {
	if fips140OnlyActive() {
		return ErrFIPSUnsupported
	}
	nonce, err := randomNonce()
	if err != nil {
		return err
	}

	// Residue R5: the OTP is a query parameter, which net/url and net/http
	// only carry as strings.
	return credential.WithTransientString(otp, func(otp string) error {
		return v.exchange(ctx, clientID, apiKey, otp, nonce)
	})
}

func (v *HTTPValidator) exchange(ctx context.Context, clientID string, apiKey *enclave.MemoryEnclave, otp, nonce string) error {
	params := url.Values{}
	params.Set("id", clientID)
	params.Set("otp", otp)
	params.Set("nonce", nonce)
	params.Set("timestamp", "1")

	signature, err := computeSignature(params, apiKey)
	if err != nil {
		return err
	}

	requestURL := fmt.Sprintf("%s?%s&h=%s", v.endpoint, params.Encode(), url.QueryEscape(signature))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	responseValues := parseResponse(string(body))
	if responseValues.Get("status") != "OK" {
		return ErrInvalidOTP
	}
	if responseValues.Get("nonce") != nonce {
		return ErrResponseNonceMismatch
	}
	if !hmac.Equal([]byte(responseValues.Get("otp")), []byte(otp)) {
		return ErrResponseOTPMismatch
	}

	responseSignature := responseValues.Get("h")
	responseValues.Del("h")

	expectedSig, err := computeSignature(responseValues, apiKey)
	if err != nil {
		return err
	}

	if !hmac.Equal([]byte(responseSignature), []byte(expectedSig)) {
		return ErrResponseSignatureInvalid
	}

	return nil
}

// computeSignature HMACs the sorted parameters with the API key decoded into locked memory, and carries the FIPS gate.
func computeSignature(values url.Values, apiKey *enclave.MemoryEnclave) (string, error) {
	if fips140OnlyActive() {
		return "", ErrFIPSUnsupported
	}
	var signature string
	err := apiKey.WithBytes(func(encoded []byte) error {
		return withDecodedAPIKey(encoded, func(key []byte) error {
			signed, err := signValues(values, key)
			if err != nil {
				return err
			}
			signature = signed
			return nil
		})
	})
	if err != nil {
		return "", fmt.Errorf("yubikey: sign request: %w", err)
	}
	return signature, nil
}

// withDecodedAPIKey base64-decodes the API key into a locked scratch enclave for fn; a non-base64 key is used as raw bytes.
func withDecodedAPIKey(encoded []byte, fn func(key []byte) error) (err error) {
	// A key under two characters can only be raw.
	size := base64.StdEncoding.DecodedLen(len(encoded))
	if size == 0 {
		return fn(encoded)
	}

	scratch, err := enclave.NewMemoryEnclaveSized(size)
	if err != nil {
		return err
	}
	defer func() {
		err = credential.DestroyAll(err, scratch)
	}()

	return scratch.WithBytes(func(buf []byte) error {
		n, err := base64.StdEncoding.Decode(buf, encoded)
		if err != nil {
			return fn(encoded)
		}
		return fn(buf[:n])
	})
}

func signValues(values url.Values, key []byte) (string, error) {
	copied := url.Values{}
	for k, v := range values {
		if k == "h" {
			continue
		}
		copied[k] = append([]string(nil), v...)
	}

	keys := make([]string, 0, len(copied))
	for k := range copied {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var builder strings.Builder
	for i, k := range keys {
		if i > 0 {
			builder.WriteByte('&')
		}
		builder.WriteString(k)
		builder.WriteByte('=')
		builder.WriteString(strings.Join(copied[k], ""))
	}

	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(builder.String()))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func randomNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func parseResponse(body string) url.Values {
	values := url.Values{}
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		values.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	return values
}
