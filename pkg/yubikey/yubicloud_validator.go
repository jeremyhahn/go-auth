// The YubiCloud validator needs HMAC-SHA-1, so under GODEBUG=fips140=only every entry point returns ErrFIPSUnsupported. See docs/fips.md.

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

// Validate signs the request and verifies the response with the borrowed API key; the OTP is a wiped transient string (residue R5).
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
