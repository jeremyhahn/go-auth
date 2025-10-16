package yubikey

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
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

func (v *HTTPValidator) Validate(ctx context.Context, clientID, apiKey, otp string) error {
	nonce, err := randomNonce()
	if err != nil {
		return err
	}

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
		return errors.New("yubikey: response nonce mismatch")
	}
	if responseValues.Get("otp") != otp {
		return errors.New("yubikey: response otp mismatch")
	}

	responseSignature := responseValues.Get("h")
	responseValues.Del("h")

	expectedSig, err := computeSignature(responseValues, apiKey)
	if err != nil {
		return err
	}

	if !hmac.Equal([]byte(responseSignature), []byte(expectedSig)) {
		return errors.New("yubikey: response signature invalid")
	}

	return nil
}

func computeSignature(values url.Values, apiKey string) (string, error) {
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

	mac := hmac.New(sha1.New, decodeAPIKey(apiKey))
	mac.Write([]byte(builder.String()))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func decodeAPIKey(key string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return []byte(key)
	}
	return decoded
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
