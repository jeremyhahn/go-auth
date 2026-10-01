package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-enclave"
)

// flowHandler manages OAuth 2.0 flows for obtaining tokens.
type flowHandler struct {
	config     *Config
	httpClient HTTPClient
}

// newFlowHandler creates a new OAuth flow handler.
func newFlowHandler(config *Config, httpClient HTTPClient) *flowHandler {
	return &flowHandler{
		config:     config,
		httpClient: httpClient,
	}
}

// clientSecretFields returns the client_secret form field, or none for a
// public client. A secret that was configured and has since been destroyed —
// by Close — is still returned, so the request fails closed with
// ErrCredentialUnavailable instead of silently going out unauthenticated.
func (f *flowHandler) clientSecretFields() []sealedFormField {
	if f.config.ClientSecret == nil {
		return nil
	}
	return []sealedFormField{{name: "client_secret", value: f.config.ClientSecret}}
}

// exchangeAuthorizationCode exchanges an authorization code for tokens without
// PKCE.
func (f *flowHandler) exchangeAuthorizationCode(ctx context.Context, code string) (*Token, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("%w: authorization code is required", ErrTokenExchangeFailed)
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", f.config.ClientID)
	data.Set("redirect_uri", f.config.RedirectURL)

	return f.postTokenRequest(ctx, data, f.clientSecretFields())
}

// exchangeAuthorizationCodePKCE exchanges an authorization code for tokens with
// a PKCE verifier held in protected memory.
//
// The verifier is checked against RFC 7636 inside its enclave and then
// form-escaped from the enclave straight into the locked request body — see
// withFormBody. Every character the check admits is unreserved, so the escape
// is a copy.
func (f *flowHandler) exchangeAuthorizationCodePKCE(ctx context.Context, code string, verifier *enclave.MemoryEnclave) (*Token, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("%w: authorization code is required", ErrTokenExchangeFailed)
	}

	if verifier.Size() == 0 {
		return nil, fmt.Errorf("%w: code verifier is missing or already destroyed", ErrTokenExchangeFailed)
	}

	if err := verifier.WithBytes(validatePKCEVerifier); err != nil {
		return nil, errors.Join(ErrTokenExchangeFailed, err)
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", f.config.ClientID)
	data.Set("redirect_uri", f.config.RedirectURL)

	sealed := append(f.clientSecretFields(), sealedFormField{name: "code_verifier", value: verifier})
	return f.postTokenRequest(ctx, data, sealed)
}

// authenticateClientCredentials performs the client credentials flow. The
// client secret is required, so it is sent even when nil and fails closed.
func (f *flowHandler) authenticateClientCredentials(ctx context.Context) (*Token, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", f.config.ClientID)

	if len(f.config.Scopes) > 0 {
		data.Set("scope", strings.Join(f.config.Scopes, " "))
	}

	return f.postTokenRequest(ctx, data, []sealedFormField{
		{name: "client_secret", value: f.config.ClientSecret},
	})
}

// authenticatePassword performs the resource owner password credentials flow.
// The password is borrowed, not destroyed.
func (f *flowHandler) authenticatePassword(ctx context.Context, username string, password *enclave.MemoryEnclave) (*Token, error) {
	if strings.TrimSpace(username) == "" || !password.IsAlive() {
		return nil, fmt.Errorf("%w: username and password are required", ErrTokenExchangeFailed)
	}

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("username", username)
	data.Set("client_id", f.config.ClientID)

	if len(f.config.Scopes) > 0 {
		data.Set("scope", strings.Join(f.config.Scopes, " "))
	}

	return f.postTokenRequest(ctx, data, []sealedFormField{
		{name: "password", value: password},
		{name: "client_secret", value: f.config.ClientSecret},
	})
}

// refreshToken uses a refresh token to obtain a new access token. The refresh
// token is borrowed, not destroyed.
func (f *flowHandler) refreshToken(ctx context.Context, refreshToken *enclave.MemoryEnclave) (*Token, error) {
	if !refreshToken.IsAlive() {
		return nil, fmt.Errorf("%w: refresh token is required", ErrTokenExchangeFailed)
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", f.config.ClientID)

	if len(f.config.Scopes) > 0 {
		data.Set("scope", strings.Join(f.config.Scopes, " "))
	}

	sealed := append([]sealedFormField{{name: "refresh_token", value: refreshToken}}, f.clientSecretFields()...)
	return f.postTokenRequest(ctx, data, sealed)
}

// postTokenRequest assembles the public and sealed parameters into a locked
// form body, posts it to the token endpoint and parses the token response.
func (f *flowHandler) postTokenRequest(ctx context.Context, public url.Values, sealed []sealedFormField) (*Token, error) {
	tokenURL := f.config.Provider.TokenURL()
	if tokenURL == "" {
		return nil, fmt.Errorf("%w: token url not configured", ErrTokenExchangeFailed)
	}

	var token *Token
	err := withFormBody(public, sealed, func(body []byte) error {
		var err error
		token, err = f.sendTokenRequest(ctx, tokenURL, body)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrTokenExchangeFailed) {
			return nil, err
		}
		// A credential that is missing, an enclave that cannot be opened, or
		// locked pages that cannot be had all fail the exchange — and stay
		// matchable, so ErrLockedMemoryUnavailable still reaches the caller.
		return nil, errors.Join(ErrTokenExchangeFailed, err)
	}

	return token, nil
}

// sendTokenRequest posts an encoded form body to the token endpoint and parses
// the token response.
//
// body is borrowed for the duration of the call and never retained: it is the
// locked scratch buffer withFormBody unmaps as soon as this returns, so keeping
// a reference here would be a use-after-free rather than a stale read. The
// borrowing is enforced rather than promised — see requestBody.
func (f *flowHandler) sendTokenRequest(ctx context.Context, tokenURL string, body []byte) (*Token, error) {
	req, reader, err := newFormRequest(ctx, tokenURL, body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}
	defer reader.release()

	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}
	defer resp.Body.Close()

	// Residue R5: the transport's response copies are not ours; this one is wiped.
	respBody, err := io.ReadAll(resp.Body)
	defer enclave.Wipe(respBody)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrTokenExchangeFailed, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d: %s", ErrTokenExchangeFailed, resp.StatusCode, string(respBody))
	}

	return parseTokenResponse(respBody)
}

// parseTokenResponse decodes a token endpoint response, sealing the access,
// refresh and ID tokens straight into enclaves.
//
// The credentials are decoded as raw JSON and unquoted directly into locked
// pages, so none of them is ever a Go string; the raw copies encoding/json
// makes are wiped before this returns. On any error every enclave already
// created is destroyed.
func parseTokenResponse(respBody []byte) (*Token, error) {
	var tokenResp struct {
		AccessToken  json.RawMessage `json:"access_token"`
		TokenType    string          `json:"token_type"`
		RefreshToken json.RawMessage `json:"refresh_token"`
		ExpiresIn    int64           `json:"expires_in"`
		Scope        string          `json:"scope"`
		IDToken      json.RawMessage `json:"id_token"`
	}
	defer func() {
		enclave.Wipe(tokenResp.AccessToken)
		enclave.Wipe(tokenResp.RefreshToken)
		enclave.Wipe(tokenResp.IDToken)
	}()

	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("%w: failed to parse response: %v", ErrTokenExchangeFailed, err)
	}

	token := &Token{TokenType: tokenResp.TokenType}

	fields := []struct {
		raw  json.RawMessage
		dest **enclave.MemoryEnclave
	}{
		{tokenResp.AccessToken, &token.accessToken},
		{tokenResp.RefreshToken, &token.refreshToken},
		{tokenResp.IDToken, &token.idToken},
	}
	for _, field := range fields {
		sealed, err := sealJSONString(field.raw)
		if err != nil {
			token.Destroy()
			return nil, errors.Join(ErrTokenExchangeFailed, err)
		}
		*field.dest = sealed
	}

	if token.accessToken == nil {
		token.Destroy()
		return nil, fmt.Errorf("%w: no access token in response", ErrTokenExchangeFailed)
	}

	if tokenResp.TokenType == "" {
		token.TokenType = "Bearer"
	}

	if tokenResp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	if tokenResp.Scope != "" {
		token.Scopes = splitScopes(tokenResp.Scope)
	}

	return token, nil
}

// newFormRequest builds a POST carrying body as an
// application/x-www-form-urlencoded request body that the transport can read
// only until the returned requestBody is released. The caller must release it
// before the bytes behind body go away.
func newFormRequest(ctx context.Context, target string, body []byte) (*http.Request, *requestBody, error) {
	reader := &requestBody{buf: body}

	// Residue R5: the transport copies the locked body into its own write buffers.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, reader)
	if err != nil {
		return nil, nil, err
	}

	// NewRequestWithContext only infers these for the reader types it knows.
	// Without them the request would be chunked, which token endpoints are not
	// obliged to accept, and a 307/308 redirect could not be replayed.
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(reader.rewind()), nil
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, reader, nil
}

// buildAuthURL builds the authorization URL for the authorization code flow.
// reservedAuthParams are the authorization-request parameters this package owns.
// A caller that could set them through additionalParams could decouple the URL
// from the state and PKCE verifier the caller was handed — the code_challenge
// case is the sharp one: the flow would fail at the token endpoint, long after
// the mistake, with nothing pointing back at it.
var reservedAuthParams = map[string]struct{}{
	"client_id":             {},
	"redirect_uri":          {},
	"response_type":         {},
	"state":                 {},
	"scope":                 {},
	"code_challenge":        {},
	"code_challenge_method": {},
}

func (f *flowHandler) buildAuthURL(state string, codeChallenge string, additionalParams map[string]string) (string, error) {
	for key := range additionalParams {
		if _, reserved := reservedAuthParams[key]; reserved {
			return "", fmt.Errorf("%w: %q is set by this package and cannot be passed in additionalParams", ErrInvalidConfiguration, key)
		}
	}

	params := url.Values{}
	params.Set("client_id", f.config.ClientID)
	params.Set("redirect_uri", f.config.RedirectURL)
	params.Set("response_type", "code")
	params.Set("state", state)

	if len(f.config.Scopes) > 0 {
		params.Set("scope", strings.Join(f.config.Scopes, " "))
	}

	// Add PKCE challenge if provided
	if codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	// Add any additional parameters
	for key, value := range additionalParams {
		params.Set(key, value)
	}

	authURL := f.config.Provider.AuthURL()
	if strings.Contains(authURL, "?") {
		return authURL + "&" + params.Encode(), nil
	}
	return authURL + "?" + params.Encode(), nil
}

// requestBody is a form body assembled in locked memory, readable only while
// the caller that owns the bytes is still inside the call it lent them for.
//
// net/http can return a response before it has finished writing the request
// body — a server that rejects the request early leaves the write in flight —
// so the transport may read from the body after Do has returned. For an
// ordinary heap body that is harmless. For the locked buffer withFormBody
// assembles, which is unmapped as soon as the request returns, a late read
// would fault the process rather than read stale bytes. release closes that
// window: a read after it returns an error instead of touching the memory.
type requestBody struct {
	mu  sync.Mutex
	buf []byte
	pos int
}

func (b *requestBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.buf == nil {
		return 0, ErrRequestBodyReleased
	}
	if b.pos >= len(b.buf) {
		return 0, io.EOF
	}

	n := copy(p, b.buf[b.pos:])
	b.pos += n
	return n, nil
}

// rewind restarts the body for a redirect replay. The replay cannot overlap the
// first attempt, so the two share one cursor.
func (b *requestBody) rewind() io.Reader {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.pos = 0
	return b
}

// release drops the reference to the borrowed bytes. It is idempotent.
func (b *requestBody) release() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.buf = nil
}
