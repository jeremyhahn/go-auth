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

	"golang.org/x/oauth2"

	"github.com/jeremyhahn/go-auth/pkg/secret"
)

// flowHandler manages OAuth 2.0 flows for obtaining tokens.
type flowHandler struct {
	config     *Config
	httpClient HTTPClient
	oauthCfg   *oauth2.Config
}

// newFlowHandler creates a new OAuth flow handler.
func newFlowHandler(config *Config, httpClient HTTPClient) *flowHandler {
	// Build golang.org/x/oauth2 config for supported flows
	oauthCfg := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.Provider.AuthURL(),
			TokenURL: config.Provider.TokenURL(),
		},
		Scopes:      config.Scopes,
		RedirectURL: config.RedirectURL,
	}

	return &flowHandler{
		config:     config,
		httpClient: httpClient,
		oauthCfg:   oauthCfg,
	}
}

// exchangeAuthorizationCode exchanges an authorization code for tokens.
func (f *flowHandler) exchangeAuthorizationCode(ctx context.Context, code, codeVerifier string) (*Token, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("%w: authorization code is required", ErrTokenExchangeFailed)
	}

	// Build token request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", f.config.ClientID)
	data.Set("redirect_uri", f.config.RedirectURL)

	if f.config.ClientSecret != "" {
		data.Set("client_secret", f.config.ClientSecret)
	}

	// Add PKCE code verifier if provided
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	return f.exchangeToken(ctx, data)
}

// exchangeAuthorizationCodePKCE exchanges an authorization code for tokens with
// a PKCE verifier held in protected memory.
//
// The request body is assembled in a locked scratch buffer: the public
// parameters are encoded first, then the verifier is copied out of its enclave
// directly into that buffer. No step of it produces a heap-allocated string
// holding the verifier, which the url.Values path would do twice — once in the
// map and once in Encode's output.
//
// The buffer is handed to net/http as the request body and released as soon as
// the exchange returns. What the transport then does with the bytes is the
// boundary of this package's control: it copies them into its own write buffer,
// which is ordinary heap. That copy is unavoidable without reimplementing the
// HTTP client, is short-lived, and is bounded by one request.
func (f *flowHandler) exchangeAuthorizationCodePKCE(ctx context.Context, code string, verifier *secret.Secret) (*Token, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("%w: authorization code is required", ErrTokenExchangeFailed)
	}

	size := verifier.Size()
	if size == 0 {
		return nil, fmt.Errorf("%w: code verifier is missing or already destroyed", ErrTokenExchangeFailed)
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", f.config.ClientID)
	data.Set("redirect_uri", f.config.RedirectURL)

	if f.config.ClientSecret != "" {
		data.Set("client_secret", f.config.ClientSecret)
	}

	const field = "&code_verifier="
	params := data.Encode()

	var token *Token
	err := secret.Scratch(len(params)+len(field)+size, func(body []byte) error {
		n := copy(body, params)
		n += copy(body[n:], field)

		return verifier.Open(func(v []byte) error {
			// Every character validatePKCEVerifier admits survives form
			// encoding unchanged, so the verifier is copied, not escaped.
			if err := validatePKCEVerifier(v); err != nil {
				return fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
			}
			if copy(body[n:], v) != size {
				return fmt.Errorf("%w: code verifier changed size during the exchange", ErrTokenExchangeFailed)
			}

			var err error
			token, err = f.postTokenRequest(ctx, body)
			return err
		})
	})
	if err != nil {
		if errors.Is(err, ErrTokenExchangeFailed) {
			return nil, err
		}
		// A locked buffer that cannot be allocated or an enclave that cannot be
		// opened both fail the exchange; neither carries a typed error of ours.
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}

	return token, nil
}

// authenticateClientCredentials performs the client credentials flow.
func (f *flowHandler) authenticateClientCredentials(ctx context.Context) (*Token, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", f.config.ClientID)
	data.Set("client_secret", f.config.ClientSecret)

	if len(f.config.Scopes) > 0 {
		data.Set("scope", strings.Join(f.config.Scopes, " "))
	}

	return f.exchangeToken(ctx, data)
}

// authenticatePassword performs the resource owner password credentials flow.
func (f *flowHandler) authenticatePassword(ctx context.Context, username, password string) (*Token, error) {
	if strings.TrimSpace(username) == "" || password == "" {
		return nil, fmt.Errorf("%w: username and password are required", ErrTokenExchangeFailed)
	}

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("username", username)
	data.Set("password", password)
	data.Set("client_id", f.config.ClientID)
	data.Set("client_secret", f.config.ClientSecret)

	if len(f.config.Scopes) > 0 {
		data.Set("scope", strings.Join(f.config.Scopes, " "))
	}

	return f.exchangeToken(ctx, data)
}

// refreshToken uses a refresh token to obtain a new access token.
func (f *flowHandler) refreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, fmt.Errorf("%w: refresh token is required", ErrTokenExchangeFailed)
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", f.config.ClientID)

	if f.config.ClientSecret != "" {
		data.Set("client_secret", f.config.ClientSecret)
	}

	if len(f.config.Scopes) > 0 {
		data.Set("scope", strings.Join(f.config.Scopes, " "))
	}

	return f.exchangeToken(ctx, data)
}

// exchangeToken exchanges credentials for an OAuth token.
func (f *flowHandler) exchangeToken(ctx context.Context, data url.Values) (*Token, error) {
	return f.postTokenRequest(ctx, []byte(data.Encode()))
}

// postTokenRequest posts an encoded form body to the token endpoint and parses
// the token response.
//
// body is borrowed for the duration of the call and never retained: callers pass
// a locked buffer that is unmapped as soon as they return, so keeping a
// reference here would be a use-after-free rather than a stale read. The
// borrowing is enforced rather than promised — see requestBody.
func (f *flowHandler) postTokenRequest(ctx context.Context, body []byte) (*Token, error) {
	tokenURL := f.config.Provider.TokenURL()
	if tokenURL == "" {
		return nil, fmt.Errorf("%w: token url not configured", ErrTokenExchangeFailed)
	}

	reader := &requestBody{buf: body}
	defer reader.release()

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}

	// NewRequestWithContext only infers these for the reader types it knows.
	// Without them the request would be chunked, which token endpoints are not
	// obliged to accept, and a 307/308 redirect could not be replayed.
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(reader.rewind()), nil
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrTokenExchangeFailed, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d: %s", ErrTokenExchangeFailed, resp.StatusCode, string(respBody))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		IDToken      string `json:"id_token"`
	}

	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("%w: failed to parse response: %v", ErrTokenExchangeFailed, err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("%w: no access token in response", ErrTokenExchangeFailed)
	}

	token := &Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
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

// requestBody is the token request's form body, readable only while the caller
// that owns the bytes is still inside the call it lent them for.
//
// net/http can return a response before it has finished writing the request
// body — a server that rejects the request early leaves the write in flight —
// so the transport may read from the body after Do has returned. For an
// ordinary heap body that is harmless. For the locked buffer the PKCE exchange
// assembles, which is unmapped as soon as the exchange returns, a late read
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
		return 0, errors.New("oauth: request body was released before it was fully written")
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
