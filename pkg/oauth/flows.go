package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
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
	tokenURL := f.config.Provider.TokenURL()
	if tokenURL == "" {
		return nil, fmt.Errorf("%w: token url not configured", ErrTokenExchangeFailed)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrTokenExchangeFailed, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d: %s", ErrTokenExchangeFailed, resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		IDToken      string `json:"id_token"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
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
func (f *flowHandler) buildAuthURL(state string, codeChallenge string, additionalParams map[string]string) string {
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
		return authURL + "&" + params.Encode()
	}
	return authURL + "?" + params.Encode()
}
