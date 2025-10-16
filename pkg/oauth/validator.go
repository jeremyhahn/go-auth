package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// tokenValidator handles token validation using JWT and/or introspection.
type tokenValidator struct {
	config     *Config
	httpClient HTTPClient
	jwks       keyfunc.Keyfunc
	jwksMu     sync.RWMutex
}

// newTokenValidator creates a new token validator.
func newTokenValidator(config *Config, httpClient HTTPClient) (*tokenValidator, error) {
	v := &tokenValidator{
		config:     config,
		httpClient: httpClient,
	}

	// Initialize JWKS if needed for JWT validation
	if config.Validation.Method == ValidationJWT || config.Validation.Method == ValidationHybrid {
		if err := v.initJWKS(context.Background()); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
		}
	}

	return v, nil
}

// validate validates a token using the configured method.
func (v *tokenValidator) validate(ctx context.Context, token string) (*TokenClaims, error) {
	if strings.TrimSpace(token) == "" {
		return nil, ErrMissingToken
	}

	switch v.config.Validation.Method {
	case ValidationJWT:
		return v.validateJWT(ctx, token)
	case ValidationIntrospection:
		return v.introspectToken(ctx, token)
	case ValidationHybrid:
		// Try JWT first, fall back to introspection
		claims, err := v.validateJWT(ctx, token)
		if err == nil {
			return claims, nil
		}
		// If introspection URL is configured, try it
		if v.config.Validation.IntrospectionURL != "" {
			return v.introspectToken(ctx, token)
		}
		return nil, err
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidConfiguration, v.config.Validation.Method)
	}
}

// validateJWT validates a JWT token locally using JWKS.
func (v *tokenValidator) validateJWT(ctx context.Context, tokenString string) (*TokenClaims, error) {
	v.jwksMu.RLock()
	jwks := v.jwks
	v.jwksMu.RUnlock()

	if jwks == nil {
		return nil, fmt.Errorf("%w: jwks not initialized", ErrJWKSFetchFailed)
	}

	// Parse and validate the JWT
	token, err := jwt.Parse(tokenString, jwks.Keyfunc, jwt.WithValidMethods([]string{
		"RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
		"PS256", "PS384", "PS512",
	}))

	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			return nil, ErrExpiredToken
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Extract claims
	claims, err := claimsFromJWT(token)
	if err != nil {
		return nil, err
	}

	// Validate issuer if configured
	if v.config.Validation.Issuer != "" && claims.Issuer != v.config.Validation.Issuer {
		return nil, fmt.Errorf("%w: invalid issuer", ErrInvalidToken)
	}

	// Validate audience if configured
	if v.config.Validation.Audience != "" {
		if !containsAudience(claims.Audience, v.config.Validation.Audience) {
			return nil, fmt.Errorf("%w: invalid audience", ErrInvalidToken)
		}
	}

	// Validate required claims
	if err := v.validateRequiredClaims(claims); err != nil {
		return nil, err
	}

	// Validate time-based claims with clock skew
	if !claims.ValidWithClockSkew(v.config.Validation.ClockSkew) {
		return nil, ErrExpiredToken
	}

	return claims, nil
}

// introspectToken validates a token using OAuth introspection endpoint.
func (v *tokenValidator) introspectToken(ctx context.Context, token string) (*TokenClaims, error) {
	if v.config.Validation.IntrospectionURL == "" {
		return nil, fmt.Errorf("%w: introspection url not configured", ErrInvalidConfiguration)
	}

	// Build introspection request
	data := url.Values{}
	data.Set("token", token)
	data.Set("token_type_hint", "access_token")

	req, err := http.NewRequestWithContext(ctx, "POST", v.config.Validation.IntrospectionURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIntrospectionFailed, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(v.config.ClientID, v.config.ClientSecret)

	// Execute request
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIntrospectionFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d: %s", ErrIntrospectionFailed, resp.StatusCode, string(body))
	}

	// Parse introspection response
	var result struct {
		Active        bool     `json:"active"`
		Scope         string   `json:"scope"`
		ClientID      string   `json:"client_id"`
		Username      string   `json:"username"`
		TokenType     string   `json:"token_type"`
		Exp           int64    `json:"exp"`
		Iat           int64    `json:"iat"`
		Nbf           int64    `json:"nbf"`
		Sub           string   `json:"sub"`
		Aud           []string `json:"aud"`
		Iss           string   `json:"iss"`
		Jti           string   `json:"jti"`
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Name          string   `json:"name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIntrospectionFailed, err)
	}

	if !result.Active {
		return nil, ErrInvalidToken
	}

	// Convert to TokenClaims
	claims := &TokenClaims{
		Subject:       result.Sub,
		Issuer:        result.Iss,
		Audience:      result.Aud,
		Email:         result.Email,
		EmailVerified: result.EmailVerified,
		Name:          result.Name,
		Custom:        make(map[string]interface{}),
	}

	if result.Username != "" && claims.Subject == "" {
		claims.Subject = result.Username
	}

	if result.Exp > 0 {
		claims.ExpiresAt = time.Unix(result.Exp, 0)
	}

	if result.Iat > 0 {
		claims.IssuedAt = time.Unix(result.Iat, 0)
	}

	if result.Nbf > 0 {
		claims.NotBefore = time.Unix(result.Nbf, 0)
	}

	if result.Scope != "" {
		claims.Scopes = splitScopes(result.Scope)
	}

	// Validate required claims
	if err := v.validateRequiredClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// initJWKS initializes the JWKS key set.
func (v *tokenValidator) initJWKS(ctx context.Context) error {
	if v.config.Validation.JWKSURL == "" {
		return fmt.Errorf("jwks url is required")
	}

	// Create JWKS using the simple default method
	jwks, err := keyfunc.NewDefaultCtx(ctx, []string{v.config.Validation.JWKSURL})
	if err != nil {
		return err
	}

	v.jwksMu.Lock()
	v.jwks = jwks
	v.jwksMu.Unlock()

	return nil
}

// validateRequiredClaims checks if all required claims are present.
func (v *tokenValidator) validateRequiredClaims(claims *TokenClaims) error {
	if len(v.config.Validation.RequiredClaims) == 0 {
		return nil
	}

	// Build a map of all available claims
	availableClaims := map[string]bool{
		"sub":            claims.Subject != "",
		"iss":            claims.Issuer != "",
		"aud":            len(claims.Audience) > 0,
		"exp":            !claims.ExpiresAt.IsZero(),
		"iat":            !claims.IssuedAt.IsZero(),
		"nbf":            !claims.NotBefore.IsZero(),
		"email":          claims.Email != "",
		"email_verified": true, // Always present (bool default is false)
		"name":           claims.Name != "",
	}

	// Check custom claims
	for key := range claims.Custom {
		availableClaims[key] = true
	}

	// Verify all required claims are present
	for _, required := range v.config.Validation.RequiredClaims {
		if !availableClaims[required] {
			return fmt.Errorf("%w: missing required claim %s", ErrInvalidClaims, required)
		}
	}

	return nil
}

// containsAudience checks if the audience list contains the expected audience.
func containsAudience(audiences []string, expected string) bool {
	for _, aud := range audiences {
		if aud == expected {
			return true
		}
	}
	return false
}

// Close releases resources held by the validator.
func (v *tokenValidator) Close() {
	// The new keyfunc v3 API doesn't require explicit cleanup
	v.jwksMu.Lock()
	defer v.jwksMu.Unlock()
	v.jwks = nil
}
