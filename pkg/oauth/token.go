package oauth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-enclave"
)

// Token represents an OAuth 2.0 token response.
//
// The access, refresh and ID tokens are bearer credentials, so a Token holds
// each one in its own go-enclave locked region and lends it through an
// accessor rather than exposing a string. The Token OWNS those enclaves: they
// stay alive until Destroy, and a caller that needs a credential to outlive the
// Token must copy it out — inside WithBytes — before destroying the Token.
// Expiry, token type and scopes are not secrets and stay plain.
//
//	token, err := auth.AuthenticateClientCredentials(ctx)
//	if err != nil {
//	    return err
//	}
//	defer token.Destroy()
//
//	err = token.AccessToken().WithBytes(func(access []byte) error {
//	    req.Header.Set("Authorization", "Bearer "+string(access)) // the caller's own HTTP boundary
//	    return nil
//	})
type Token struct {
	// TokenType is the type of token (usually "Bearer").
	TokenType string

	// Expiry is when the access token expires.
	Expiry time.Time

	// Scopes are the scopes granted to this token.
	Scopes []string

	accessToken  *enclave.MemoryEnclave
	refreshToken *enclave.MemoryEnclave
	idToken      *enclave.MemoryEnclave
}

// AccessToken lends the access token. The enclave belongs to the Token: do not
// destroy it, and do not use it after Token.Destroy. A nil *Token lends nil,
// which every enclave method treats as destroyed.
func (t *Token) AccessToken() *enclave.MemoryEnclave {
	if t == nil {
		return nil
	}
	return t.accessToken
}

// RefreshToken lends the refresh token, or nil when the provider issued none.
// It can be passed straight to Authenticator.RefreshToken, which borrows it.
// The enclave belongs to the Token, as with AccessToken.
func (t *Token) RefreshToken() *enclave.MemoryEnclave {
	if t == nil {
		return nil
	}
	return t.refreshToken
}

// IDToken lends the OpenID Connect ID token, or nil when the provider issued
// none. The enclave belongs to the Token, as with AccessToken.
func (t *Token) IDToken() *enclave.MemoryEnclave {
	if t == nil {
		return nil
	}
	return t.idToken
}

// Destroy wipes and releases every credential the Token holds. It is
// idempotent and safe on a nil *Token, so it can always be deferred. Every
// credential is destroyed even when one fails; the failures are joined.
func (t *Token) Destroy() error {
	if t == nil {
		return nil
	}
	return errors.Join(
		t.accessToken.Destroy(),
		t.refreshToken.Destroy(),
		t.idToken.Destroy(),
	)
}

// Valid returns true if the token is not expired.
func (t *Token) Valid() bool {
	return !t.Expired()
}

// Expired returns true if the token has expired.
func (t *Token) Expired() bool {
	if t.Expiry.IsZero() {
		return false
	}
	return time.Now().After(t.Expiry)
}

// ExpiresIn returns the duration until the token expires.
// Returns 0 if the token is already expired or has no expiry.
func (t *Token) ExpiresIn() time.Duration {
	if t.Expiry.IsZero() {
		return 0
	}
	d := time.Until(t.Expiry)
	if d < 0 {
		return 0
	}
	return d
}

// TokenClaims represents validated claims extracted from a token.
type TokenClaims struct {
	// Subject is the subject identifier (typically user ID).
	Subject string

	// Issuer is the token issuer.
	Issuer string

	// Audience is the intended audience for this token.
	Audience []string

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time

	// IssuedAt is when the token was issued.
	IssuedAt time.Time

	// NotBefore is the time before which the token is not valid.
	NotBefore time.Time

	// Scopes are the scopes granted to this token.
	Scopes []string

	// Email is the user's email address (if present in claims).
	Email string

	// EmailVerified indicates if the email is verified (OIDC).
	EmailVerified bool

	// Name is the user's display name (if present in claims).
	Name string

	// Groups are the user's group memberships (if present in claims).
	Groups []string

	// Custom contains any additional claims not mapped to standard fields.
	Custom map[string]interface{}
}

// Valid returns true if the token claims are currently valid based on time.
func (c *TokenClaims) Valid() bool {
	now := time.Now()

	// Check expiration
	if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt) {
		return false
	}

	// Check not-before
	if !c.NotBefore.IsZero() && now.Before(c.NotBefore) {
		return false
	}

	return true
}

// ValidWithClockSkew returns true if the claims are valid allowing for clock skew.
func (c *TokenClaims) ValidWithClockSkew(skew time.Duration) bool {
	now := time.Now()

	// Check expiration with skew
	if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt.Add(skew)) {
		return false
	}

	// Check not-before with skew
	if !c.NotBefore.IsZero() && now.Before(c.NotBefore.Add(-skew)) {
		return false
	}

	return true
}

// claimsFromJWT extracts TokenClaims from a parsed JWT token.
func claimsFromJWT(token *jwt.Token) (*TokenClaims, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims type", ErrInvalidClaims)
	}

	tc := &TokenClaims{
		Custom: make(map[string]interface{}),
	}

	// Extract standard claims
	if sub, ok := claims["sub"].(string); ok {
		tc.Subject = sub
	}

	if iss, ok := claims["iss"].(string); ok {
		tc.Issuer = iss
	}

	// Audience can be string or array
	if aud, ok := claims["aud"].(string); ok {
		tc.Audience = []string{aud}
	} else if aud, ok := claims["aud"].([]interface{}); ok {
		for _, a := range aud {
			if s, ok := a.(string); ok {
				tc.Audience = append(tc.Audience, s)
			}
		}
	}

	// Extract time claims
	if exp, ok := claims["exp"].(float64); ok {
		tc.ExpiresAt = time.Unix(int64(exp), 0)
	}

	if iat, ok := claims["iat"].(float64); ok {
		tc.IssuedAt = time.Unix(int64(iat), 0)
	}

	if nbf, ok := claims["nbf"].(float64); ok {
		tc.NotBefore = time.Unix(int64(nbf), 0)
	}

	// Extract scope claim (can be string or array)
	if scope, ok := claims["scope"].(string); ok {
		// Space-separated string
		tc.Scopes = append(tc.Scopes, splitScopes(scope)...)
	} else if scope, ok := claims["scopes"].([]interface{}); ok {
		for _, s := range scope {
			if str, ok := s.(string); ok {
				tc.Scopes = append(tc.Scopes, str)
			}
		}
	} else if scope, ok := claims["scp"].([]interface{}); ok {
		// Azure AD uses "scp"
		for _, s := range scope {
			if str, ok := s.(string); ok {
				tc.Scopes = append(tc.Scopes, str)
			}
		}
	}

	// Extract OIDC claims
	if email, ok := claims["email"].(string); ok {
		tc.Email = email
	}

	if emailVerified, ok := claims["email_verified"].(bool); ok {
		tc.EmailVerified = emailVerified
	}

	if name, ok := claims["name"].(string); ok {
		tc.Name = name
	}

	// Extract groups (common claim)
	if groups, ok := claims["groups"].([]interface{}); ok {
		for _, g := range groups {
			if s, ok := g.(string); ok {
				tc.Groups = append(tc.Groups, s)
			}
		}
	}

	// Store remaining claims in Custom
	standardClaims := map[string]bool{
		"sub": true, "iss": true, "aud": true, "exp": true, "iat": true, "nbf": true,
		"scope": true, "scopes": true, "scp": true,
		"email": true, "email_verified": true, "name": true, "groups": true,
	}

	for key, value := range claims {
		if !standardClaims[key] {
			tc.Custom[key] = value
		}
	}

	return tc, nil
}

// splitScopes splits a space-separated scope string.
func splitScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	var scopes []string
	for _, s := range splitBySpace(scope) {
		if s != "" {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

// splitBySpace splits a string by whitespace.
func splitBySpace(s string) []string {
	var result []string
	var current string
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(r)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
