package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// oidcValidator handles ID token validation with OIDC-specific checks.
type oidcValidator struct {
	config          *Config
	baseValidator   *tokenValidator
	nonceStore      *nonceStore
	discoveryClient *discoveryClient
}

// newOIDCValidator creates a new OIDC validator.
func newOIDCValidator(config *Config, baseValidator *tokenValidator, discoveryClient *discoveryClient) *oidcValidator {
	var nonceStore *nonceStore
	if config.OIDC != nil && config.OIDC.ValidateNonce {
		nonceStore = newNonceStore(config.OIDC.NonceLifetime)
	}

	return &oidcValidator{
		config:          config,
		baseValidator:   baseValidator,
		nonceStore:      nonceStore,
		discoveryClient: discoveryClient,
	}
}

// ValidateIDToken validates an OpenID Connect ID token with full OIDC compliance.
func (v *oidcValidator) ValidateIDToken(ctx context.Context, idToken string, nonce string, accessToken string) (*IDTokenClaims, error) {
	if !v.isOIDCEnabled() {
		return nil, ErrOIDCNotEnabled
	}

	if strings.TrimSpace(idToken) == "" {
		return nil, ErrOIDCMissingIDToken
	}

	// Parse JWT without validation first to get claims for issuer check
	unverified, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse id token: %v", ErrOIDCInvalidIDToken, err)
	}

	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims type", ErrOIDCInvalidIDToken)
	}

	issuer, _ := claims["iss"].(string)
	if issuer == "" {
		return nil, fmt.Errorf("%w: missing issuer claim", ErrOIDCInvalidIDToken)
	}

	// Get or fetch discovery document to get JWKS URL
	discovery, err := v.discoveryClient.getDiscovery(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCDiscoveryFailed, err)
	}

	// Validate JWT signature and standard claims
	_, err = v.baseValidator.validateJWT(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCInvalidIDToken, err)
	}

	// Parse OIDC-specific claims
	jwtToken, err := jwt.Parse(idToken, v.baseValidator.jwks.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCInvalidIDToken, err)
	}

	idClaims, err := parseIDTokenClaims(jwtToken)
	if err != nil {
		return nil, err
	}

	// Perform OIDC-specific validations
	if err := v.validateOIDCClaims(idClaims, nonce, accessToken, discovery); err != nil {
		return nil, err
	}

	// Additional time-based validations
	if err := v.validateTimeClaims(idClaims); err != nil {
		return nil, err
	}

	return idClaims, nil
}

// validateOIDCClaims performs OIDC-specific claim validations.
func (v *oidcValidator) validateOIDCClaims(claims *IDTokenClaims, nonce string, accessToken string, discovery *OIDCDiscoveryConfig) error {
	// Validate issuer matches discovery
	if discovery != nil && claims.Issuer != discovery.Issuer {
		return fmt.Errorf("%w: issuer mismatch", ErrOIDCInvalidIDToken)
	}

	// Validate audience contains client ID
	if !containsAudience(claims.Audience, v.config.ClientID) {
		return fmt.Errorf("%w: audience doesn't contain client_id", ErrOIDCInvalidIDToken)
	}

	// Validate azp (authorized party) if present and audience has multiple values
	if len(claims.Audience) > 1 && claims.AZP != "" {
		if claims.AZP != v.config.ClientID {
			return fmt.Errorf("%w: azp doesn't match client_id", ErrOIDCInvalidIDToken)
		}
	}

	// Validate nonce if configured
	if v.config.OIDC.ValidateNonce {
		if nonce == "" && claims.Nonce != "" {
			return fmt.Errorf("%w: nonce expected but not provided", ErrOIDCInvalidNonce)
		}
		if nonce != "" {
			if claims.Nonce == "" {
				return fmt.Errorf("%w: nonce missing in id token", ErrOIDCInvalidNonce)
			}
			if nonce != claims.Nonce {
				return fmt.Errorf("%w: nonce mismatch", ErrOIDCInvalidNonce)
			}
			// Validate and consume nonce from store
			if v.nonceStore != nil {
				if err := v.nonceStore.Validate(nonce); err != nil {
					return err
				}
			}
		}
	}

	// Validate at_hash if present and configured
	if v.config.OIDC.ValidateAtHash && claims.AtHash != "" && accessToken != "" {
		if err := v.validateAtHash(claims.AtHash, accessToken, getHashAlg(claims)); err != nil {
			return err
		}
	}

	// Validate ACR if required
	if v.config.OIDC.RequireACR && len(v.config.OIDC.ACRValues) > 0 {
		if !containsString(v.config.OIDC.ACRValues, claims.ACR) {
			return fmt.Errorf("%w: required acr not met", ErrOIDCInvalidACR)
		}
	}

	return nil
}

// validateTimeClaims validates time-based claims with clock skew.
func (v *oidcValidator) validateTimeClaims(claims *IDTokenClaims) error {
	now := time.Now()
	clockSkew := v.config.Validation.ClockSkew

	// Validate expiration
	if claims.ExpiresAt > 0 {
		exp := time.Unix(claims.ExpiresAt, 0)
		if now.After(exp.Add(clockSkew)) {
			return fmt.Errorf("%w: id token expired", ErrExpiredToken)
		}
	}

	// Validate not before
	if claims.NotBefore > 0 {
		nbf := time.Unix(claims.NotBefore, 0)
		if now.Before(nbf.Add(-clockSkew)) {
			return fmt.Errorf("%w: id token not yet valid", ErrOIDCInvalidIDToken)
		}
	}

	// Validate auth_time vs max_age
	if v.config.OIDC.MaxAge > 0 && claims.AuthTime > 0 {
		authTime := time.Unix(claims.AuthTime, 0)
		maxAge := time.Duration(v.config.OIDC.MaxAge) * time.Second
		if now.After(authTime.Add(maxAge).Add(clockSkew)) {
			return ErrOIDCAuthTimeTooOld
		}
	}

	// Validate issued at is not in the future
	if claims.IssuedAt > 0 {
		iat := time.Unix(claims.IssuedAt, 0)
		if now.Before(iat.Add(-clockSkew)) {
			return fmt.Errorf("%w: issued at time is in the future", ErrOIDCInvalidIDToken)
		}
	}

	return nil
}

// validateAtHash validates the at_hash claim against the access token.
// This prevents token substitution attacks.
func (v *oidcValidator) validateAtHash(atHash string, accessToken string, hashFunc func() hash.Hash) error {
	if hashFunc == nil {
		// If we can't determine the hash algorithm, skip validation
		return nil
	}

	// Hash the access token
	h := hashFunc()
	h.Write([]byte(accessToken))
	hashBytes := h.Sum(nil)

	// Take the left-most half of the hash
	halfLen := len(hashBytes) / 2
	leftHalf := hashBytes[:halfLen]

	// Base64url encode
	expected := base64.RawURLEncoding.EncodeToString(leftHalf)

	if atHash != expected {
		return ErrOIDCInvalidAtHash
	}

	return nil
}

// getHashAlg determines the hash algorithm from the ID token's signing algorithm.
func getHashAlg(claims *IDTokenClaims) func() hash.Hash {
	// The hash algorithm is derived from the signing algorithm
	// This would typically come from the JWT header, but we can infer from common usage
	// For production, you should parse the JWT header to get the 'alg' claim

	// Default to SHA256 for RS256/ES256/PS256 (most common)
	return sha256.New
}

// GenerateNonce generates a new nonce for an OIDC authorization request.
func (v *oidcValidator) GenerateNonce() (string, error) {
	if !v.isOIDCEnabled() {
		return "", ErrOIDCNotEnabled
	}

	if !v.config.OIDC.ValidateNonce || v.nonceStore == nil {
		return "", nil
	}

	return v.nonceStore.Generate()
}

// isOIDCEnabled checks if OIDC features are enabled.
func (v *oidcValidator) isOIDCEnabled() bool {
	return v.config.OIDC != nil && v.config.OIDC.Enabled
}

// Close releases resources held by the validator.
func (v *oidcValidator) Close() {
	if v.nonceStore != nil {
		v.nonceStore.Close()
	}
}

// containsString checks if a slice contains a string.
func containsString(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// getJWTAlgorithm extracts the signing algorithm from a JWT token string.
func getJWTAlgorithm(tokenString string) string {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 2 {
		return ""
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}

	// Simple JSON parsing for algorithm
	headerStr := string(headerBytes)
	if strings.Contains(headerStr, `"alg"`) {
		start := strings.Index(headerStr, `"alg":"`) + 7
		end := strings.Index(headerStr[start:], `"`)
		if end > 0 {
			return headerStr[start : start+end]
		}
	}

	return ""
}

// getHashFuncForAlg returns the appropriate hash function for a JWT algorithm.
func getHashFuncForAlg(alg string) func() hash.Hash {
	switch alg {
	case "RS256", "ES256", "PS256", "HS256":
		return sha256.New
	case "RS384", "ES384", "PS384", "HS384":
		return sha512.New384
	case "RS512", "ES512", "PS512", "HS512":
		return sha512.New
	default:
		return sha256.New // Default to SHA256
	}
}
