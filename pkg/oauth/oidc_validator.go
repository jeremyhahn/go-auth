package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-enclave"
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
// Both tokens are borrowed; accessToken may be nil.
func (v *oidcValidator) ValidateIDToken(ctx context.Context, idToken *enclave.MemoryEnclave, nonce string, accessToken *enclave.MemoryEnclave) (*IDTokenClaims, error) {
	if !v.isOIDCEnabled() {
		return nil, ErrOIDCNotEnabled
	}

	var idClaims *IDTokenClaims
	err := idToken.WithBytes(func(b []byte) error {
		// Residue (JWT parse boundary): golang-jwt parses only from a string.
		var err error
		idClaims, err = v.validateIDTokenString(ctx, string(b), nonce, accessToken)
		return err
	})
	if errors.Is(err, enclave.ErrEnclaveDestroyed) {
		return nil, ErrOIDCMissingIDToken
	}
	return idClaims, err
}

// validateIDTokenString validates the residue copy ValidateIDToken makes of an
// ID token for golang-jwt.
func (v *oidcValidator) validateIDTokenString(ctx context.Context, idToken string, nonce string, accessToken *enclave.MemoryEnclave) (*IDTokenClaims, error) {
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
	_, err = v.baseValidator.validateJWTString(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCInvalidIDToken, err)
	}

	// Parse OIDC-specific claims
	jwtToken, err := parseVerifiedIDToken(idToken, v.baseValidator.jwks.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCInvalidIDToken, err)
	}

	idClaims, err := parseIDTokenClaims(jwtToken)
	if err != nil {
		return nil, err
	}

	// Perform OIDC-specific validations
	if err := v.validateOIDCClaims(idClaims, nonce, accessToken, jwtToken.Method.Alg(), discovery); err != nil {
		return nil, err
	}

	// Additional time-based validations
	if err := v.validateTimeClaims(idClaims); err != nil {
		return nil, err
	}

	return idClaims, nil
}

// parseVerifiedIDToken parses and verifies an ID token with keyfunc, admitting
// only the asymmetric algorithms in asymmetricJWTAlgorithms.
func parseVerifiedIDToken(idToken string, keyfunc jwt.Keyfunc) (*jwt.Token, error) {
	return jwt.Parse(idToken, keyfunc, jwt.WithValidMethods(asymmetricJWTAlgorithms))
}

// validateOIDCClaims performs OIDC-specific claim validations. alg is the
// verified ID token's JWS algorithm, which decides the at_hash hash.
func (v *oidcValidator) validateOIDCClaims(claims *IDTokenClaims, nonce string, accessToken *enclave.MemoryEnclave, alg string, discovery *OIDCDiscoveryConfig) error {
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

	// Validate at_hash if present and configured. Only a nil access token means
	// none was supplied; a destroyed one is rejected by validateAtHash.
	if v.config.OIDC.ValidateAtHash && claims.AtHash != "" && accessToken != nil {
		if err := v.validateAtHash(claims.AtHash, accessToken, atHashAlgorithms[alg]); err != nil {
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
// This prevents token substitution attacks. The access token is hashed inside
// its enclave. It fails closed: no hash function (an algorithm at_hash is not
// defined for) and an access token that cannot be opened both reject.
func (v *oidcValidator) validateAtHash(atHash string, accessToken *enclave.MemoryEnclave, hashFunc func() hash.Hash) error {
	if hashFunc == nil {
		return errors.Join(ErrOIDCInvalidAtHash, ErrOIDCUnsupportedAtHashAlgorithm)
	}

	// Hash the access token
	h := hashFunc()
	if err := accessToken.WithBytes(func(b []byte) error {
		h.Write(b)
		return nil
	}); err != nil {
		return errors.Join(ErrOIDCInvalidAtHash, err)
	}
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

// atHashAlgorithms maps an ID token's JWS algorithm to the hash at_hash is
// computed with: the hash of the signing algorithm (OIDC Core §3.1.3.6), and
// SHA-512 for EdDSA, the convention for Ed25519. An algorithm absent here has
// no at_hash and is rejected — never defaulted.
var atHashAlgorithms = map[string]func() hash.Hash{
	"RS256": sha256.New, "ES256": sha256.New, "PS256": sha256.New,
	"RS384": sha512.New384, "ES384": sha512.New384, "PS384": sha512.New384,
	"RS512": sha512.New, "ES512": sha512.New, "PS512": sha512.New,
	"EdDSA": sha512.New,
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
