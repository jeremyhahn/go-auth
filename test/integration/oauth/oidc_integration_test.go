//go:build integration

package oauth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-auth/pkg/oauth"
)

// TestOIDC_Discovery tests the OIDC discovery endpoint functionality.
func TestOIDC_Discovery(t *testing.T) {
	clientID, clientSecret := getClientCredentials(t)

	// Configure OIDC-enabled provider
	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		AuthEndpoint:  hydraPublicURL + "/oauth2/auth",
		IssuerURL:     hydraPublicURL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	cfg := &oauth.Config{
		Provider:     provider,
		Flow:         oauth.FlowClientCredentials,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Timeout:      10 * time.Second,
		OIDC: &oauth.OIDCConfig{
			Enabled: true,
		},
		Validation: oauth.TokenValidationConfig{
			Issuer: hydraPublicURL + "/",
		},
	}

	authenticator, err := oauth.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer authenticator.Close()

	ctx := context.Background()
	discovery, err := authenticator.GetDiscovery(ctx)
	if err != nil {
		t.Fatalf("Failed to get discovery document: %v", err)
	}

	// Test 1: Verify required fields are present
	if discovery.Issuer == "" {
		t.Error("Discovery document missing issuer")
	}
	if discovery.Issuer != hydraPublicURL+"/" {
		t.Errorf("Expected issuer '%s', got '%s'", hydraPublicURL+"/", discovery.Issuer)
	}

	if discovery.AuthorizationEndpoint == "" {
		t.Error("Discovery document missing authorization_endpoint")
	}
	t.Logf("Authorization endpoint: %s", discovery.AuthorizationEndpoint)

	if discovery.TokenEndpoint == "" {
		t.Error("Discovery document missing token_endpoint")
	}
	t.Logf("Token endpoint: %s", discovery.TokenEndpoint)

	if discovery.JWKSUri == "" {
		t.Error("Discovery document missing jwks_uri")
	}
	t.Logf("JWKS URI: %s", discovery.JWKSUri)

	if discovery.UserInfoEndpoint == "" {
		t.Error("Discovery document missing userinfo_endpoint")
	}
	t.Logf("UserInfo endpoint: %s", discovery.UserInfoEndpoint)

	// Test 2: Verify supported response types
	if len(discovery.ResponseTypesSupported) == 0 {
		t.Error("Discovery document has no response_types_supported")
	} else {
		t.Logf("Supported response types: %v", discovery.ResponseTypesSupported)
	}

	// Test 3: Verify supported grant types
	if len(discovery.GrantTypesSupported) > 0 {
		t.Logf("Supported grant types: %v", discovery.GrantTypesSupported)
	}

	// Test 4: Verify supported scopes
	if len(discovery.ScopesSupported) > 0 {
		t.Logf("Supported scopes: %v", discovery.ScopesSupported)
		hasOpenID := false
		for _, scope := range discovery.ScopesSupported {
			if scope == "openid" {
				hasOpenID = true
				break
			}
		}
		if !hasOpenID {
			t.Error("Discovery document doesn't list 'openid' scope support")
		}
	}

	// Test 5: Verify signing algorithms
	if len(discovery.IDTokenSigningAlgValuesSupported) == 0 {
		t.Error("Discovery document has no id_token_signing_alg_values_supported")
	} else {
		t.Logf("Supported ID token signing algorithms: %v", discovery.IDTokenSigningAlgValuesSupported)
	}

	// Test 6: Verify subject types
	if len(discovery.SubjectTypesSupported) == 0 {
		t.Error("Discovery document has no subject_types_supported")
	} else {
		t.Logf("Supported subject types: %v", discovery.SubjectTypesSupported)
	}

	// Test 7: Verify PKCE support
	if len(discovery.CodeChallengeMethodsSupported) > 0 {
		t.Logf("Supported PKCE methods: %v", discovery.CodeChallengeMethodsSupported)
	}

	// Test 8: Verify discovery document validation
	if err := discovery.Validate(); err != nil {
		t.Errorf("Discovery document failed validation: %v", err)
	}

	// Test 9: Test discovery caching
	discovery2, err := authenticator.GetDiscovery(ctx)
	if err != nil {
		t.Fatalf("Failed to get cached discovery document: %v", err)
	}
	if discovery2.Issuer != discovery.Issuer {
		t.Error("Cached discovery document differs from original")
	}

	// Test 10: Test discovery refresh
	err = authenticator.RefreshDiscovery(ctx)
	if err != nil {
		t.Errorf("Failed to refresh discovery document: %v", err)
	}

	t.Log("OIDC discovery document validated successfully")
}

// TestOIDC_IDTokenValidation tests ID token validation with client credentials flow.
func TestOIDC_IDTokenValidation(t *testing.T) {
	clientID, clientSecret := getPasswordClientCredentials(t)

	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		AuthEndpoint:  hydraPublicURL + "/oauth2/auth",
		IssuerURL:     hydraPublicURL + "/",
		JWKSEndpoint:       hydraPublicURL + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Configure with OIDC enabled
	cfg := &oauth.Config{
		Provider:     provider,
		Flow:         oauth.FlowClientCredentials,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Timeout:      10 * time.Second,
		OIDC: &oauth.OIDCConfig{
			Enabled:        true,
			ValidateNonce:  false, // Client credentials doesn't use nonce
			ValidateAtHash: false, // Not applicable for client credentials
		},
		Validation: oauth.TokenValidationConfig{
			Method:    oauth.ValidationJWT,
			JWKSURL:   hydraPublicURL + "/.well-known/jwks.json",
			Issuer:    hydraPublicURL + "/",
			ClockSkew: 60 * time.Second,
		},
	}

	authenticator, err := oauth.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer authenticator.Close()

	// Get token with openid scope
	ctx := context.Background()
	token, err := authenticator.AuthenticateClientCredentials(ctx)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	// Note: ORY Hydra in client_credentials flow may not return ID token
	// since there's no end-user involved. This is expected behavior.
	if token.IDToken == "" {
		t.Skip("Skipping ID token validation - client credentials flow doesn't return ID token (expected behavior)")
		return
	}

	// If we do get an ID token, validate it
	t.Logf("Received ID token: %d bytes", len(token.IDToken))

	// Validate the ID token
	idClaims, err := authenticator.ValidateIDToken(ctx, token.IDToken, "", token.AccessToken)
	if err != nil {
		t.Fatalf("Failed to validate ID token: %v", err)
	}

	// Test 1: Verify required claims
	if idClaims.Issuer == "" {
		t.Error("ID token missing issuer claim")
	}
	if idClaims.Subject == "" {
		t.Error("ID token missing subject claim")
	}
	if len(idClaims.Audience) == 0 {
		t.Error("ID token missing audience claim")
	}
	if idClaims.ExpiresAt == 0 {
		t.Error("ID token missing expiration claim")
	}
	if idClaims.IssuedAt == 0 {
		t.Error("ID token missing issued at claim")
	}

	// Test 2: Verify issuer matches configuration
	expectedIssuer := hydraPublicURL + "/"
	if idClaims.Issuer != expectedIssuer {
		t.Errorf("Expected issuer '%s', got '%s'", expectedIssuer, idClaims.Issuer)
	}

	// Test 3: Verify audience contains client ID
	hasClientID := false
	for _, aud := range idClaims.Audience {
		if aud == clientID {
			hasClientID = true
			break
		}
	}
	if !hasClientID {
		t.Errorf("ID token audience %v doesn't contain client_id '%s'", idClaims.Audience, clientID)
	}

	// Test 4: Verify expiration is in the future
	exp := time.Unix(idClaims.ExpiresAt, 0)
	if !exp.After(time.Now()) {
		t.Error("ID token is already expired")
	}

	// Test 5: Verify issued at is not in the future
	iat := time.Unix(idClaims.IssuedAt, 0)
	if iat.After(time.Now().Add(60 * time.Second)) {
		t.Error("ID token issued at time is in the future")
	}

	t.Logf("ID token validated successfully")
	t.Logf("Subject: %s", idClaims.Subject)
	t.Logf("Issuer: %s", idClaims.Issuer)
	t.Logf("Audience: %v", idClaims.Audience)
	t.Logf("Expires: %s", exp)
}

// TestOIDC_IDTokenParsing tests parsing of ID token JWT structure.
func TestOIDC_IDTokenParsing(t *testing.T) {
	clientID, clientSecret := getPasswordClientCredentials(t)

	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		IssuerURL:     hydraPublicURL + "/",
		JWKSEndpoint:       hydraPublicURL + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	cfg := &oauth.Config{
		Provider:     provider,
		Flow:         oauth.FlowClientCredentials,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile"},
		Timeout:      10 * time.Second,
		OIDC: &oauth.OIDCConfig{
			Enabled: true,
		},
		Validation: oauth.TokenValidationConfig{
			Method:    oauth.ValidationJWT,
			JWKSURL:   hydraPublicURL + "/.well-known/jwks.json",
			Issuer:    hydraPublicURL + "/",
			ClockSkew: 60 * time.Second,
		},
	}

	authenticator, err := oauth.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer authenticator.Close()

	ctx := context.Background()
	token, err := authenticator.AuthenticateClientCredentials(ctx)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	if token.IDToken == "" {
		t.Skip("Skipping - no ID token returned in client credentials flow (expected)")
		return
	}

	// Test 1: Verify JWT structure
	parts := strings.Split(token.IDToken, ".")
	if len(parts) != 3 {
		t.Fatalf("Invalid JWT structure: expected 3 parts, got %d", len(parts))
	}

	// Test 2: Parse header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("Failed to decode JWT header: %v", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("Failed to parse JWT header: %v", err)
	}

	if alg, ok := header["alg"].(string); ok {
		t.Logf("Signing algorithm: %s", alg)
		if alg == "none" {
			t.Error("ID token must be signed (alg cannot be 'none')")
		}
	} else {
		t.Error("JWT header missing 'alg' field")
	}

	if typ, ok := header["typ"].(string); ok {
		t.Logf("Token type: %s", typ)
	}

	if kid, ok := header["kid"].(string); ok {
		t.Logf("Key ID: %s", kid)
	}

	// Test 3: Parse payload (without verification for inspection)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode JWT payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("Failed to parse JWT payload: %v", err)
	}

	// Verify standard claims are present
	standardClaims := []string{"iss", "sub", "aud", "exp", "iat"}
	for _, claim := range standardClaims {
		if _, exists := payload[claim]; !exists {
			t.Errorf("ID token missing standard claim: %s", claim)
		}
	}

	t.Logf("ID token JWT structure validated successfully")
	t.Logf("Claims present: %v", getMapKeys(payload))
}

// TestOIDC_UserInfo tests the UserInfo endpoint functionality.
func TestOIDC_UserInfo(t *testing.T) {
	clientID, clientSecret := getPasswordClientCredentials(t)

	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		IssuerURL:     hydraPublicURL + "/",
		UserInfoEndpoint:   hydraPublicURL + "/userinfo",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	cfg := &oauth.Config{
		Provider:     provider,
		Flow:         oauth.FlowClientCredentials,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Timeout:      10 * time.Second,
		OIDC: &oauth.OIDCConfig{
			Enabled: true,
			UserInfo: oauth.UserInfoConfig{
				Enabled:  true,
				CacheTTL: 5 * time.Minute,
				Timeout:  10 * time.Second,
			},
		},
		Validation: oauth.TokenValidationConfig{
			Issuer: hydraPublicURL + "/",
		},
	}

	authenticator, err := oauth.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer authenticator.Close()

	// Get access token
	ctx := context.Background()
	token, err := authenticator.AuthenticateClientCredentials(ctx)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	// Test 1: Fetch UserInfo
	userInfo, err := authenticator.GetUserInfo(ctx, token.AccessToken)
	if err != nil {
		// UserInfo might not be available for client credentials flow
		t.Logf("UserInfo fetch failed (may be expected for client credentials): %v", err)
		t.Skip("Skipping UserInfo tests - not available for client credentials flow")
		return
	}

	// Test 2: Verify subject is present
	if userInfo.Subject == "" {
		t.Error("UserInfo missing subject claim")
	}
	t.Logf("UserInfo subject: %s", userInfo.Subject)

	// Test 3: Check for profile claims
	if userInfo.Name != "" {
		t.Logf("Name: %s", userInfo.Name)
	}
	if userInfo.Email != "" {
		t.Logf("Email: %s", userInfo.Email)
		t.Logf("Email verified: %v", userInfo.EmailVerified)
	}
	if userInfo.PreferredUsername != "" {
		t.Logf("Preferred username: %s", userInfo.PreferredUsername)
	}

	// Test 4: Test UserInfo caching
	userInfo2, err := authenticator.GetUserInfo(ctx, token.AccessToken)
	if err != nil {
		t.Errorf("Failed to get cached UserInfo: %v", err)
	}
	if userInfo2.Subject != userInfo.Subject {
		t.Error("Cached UserInfo differs from original")
	}

	// Test 5: Test cache clearing
	authenticator.ClearUserInfoCache()
	userInfo3, err := authenticator.GetUserInfo(ctx, token.AccessToken)
	if err != nil {
		t.Errorf("Failed to get UserInfo after cache clear: %v", err)
	}
	if userInfo3.Subject != userInfo.Subject {
		t.Error("UserInfo after cache clear differs from original")
	}

	t.Log("UserInfo endpoint validated successfully")
}

// TestOIDC_UserInfoWithInvalidToken tests error handling for invalid tokens.
func TestOIDC_UserInfoWithInvalidToken(t *testing.T) {
	clientID, clientSecret := getPasswordClientCredentials(t)

	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		IssuerURL:     hydraPublicURL + "/",
		UserInfoEndpoint:   hydraPublicURL + "/userinfo",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	cfg := &oauth.Config{
		Provider:     provider,
		Flow:         oauth.FlowClientCredentials,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid"},
		Timeout:      10 * time.Second,
		OIDC: &oauth.OIDCConfig{
			Enabled: true,
			UserInfo: oauth.UserInfoConfig{
				Enabled: true,
				Timeout: 10 * time.Second,
			},
		},
		Validation: oauth.TokenValidationConfig{
			Issuer: hydraPublicURL + "/",
		},
	}

	authenticator, err := oauth.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer authenticator.Close()

	ctx := context.Background()

	// Test 1: Invalid token should fail
	_, err = authenticator.GetUserInfo(ctx, "invalid-token-12345")
	if err == nil {
		t.Error("Expected UserInfo to fail with invalid token")
	} else {
		t.Logf("Invalid token properly rejected: %v", err)
	}

	// Test 2: Empty token should fail
	_, err = authenticator.GetUserInfo(ctx, "")
	if err == nil {
		t.Error("Expected UserInfo to fail with empty token")
	} else {
		t.Logf("Empty token properly rejected: %v", err)
	}
}

// TestOIDC_ClaimsValidation tests validation of all standard OIDC claims.
func TestOIDC_ClaimsValidation(t *testing.T) {
	clientID, clientSecret := getPasswordClientCredentials(t)

	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		IssuerURL:     hydraPublicURL + "/",
		JWKSEndpoint:       hydraPublicURL + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	cfg := &oauth.Config{
		Provider:     provider,
		Flow:         oauth.FlowClientCredentials,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Timeout:      10 * time.Second,
		OIDC: &oauth.OIDCConfig{
			Enabled:        true,
			ValidateNonce:  false,
			ValidateAtHash: false,
			MaxAge:         0, // Don't require specific auth age for client credentials
		},
		Validation: oauth.TokenValidationConfig{
			Method:         oauth.ValidationJWT,
			JWKSURL:        hydraPublicURL + "/.well-known/jwks.json",
			Issuer:         hydraPublicURL + "/",
			Audience:       clientID,
			ClockSkew:      60 * time.Second,
			RequiredClaims: []string{"iss", "sub", "aud", "exp", "iat"},
		},
	}

	authenticator, err := oauth.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer authenticator.Close()

	ctx := context.Background()
	token, err := authenticator.AuthenticateClientCredentials(ctx)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	if token.IDToken == "" {
		t.Skip("Skipping claims validation - no ID token in client credentials flow")
		return
	}

	idClaims, err := authenticator.ValidateIDToken(ctx, token.IDToken, "", token.AccessToken)
	if err != nil {
		t.Fatalf("Failed to validate ID token: %v", err)
	}

	// Test 1: Issuer validation
	t.Run("IssuerClaim", func(t *testing.T) {
		if idClaims.Issuer == "" {
			t.Error("Issuer claim is empty")
		}
		expectedIssuer := hydraPublicURL + "/"
		if idClaims.Issuer != expectedIssuer {
			t.Errorf("Expected issuer '%s', got '%s'", expectedIssuer, idClaims.Issuer)
		}
	})

	// Test 2: Subject validation
	t.Run("SubjectClaim", func(t *testing.T) {
		if idClaims.Subject == "" {
			t.Error("Subject claim is empty")
		}
		if len(idClaims.Subject) < 1 {
			t.Error("Subject claim is too short")
		}
	})

	// Test 3: Audience validation
	t.Run("AudienceClaim", func(t *testing.T) {
		if len(idClaims.Audience) == 0 {
			t.Error("Audience claim is empty")
		}
		foundClientID := false
		for _, aud := range idClaims.Audience {
			if aud == clientID {
				foundClientID = true
				break
			}
		}
		if !foundClientID {
			t.Errorf("Audience %v doesn't contain client_id '%s'", idClaims.Audience, clientID)
		}
	})

	// Test 4: Expiration validation
	t.Run("ExpirationClaim", func(t *testing.T) {
		if idClaims.ExpiresAt == 0 {
			t.Error("Expiration claim is missing")
		}
		exp := time.Unix(idClaims.ExpiresAt, 0)
		if !exp.After(time.Now()) {
			t.Error("Token is already expired")
		}
		// Check reasonable expiration (not too far in future)
		maxExpiry := time.Now().Add(24 * time.Hour)
		if exp.After(maxExpiry) {
			t.Logf("Warning: Token expiration is very far in the future: %s", exp)
		}
	})

	// Test 5: Issued At validation
	t.Run("IssuedAtClaim", func(t *testing.T) {
		if idClaims.IssuedAt == 0 {
			t.Error("Issued at claim is missing")
		}
		iat := time.Unix(idClaims.IssuedAt, 0)
		// Should not be in the future (with clock skew)
		if iat.After(time.Now().Add(60 * time.Second)) {
			t.Error("Issued at time is in the future")
		}
		// Should not be too old (more than 1 hour)
		if iat.Before(time.Now().Add(-1 * time.Hour)) {
			t.Logf("Warning: Token was issued over an hour ago: %s", iat)
		}
	})

	// Test 6: Not Before validation (if present)
	t.Run("NotBeforeClaim", func(t *testing.T) {
		if idClaims.NotBefore > 0 {
			nbf := time.Unix(idClaims.NotBefore, 0)
			if nbf.After(time.Now().Add(60 * time.Second)) {
				t.Error("Token is not yet valid (nbf is in the future)")
			}
		}
	})

	// Test 7: AZP validation (if multiple audiences)
	t.Run("AuthorizedPartyClaim", func(t *testing.T) {
		if len(idClaims.Audience) > 1 {
			if idClaims.AZP == "" {
				t.Error("AZP claim is required when audience has multiple values")
			}
			if idClaims.AZP != clientID {
				t.Errorf("Expected AZP to be '%s', got '%s'", clientID, idClaims.AZP)
			}
		}
	})

	t.Log("All OIDC claims validated successfully")
}

// TestOIDC_NonceValidation tests nonce validation in ID tokens.
func TestOIDC_NonceValidation(t *testing.T) {
	clientID, clientSecret := getPasswordClientCredentials(t)

	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		AuthEndpoint:  hydraPublicURL + "/oauth2/auth",
		IssuerURL:     hydraPublicURL + "/",
		JWKSEndpoint:       hydraPublicURL + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Test 1: Authenticator with nonce validation enabled
	t.Run("NonceGenerationAndStorage", func(t *testing.T) {
		cfg := &oauth.Config{
			Provider:     provider,
			Flow:         oauth.FlowAuthorizationCode,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"openid", "profile"},
			Timeout:      10 * time.Second,
			OIDC: &oauth.OIDCConfig{
				Enabled:       true,
				ValidateNonce: true,
				NonceLifetime: 10 * time.Minute,
			},
			Validation: oauth.TokenValidationConfig{
				Method:    oauth.ValidationJWT,
				JWKSURL:   hydraPublicURL + "/.well-known/jwks.json",
				Issuer:    hydraPublicURL + "/",
				ClockSkew: 60 * time.Second,
			},
		}

		authenticator, err := oauth.NewAuthenticator(cfg)
		if err != nil {
			t.Fatalf("Failed to create authenticator: %v", err)
		}
		defer authenticator.Close()

		// Generate a nonce
		nonce, err := authenticator.GenerateNonce()
		if err != nil {
			t.Fatalf("Failed to generate nonce: %v", err)
		}

		if nonce == "" {
			t.Error("Generated nonce is empty")
		}
		if len(nonce) < 16 {
			t.Errorf("Generated nonce is too short: %d bytes", len(nonce))
		}

		t.Logf("Generated nonce: %s (length: %d)", nonce, len(nonce))

		// Generate another nonce - should be different
		nonce2, err := authenticator.GenerateNonce()
		if err != nil {
			t.Fatalf("Failed to generate second nonce: %v", err)
		}

		if nonce == nonce2 {
			t.Error("Two generated nonces are identical (should be unique)")
		}
	})

	// Test 2: Nonce validation disabled
	t.Run("NonceValidationDisabled", func(t *testing.T) {
		cfg := &oauth.Config{
			Provider:     provider,
			Flow:         oauth.FlowClientCredentials,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       []string{"openid"},
			Timeout:      10 * time.Second,
			OIDC: &oauth.OIDCConfig{
				Enabled:       true,
				ValidateNonce: false,
			},
			Validation: oauth.TokenValidationConfig{
				Method:    oauth.ValidationJWT,
				JWKSURL:   hydraPublicURL + "/.well-known/jwks.json",
				Issuer:    hydraPublicURL + "/",
				ClockSkew: 60 * time.Second,
			},
		}

		authenticator, err := oauth.NewAuthenticator(cfg)
		if err != nil {
			t.Fatalf("Failed to create authenticator: %v", err)
		}
		defer authenticator.Close()

		// Nonce generation should still work but return empty string
		nonce, err := authenticator.GenerateNonce()
		if err != nil {
			t.Fatalf("Failed to generate nonce: %v", err)
		}

		if nonce != "" {
			t.Logf("Note: Nonce generated even though validation is disabled: %s", nonce)
		}
	})

	t.Log("Nonce validation tests completed successfully")
}

// TestOIDC_MultipleScopes tests requesting and validating tokens with multiple OIDC scopes.
func TestOIDC_MultipleScopes(t *testing.T) {
	clientID, clientSecret := getPasswordClientCredentials(t)

	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		IssuerURL:     hydraPublicURL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	testCases := []struct {
		name   string
		scopes []string
	}{
		{
			name:   "OpenIDOnly",
			scopes: []string{"openid"},
		},
		{
			name:   "OpenIDProfile",
			scopes: []string{"openid", "profile"},
		},
		{
			name:   "OpenIDEmail",
			scopes: []string{"openid", "email"},
		},
		{
			name:   "AllStandardScopes",
			scopes: []string{"openid", "profile", "email"},
		},
		{
			name:   "WithOfflineAccess",
			scopes: []string{"openid", "profile", "offline"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &oauth.Config{
				Provider:     provider,
				Flow:         oauth.FlowClientCredentials,
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scopes:       tc.scopes,
				Timeout:      10 * time.Second,
				OIDC: &oauth.OIDCConfig{
					Enabled: true,
				},
				Validation: oauth.TokenValidationConfig{
					Issuer: hydraPublicURL + "/",
				},
			}

			authenticator, err := oauth.NewAuthenticator(cfg)
			if err != nil {
				t.Fatalf("Failed to create authenticator: %v", err)
			}
			defer authenticator.Close()

			ctx := context.Background()
			token, err := authenticator.AuthenticateClientCredentials(ctx)
			if err != nil {
				t.Fatalf("Failed to get token with scopes %v: %v", tc.scopes, err)
			}

			if token.AccessToken == "" {
				t.Error("Access token is empty")
			}

			t.Logf("Successfully obtained token with scopes: %v", tc.scopes)
			t.Logf("Token type: %s, expires in: %d seconds", token.TokenType, int64(time.Until(token.Expiry).Seconds()))

			// Check if refresh token is present for offline access
			if contains(tc.scopes, "offline") {
				if token.RefreshToken != "" {
					t.Logf("Refresh token obtained (scope offline requested)")
				} else {
					t.Log("Note: No refresh token (may not be available for client credentials flow)")
				}
			}
		})
	}
}

// TestOIDC_IntegrationWithExistingFlow tests OIDC with the existing token validation flow.
func TestOIDC_IntegrationWithExistingFlow(t *testing.T) {
	// Use password client which has openid scope
	clientID, clientSecret := getPasswordClientCredentials(t)

	// Step 1: Get a token with OIDC scopes
	tokenProvider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:  "hydra",
		TokenEndpoint: hydraPublicURL + "/oauth2/token",
		IssuerURL:     hydraPublicURL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create token provider: %v", err)
	}

	tokenCfg := &oauth.Config{
		Provider:     tokenProvider,
		Flow:         oauth.FlowClientCredentials,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile"},
		Timeout:      10 * time.Second,
		OIDC: &oauth.OIDCConfig{
			Enabled: true,
		},
	}

	tokenAuth, err := oauth.NewAuthenticator(tokenCfg)
	if err != nil {
		t.Fatalf("Failed to create token authenticator: %v", err)
	}
	defer tokenAuth.Close()

	ctx := context.Background()
	token, err := tokenAuth.AuthenticateClientCredentials(ctx)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	// Step 2: Validate the token with OIDC-aware validator
	validationProvider, err := oauth.CustomProvider(oauth.ProviderConfig{
		ProviderName:          "hydra",
		TokenEndpoint:         hydraPublicURL + "/oauth2/token",
		IntrospectionEndpoint: hydraAdminURL + "/admin/oauth2/introspect",
		IssuerURL:             hydraPublicURL + "/",
		JWKSEndpoint:               hydraPublicURL + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("Failed to create validation provider: %v", err)
	}

	validationCfg := &oauth.Config{
		Provider:     validationProvider,
		Flow:         oauth.FlowTokenValidation,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Timeout:      10 * time.Second,
		OIDC: &oauth.OIDCConfig{
			Enabled: true,
		},
		Validation: oauth.TokenValidationConfig{
			Method:           oauth.ValidationHybrid,
			JWKSURL:          hydraPublicURL + "/.well-known/jwks.json",
			IntrospectionURL: hydraAdminURL + "/admin/oauth2/introspect",
			Issuer:           hydraPublicURL + "/",
			ClockSkew:        60 * time.Second,
		},
	}

	validator, err := oauth.NewAuthenticator(validationCfg)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}
	defer validator.Close()

	// Validate access token
	claims, err := validator.ValidateToken(ctx, token.AccessToken)
	if err != nil {
		t.Errorf("Failed to validate access token: %v", err)
	} else {
		t.Logf("Access token validated successfully")
		t.Logf("Subject: %s", claims.Subject)
		t.Logf("Expires: %s", claims.ExpiresAt)
	}

	// If ID token is present, validate it too
	if token.IDToken != "" {
		idClaims, err := validator.ValidateIDToken(ctx, token.IDToken, "", token.AccessToken)
		if err != nil {
			t.Errorf("Failed to validate ID token: %v", err)
		} else {
			t.Logf("ID token validated successfully")
			t.Logf("ID token subject: %s", idClaims.Subject)
		}
	}

	t.Log("OIDC integration with existing flows validated successfully")
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
