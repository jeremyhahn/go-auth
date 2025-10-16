package oauth

import "errors"

var (
	// ErrMissingToken indicates no token was provided for validation.
	ErrMissingToken = errors.New("oauth: missing token")

	// ErrInvalidToken indicates the token is malformed or has an invalid signature.
	ErrInvalidToken = errors.New("oauth: invalid token")

	// ErrExpiredToken indicates the token has expired.
	ErrExpiredToken = errors.New("oauth: token expired")

	// ErrInvalidConfiguration indicates the authenticator configuration is invalid.
	ErrInvalidConfiguration = errors.New("oauth: invalid configuration")

	// ErrProviderNotSupported indicates the requested provider is not supported.
	ErrProviderNotSupported = errors.New("oauth: provider not supported")

	// ErrFlowNotSupported indicates the requested OAuth flow is not supported.
	ErrFlowNotSupported = errors.New("oauth: flow not supported")

	// ErrInvalidClaims indicates the token claims are invalid or missing required fields.
	ErrInvalidClaims = errors.New("oauth: invalid claims")

	// ErrIntrospectionFailed indicates token introspection failed.
	ErrIntrospectionFailed = errors.New("oauth: introspection failed")

	// ErrJWKSFetchFailed indicates JWKS retrieval failed.
	ErrJWKSFetchFailed = errors.New("oauth: jwks fetch failed")

	// ErrTokenExchangeFailed indicates OAuth token exchange failed.
	ErrTokenExchangeFailed = errors.New("oauth: token exchange failed")

	// OIDC-specific errors

	// ErrOIDCNotEnabled indicates OIDC functionality is not enabled.
	ErrOIDCNotEnabled = errors.New("oauth: oidc not enabled")

	// ErrOIDCDiscoveryFailed indicates OIDC discovery document fetch failed.
	ErrOIDCDiscoveryFailed = errors.New("oauth: oidc discovery failed")

	// ErrOIDCInvalidDiscovery indicates the OIDC discovery document is invalid or incomplete.
	ErrOIDCInvalidDiscovery = errors.New("oauth: invalid oidc discovery document")

	// ErrOIDCMissingIDToken indicates no ID token was returned when one was required.
	ErrOIDCMissingIDToken = errors.New("oauth: missing id token")

	// ErrOIDCInvalidIDToken indicates the ID token is invalid or failed validation.
	ErrOIDCInvalidIDToken = errors.New("oauth: invalid id token")

	// ErrOIDCInvalidNonce indicates nonce validation failed.
	ErrOIDCInvalidNonce = errors.New("oauth: invalid nonce")

	// ErrOIDCNonceExpired indicates the nonce has expired.
	ErrOIDCNonceExpired = errors.New("oauth: nonce expired")

	// ErrOIDCNonceNotFound indicates the nonce was not found in the store.
	ErrOIDCNonceNotFound = errors.New("oauth: nonce not found")

	// ErrOIDCInvalidAtHash indicates at_hash validation failed.
	ErrOIDCInvalidAtHash = errors.New("oauth: invalid at_hash")

	// ErrOIDCAuthTimeTooOld indicates the auth_time is older than max_age.
	ErrOIDCAuthTimeTooOld = errors.New("oauth: authentication too old")

	// ErrOIDCInvalidACR indicates the acr claim doesn't match required values.
	ErrOIDCInvalidACR = errors.New("oauth: invalid acr")

	// ErrOIDCUserInfoFailed indicates UserInfo endpoint request failed.
	ErrOIDCUserInfoFailed = errors.New("oauth: userinfo request failed")

	// ErrOIDCInvalidUserInfo indicates UserInfo response is invalid.
	ErrOIDCInvalidUserInfo = errors.New("oauth: invalid userinfo response")
)
