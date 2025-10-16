# OIDC Integration Tests

This document describes the comprehensive OIDC (OpenID Connect) integration tests added to the OAuth test suite.

## Overview

The OIDC integration tests in `oidc_integration_test.go` validate the full OIDC functionality of the OAuth package against a real ORY Hydra server. These tests ensure compatibility with the OpenID Connect specification and proper integration with OIDC providers.

## Test Coverage

### 1. TestOIDC_Discovery
Tests the OIDC discovery endpoint (/.well-known/openid-configuration) functionality.

**What it tests:**
- Fetching the discovery document from the provider
- Validation of required fields (issuer, endpoints, supported features)
- Verification of supported scopes (openid, profile, email)
- Supported response types and grant types
- Supported signing algorithms for ID tokens
- PKCE support detection
- Discovery document caching
- Manual discovery refresh

**Expected behavior:**
- Discovery document contains all required OIDC fields
- Provider supports standard OIDC scopes
- Document validates according to OIDC spec
- Caching works correctly to reduce network calls

---

### 2. TestOIDC_IDTokenValidation
Tests ID token validation with JWT parsing and signature verification.

**What it tests:**
- Obtaining tokens with openid scope
- ID token presence in token response
- ID token JWT signature validation
- Required claims validation (iss, sub, aud, exp, iat)
- Issuer claim matches configuration
- Audience contains client_id
- Expiration and issued_at time validation

**Expected behavior:**
- Client credentials flow may not return ID tokens (expected)
- When ID token is present, all claims are valid
- Signature verification passes
- Time-based validations respect clock skew

**Note:** ORY Hydra in client credentials flow does not return ID tokens since there's no end-user involved. Tests handle this gracefully by skipping when appropriate.

---

### 3. TestOIDC_IDTokenParsing
Tests parsing of ID token JWT structure and claim extraction.

**What it tests:**
- JWT structure (header.payload.signature)
- Header parsing (alg, typ, kid)
- Algorithm validation (must not be 'none')
- Payload parsing and claim extraction
- Presence of standard claims

**Expected behavior:**
- ID token is a valid 3-part JWT
- Signing algorithm is secure (not 'none')
- All standard OIDC claims are present
- JSON structure is valid

---

### 4. TestOIDC_UserInfo
Tests the OIDC UserInfo endpoint functionality.

**What it tests:**
- Calling the UserInfo endpoint with access token
- Subject claim presence (required)
- Profile claims (name, email, username)
- UserInfo caching
- Cache clearing

**Expected behavior:**
- UserInfo endpoint returns valid user data
- Subject matches ID token subject
- Profile claims are included when scopes granted
- Caching reduces redundant network calls

**Note:** UserInfo may not be available for client credentials flow (no end-user).

---

### 5. TestOIDC_UserInfoWithInvalidToken
Tests error handling for UserInfo endpoint with invalid tokens.

**What it tests:**
- Invalid token rejection
- Empty token rejection
- Proper error messages

**Expected behavior:**
- Invalid tokens are properly rejected
- Empty tokens return appropriate errors
- No server crashes or unexpected behavior

---

### 6. TestOIDC_ClaimsValidation
Comprehensive validation of all standard OIDC claims.

**Tests each claim:**
1. **Issuer (iss):** Matches configured issuer
2. **Subject (sub):** Present and non-empty
3. **Audience (aud):** Contains client_id
4. **Expiration (exp):** In the future, reasonable duration
5. **Issued At (iat):** Not in the future, not too old
6. **Not Before (nbf):** If present, validation logic
7. **Authorized Party (azp):** Required when multiple audiences

**Expected behavior:**
- All required claims are present
- Time-based validations pass with clock skew tolerance
- Audience and issuer match configuration
- Claims follow OIDC specification requirements

---

### 7. TestOIDC_NonceValidation
Tests nonce generation, storage, and validation for preventing replay attacks.

**Subtests:**

#### NonceGenerationAndStorage
- Generate unique nonces
- Nonces have sufficient length (>= 16 bytes)
- Multiple nonces are different
- Nonce storage for validation

#### NonceValidationDisabled
- Behavior when nonce validation is disabled
- Configuration flexibility

**Expected behavior:**
- Nonces are cryptographically random
- Each nonce is unique
- Nonce validation can be enabled/disabled
- Proper nonce lifetime management

**Note:** Nonce validation is primarily for authorization code flow. Client credentials flow doesn't use nonces.

---

### 8. TestOIDC_MultipleScopes
Tests requesting and validating tokens with various OIDC scope combinations.

**Scope combinations tested:**
1. `openid` - Minimum required scope
2. `openid profile` - With profile information
3. `openid email` - With email information
4. `openid profile email` - All standard scopes
5. `openid profile offline` - With refresh token (offline_access)

**Expected behavior:**
- Tokens obtained successfully with all scope combinations
- Access tokens work regardless of scopes
- Refresh tokens may be issued with offline scope
- Scope flexibility maintained

---

### 9. TestOIDC_IntegrationWithExistingFlow
Tests OIDC integration with existing OAuth 2.0 token validation flows.

**What it tests:**
- Getting tokens with OIDC scopes
- Validating access tokens with OIDC-aware validator
- Validating ID tokens when present
- Hybrid validation (JWT + introspection)
- Integration between token issuance and validation

**Expected behavior:**
- OIDC features work seamlessly with existing OAuth flows
- Both access token and ID token validation work
- Backward compatibility maintained
- Hybrid validation strategies work correctly

---

## Running the Tests

### Prerequisites

The tests require:
- Go 1.21+
- Docker (for running ORY Hydra)
- ORY Hydra v2.2.0+ running locally

### Run via Docker

```bash
make -C pkg/oauth integration-test
```

This will:
1. Build the integration test container
2. Start ORY Hydra server
3. Create test OAuth clients
4. Run all integration tests
5. Clean up

### Run Manually

If Hydra is already running:

```bash
# Set up test clients
./pkg/oauth/testdata/setup-hydra.sh

# Source environment variables
source /tmp/oauth-test-env.sh

# Run OIDC tests only
go test -v -tags integration ./test/integration/oauth -run "TestOIDC"

# Run all OAuth integration tests
go test -v -tags integration ./test/integration/oauth
```

## Test Design Principles

1. **Real Integration Tests:** Tests run against actual ORY Hydra server, not mocks
2. **Graceful Handling:** Tests handle expected limitations (e.g., no ID token in client credentials)
3. **Comprehensive Coverage:** All OIDC features tested end-to-end
4. **Clear Expectations:** Each test documents what's expected and why
5. **Isolation:** Tests are independent and can run in any order
6. **Informative:** Detailed logging helps understand test behavior

## Known Limitations

1. **Client Credentials Flow:**
   - Does not return ID tokens (no end-user involved) - this is expected and per spec
   - UserInfo endpoint may not be available
   - Nonces not applicable

2. **Hydra Specifics:**
   - Password grant not supported (security best practice)
   - Authorization code flow requires interactive login (not tested in integration tests)

3. **Test Scope:**
   - Tests focus on token issuance and validation
   - Full authorization code flow with UI interactions not covered
   - Token refresh with ID tokens not explicitly tested

## Future Enhancements

Potential additions:
1. Authorization code flow with PKCE simulation
2. Token refresh with ID token rotation
3. at_hash validation testing
4. c_hash validation for hybrid flow
5. ACR (Authentication Context Class Reference) validation
6. max_age validation
7. UserInfo with signed/encrypted responses
8. Multiple audience scenarios
9. Sub-domain issuer scenarios
10. JWKS rotation testing

## Troubleshooting

### Tests Skip Unexpectedly

If tests skip with messages about missing ID tokens or UserInfo:
- This is **expected behavior** for client credentials flow
- Client credentials is machine-to-machine authentication without end-users
- OIDC ID tokens represent user identity, not present without users

### Discovery Failures

If discovery tests fail:
- Check Hydra is running: `curl http://127.0.0.1:4444/health/ready`
- Verify issuer configuration matches
- Check network connectivity

### JWT Validation Failures

If JWT validation fails:
- Ensure clock skew tolerance is configured (60s default)
- Check system time synchronization
- Verify JWKS endpoint is accessible

### Compilation Errors

If tests don't compile:
- Ensure you're using the correct struct field names
- `ProviderConfig` uses: `JWKSEndpoint`, `UserInfoEndpoint`, `AuthEndpoint`, `TokenEndpoint`
- `TokenValidationConfig` uses: `JWKSURL`, `IntrospectionURL`

## Contributing

When adding new OIDC tests:
1. Follow existing test patterns
2. Add clear documentation of what's being tested
3. Handle expected failures gracefully (skip with explanation)
4. Log relevant information for debugging
5. Test against real OIDC providers when possible
6. Update this documentation

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [ORY Hydra Documentation](https://www.ory.sh/docs/hydra/)
- [OAuth 2.0 for Go](https://pkg.go.dev/golang.org/x/oauth2)
