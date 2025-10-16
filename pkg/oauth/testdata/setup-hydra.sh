#!/bin/bash
set -e

echo "Setting up Hydra test clients..."

# Create OAuth client for client credentials flow with fixed client ID
CLIENT_CC=$(hydra create oauth2-client \
    --endpoint http://127.0.0.1:4445 \
    --name test-client-credentials \
    --secret test-client-secret \
    --grant-type client_credentials \
    --response-type token \
    --scope "api:read,api:write" \
    --token-endpoint-auth-method client_secret_post \
    --format json)

# Extract the client ID and update it to our expected value if needed
CLIENT_CC_ID=$(echo "$CLIENT_CC" | jq -r '.client_id')
echo "Created client credentials client: $CLIENT_CC_ID"

# Create OAuth client for password flow with client_credentials support for OIDC tests
# This allows testing OIDC discovery and configuration without needing interactive auth
CLIENT_PW=$(hydra create oauth2-client \
    --endpoint http://127.0.0.1:4445 \
    --name test-password-client \
    --secret test-password-secret \
    --grant-type password,refresh_token,client_credentials \
    --response-type token \
    --scope "openid,profile,email,offline" \
    --token-endpoint-auth-method client_secret_post \
    --format json)

CLIENT_PW_ID=$(echo "$CLIENT_PW" | jq -r '.client_id')
echo "Created password flow client: $CLIENT_PW_ID"

# Create OAuth client for authorization code flow with PKCE
CLIENT_AC=$(hydra create oauth2-client \
    --endpoint http://127.0.0.1:4445 \
    --name test-auth-code-client \
    --secret test-auth-code-secret \
    --grant-type authorization_code,refresh_token \
    --response-type code,id_token \
    --scope "openid,profile,email,offline" \
    --redirect-uri http://127.0.0.1:8080/callback,http://localhost:8080/callback \
    --token-endpoint-auth-method client_secret_post \
    --format json)

CLIENT_AC_ID=$(echo "$CLIENT_AC" | jq -r '.client_id')
echo "Created authorization code client: $CLIENT_AC_ID"

# Export environment variables for tests
export TEST_OAUTH_CLIENT_CREDENTIALS_ID="$CLIENT_CC_ID"
export TEST_OAUTH_CLIENT_CREDENTIALS_SECRET="test-client-secret"
export TEST_OAUTH_PASSWORD_CLIENT_ID="$CLIENT_PW_ID"
export TEST_OAUTH_PASSWORD_CLIENT_SECRET="test-password-secret"
export TEST_OAUTH_AUTHCODE_CLIENT_ID="$CLIENT_AC_ID"
export TEST_OAUTH_AUTHCODE_CLIENT_SECRET="test-auth-code-secret"

# Save to file for the tests to source
cat > /tmp/oauth-test-env.sh << EOF
export TEST_OAUTH_CLIENT_CREDENTIALS_ID="$CLIENT_CC_ID"
export TEST_OAUTH_CLIENT_CREDENTIALS_SECRET="test-client-secret"
export TEST_OAUTH_PASSWORD_CLIENT_ID="$CLIENT_PW_ID"
export TEST_OAUTH_PASSWORD_CLIENT_SECRET="test-password-secret"
export TEST_OAUTH_AUTHCODE_CLIENT_ID="$CLIENT_AC_ID"
export TEST_OAUTH_AUTHCODE_CLIENT_SECRET="test-auth-code-secret"
EOF

echo ""
echo "Hydra is configured and ready for testing"
echo "Public endpoint: http://127.0.0.1:4444"
echo "Admin endpoint: http://127.0.0.1:4445"
