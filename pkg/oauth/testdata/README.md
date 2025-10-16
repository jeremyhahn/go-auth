# OAuth Integration Test Setup

This directory contains the setup scripts and configuration for running OAuth integration tests against a real ORY Hydra OAuth 2.0 server.

## Overview

The OAuth integration tests use ORY Hydra, a lightweight and production-ready OAuth 2.0 and OpenID Connect server, to test real OAuth flows instead of mock servers.

## Architecture

```
Docker Container
├── ORY Hydra Server (ports 4444/4445)
│   ├── Public endpoint: http://127.0.0.1:4444
│   └── Admin endpoint: http://127.0.0.1:4445
├── Test OAuth Clients (created by setup-hydra.sh)
│   ├── test-client-credentials (for client credentials flow)
│   ├── test-password-client (for password flow)
│   └── test-auth-code-client (for authorization code flow)
└── Integration Tests
    └── Test against real Hydra endpoints
```

## Test Clients

The `setup-hydra.sh` script creates three OAuth clients:

### 1. Client Credentials Client
- **Client ID**: `test-client-credentials`
- **Client Secret**: `test-client-secret`
- **Grant Types**: `client_credentials`
- **Scopes**: `api:read`, `api:write`
- **Use Case**: Machine-to-machine authentication

### 2. Password Flow Client
- **Client ID**: `test-password-client`
- **Client Secret**: `test-password-secret`
- **Grant Types**: `password`, `refresh_token`
- **Scopes**: `openid`, `profile`, `email`, `offline`
- **Use Case**: First-party applications (Hydra in dev mode accepts any credentials)

### 3. Authorization Code Client
- **Client ID**: `test-auth-code-client`
- **Client Secret**: `test-auth-code-secret`
- **Grant Types**: `authorization_code`, `refresh_token`
- **Scopes**: `openid`, `profile`, `email`, `offline`
- **Redirect URIs**: `http://127.0.0.1:8080/callback`, `http://localhost:8080/callback`
- **Use Case**: Third-party applications with user consent

## Running Integration Tests

### From the oauth package directory:
```bash
make integration-test
```

This will:
1. Build a Docker image with Go, Hydra, and the test code
2. Start Hydra in dev mode
3. Create test OAuth clients
4. Run integration tests
5. Clean up and exit

### Manually with Docker:
```bash
# Build the image
docker build -f pkg/oauth/Dockerfile -t go-auth-oauth-integration:latest .

# Run the tests
docker run --rm go-auth-oauth-integration:latest
```

### Running specific tests:
```bash
docker run --rm go-auth-oauth-integration:latest \
  bash -c "hydra serve all --dev & sleep 5; /setup-hydra.sh; \
  go test -v -tags integration ./test/integration/oauth -run TestOAuthIntegration_ClientCredentialsFlow"
```

## What Gets Tested

The integration tests verify:

1. **Client Credentials Flow**
   - Successful token acquisition with valid credentials
   - Proper rejection of invalid credentials
   - Token response structure and validity

2. **Password Flow** (ROPC)
   - Token acquisition with username/password
   - Refresh token handling

3. **Token Introspection**
   - Validating active tokens
   - Rejecting invalid tokens
   - Token claims extraction

4. **API Integration**
   - Integration with api.Service
   - OAuth backend authentication
   - Error handling

5. **Token Caching**
   - Cache hit performance
   - Cache clearing
   - Expired token handling

6. **Multiple Scopes**
   - Requesting tokens with multiple scopes
   - Scope validation

## Hydra Configuration

The Hydra server runs with these settings:

- **Mode**: Development (`--dev`)
- **Database**: In-memory (ephemeral)
- **Public Port**: 4444
- **Admin Port**: 4445
- **CORS**: Enabled for testing
- **Log Level**: Error (to reduce noise)

## Important Notes

1. **Dev Mode**: Hydra runs in `--dev` mode which:
   - Accepts any username/password for password flow
   - Uses in-memory storage (data lost on restart)
   - Disables some security checks
   - Should NOT be used in production

2. **Network**: All services run on localhost (127.0.0.1) within the container

3. **Cleanup**: The Docker container is removed after tests complete

4. **Test Isolation**: Each test should be independent and not rely on state from other tests

## Troubleshooting

### Hydra fails to start
- Check if ports 4444/4445 are available
- Increase the startup wait time in Dockerfile CMD
- Check Hydra logs: `docker logs <container-id>`

### Tests timeout
- Increase the timeout in test configurations
- Check network connectivity within container
- Verify Hydra health: `curl http://127.0.0.1:4444/health/ready`

### Client creation fails
- Check the setup-hydra.sh script
- Verify Hydra admin endpoint is accessible
- Run setup script manually to see detailed errors

## References

- [ORY Hydra Documentation](https://www.ory.sh/hydra/docs/)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.0 Token Introspection RFC 7662](https://tools.ietf.org/html/rfc7662)
