# OAuth 2.0 / OIDC Package

The `oauth` package provides comprehensive OAuth 2.0 and OpenID Connect (OIDC) authentication support for the go-auth library.

## Features

- Multiple OAuth 2.0 flows
  - Token Validation (JWT and introspection)
  - Client Credentials
  - Resource Owner Password Credentials
  - Authorization Code with PKCE support
- Pre-configured providers (Google, Microsoft, GitHub, Okta, Auth0, Keycloak)
- Custom provider support
- In-memory token caching with LRU eviction
- JWT validation using JWKS
- OAuth introspection support
- Hybrid validation (JWT with introspection fallback)
- Thread-safe, concurrent operation
- Context-aware with proper cancellation
- Configurable timeouts and retry logic

## Quick Reference

### Token Validation Only

```go
config := &oauth.Config{
    Provider: oauth.Google(),
    Flow:     oauth.FlowTokenValidation,
    ClientID: "your-client-id",
    Validation: oauth.TokenValidationConfig{
        Method:  oauth.ValidationJWT,
        JWKSURL: "https://www.googleapis.com/oauth2/v3/certs",
    },
}

auth, _ := oauth.NewAuthenticator(config)
defer auth.Close()

claims, err := auth.ValidateToken(ctx, token)
```

### Client Credentials Flow

```go
config := &oauth.Config{
    Provider:     oauth.Keycloak("https://keycloak.example.com", "master"),
    Flow:         oauth.FlowClientCredentials,
    ClientID:     "service-account",
    ClientSecret: "secret",
}

auth, _ := oauth.NewAuthenticator(config)
token, err := auth.AuthenticateClientCredentials(ctx)
```

### Password Flow

```go
config := &oauth.Config{
    Provider:     oauth.Auth0("myapp.us.auth0.com"),
    Flow:         oauth.FlowPassword,
    ClientID:     "client-id",
    ClientSecret: "secret",
}

auth, _ := oauth.NewAuthenticator(config)
token, err := auth.AuthenticatePassword(ctx, "user@example.com", "password")
```

### Authorization Code + PKCE

```go
config := &oauth.Config{
    Provider:    oauth.Microsoft(),
    Flow:        oauth.FlowAuthorizationCode,
    ClientID:    "client-id",
    RedirectURL: "http://localhost:8080/callback",
}

auth, _ := oauth.NewAuthenticator(config)

// Step 1: Generate auth URL
authURL, codeVerifier, _ := auth.BuildAuthURL("state", true, nil)
// Redirect user to authURL

// Step 2: Exchange code for token
token, err := auth.ExchangeAuthorizationCode(ctx, code, codeVerifier)
```

### With Token Caching

```go
Cache: oauth.CacheConfig{
    Enabled: true,
    MaxSize: 1000,
    TTL:     5 * time.Minute,
}
```

### Hybrid Validation

```go
Validation: oauth.TokenValidationConfig{
    Method:           oauth.ValidationHybrid,
    JWKSURL:          "https://provider.com/jwks",
    IntrospectionURL: "https://provider.com/introspect",
}
```

### With Required Claims

```go
Validation: oauth.TokenValidationConfig{
    Method:         oauth.ValidationJWT,
    JWKSURL:        "https://provider.com/jwks",
    RequiredClaims: []string{"email", "email_verified", "sub"},
}
```

### Token Claims Access

```go
claims, _ := auth.ValidateToken(ctx, token)

fmt.Println(claims.Subject)       // User ID
fmt.Println(claims.Email)         // Email
fmt.Println(claims.Name)          // Display name
fmt.Println(claims.Scopes)        // Scopes
fmt.Println(claims.Groups)        // Groups
fmt.Println(claims.Custom["key"]) // Custom claim
```

### Pre-configured Providers

```go
oauth.Google()                                    // Google
oauth.Microsoft()                                 // Microsoft Azure AD
oauth.GitHub()                                    // GitHub
oauth.Okta("dev-12345.okta.com")                 // Okta
oauth.Auth0("myapp.us.auth0.com")                // Auth0
oauth.Keycloak("https://kc.example.com", "realm") // Keycloak
```

## Detailed Documentation

### Token Validation

Validate existing OAuth access tokens:

```go
import "github.com/jhahn/go-auth/pkg/oauth"

config := &oauth.Config{
    Provider: oauth.Google(),
    Flow:     oauth.FlowTokenValidation,
    ClientID: "your-client-id",
    Validation: oauth.TokenValidationConfig{
        Method:   oauth.ValidationJWT,
        JWKSURL:  "https://www.googleapis.com/oauth2/v3/certs",
        Issuer:   "https://accounts.google.com",
        Audience: "your-client-id",
    },
    Cache: oauth.CacheConfig{
        Enabled: true,
        MaxSize: 1000,
        TTL:     5 * time.Minute,
    },
}

auth, err := oauth.NewAuthenticator(config)
if err != nil {
    log.Fatal(err)
}
defer auth.Close()

claims, err := auth.ValidateToken(ctx, accessToken)
if err != nil {
    log.Printf("Invalid token: %v", err)
    return
}

fmt.Printf("User: %s (%s)\n", claims.Name, claims.Email)
```

### Client Credentials Flow

Authenticate service-to-service:

```go
config := &oauth.Config{
    Provider:     oauth.Keycloak("https://keycloak.example.com", "master"),
    Flow:         oauth.FlowClientCredentials,
    ClientID:     "service-account",
    ClientSecret: "secret",
    Scopes:       []string{"api.read", "api.write"},
}

auth, err := oauth.NewAuthenticator(config)
if err != nil {
    log.Fatal(err)
}

token, err := auth.AuthenticateClientCredentials(ctx)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Access Token: %s\n", token.AccessToken)
```

### Password Flow

Direct username/password authentication:

```go
config := &oauth.Config{
    Provider:     oauth.Auth0("myapp.us.auth0.com"),
    Flow:         oauth.FlowPassword,
    ClientID:     "client-id",
    ClientSecret: "client-secret",
    Scopes:       []string{"openid", "profile", "email"},
}

auth, err := oauth.NewAuthenticator(config)
if err != nil {
    log.Fatal(err)
}

token, err := auth.AuthenticatePassword(ctx, "user@example.com", "password")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Access Token: %s\n", token.AccessToken)
fmt.Printf("ID Token: %s\n", token.IDToken)
```

### Authorization Code Flow with PKCE

User-interactive authentication flow:

```go
config := &oauth.Config{
    Provider:    oauth.Microsoft(),
    Flow:        oauth.FlowAuthorizationCode,
    ClientID:    "client-id",
    RedirectURL: "http://localhost:8080/callback",
    Scopes:      []string{"openid", "profile", "email"},
}

auth, err := oauth.NewAuthenticator(config)
if err != nil {
    log.Fatal(err)
}

// Generate authorization URL with PKCE
state := generateRandomState() // Your CSRF token
authURL, codeVerifier, err := auth.BuildAuthURL(state, true, nil)
if err != nil {
    log.Fatal(err)
}

// Redirect user to authURL...

// After receiving callback with authorization code:
token, err := auth.ExchangeAuthorizationCode(ctx, code, codeVerifier)
if err != nil {
    log.Fatal(err)
}
```

## Provider Configuration

### Google

```go
provider := oauth.Google()
```

### Microsoft Azure AD

```go
provider := oauth.Microsoft()
```

### GitHub

```go
provider := oauth.GitHub()
```

### Okta

```go
provider := oauth.Okta("dev-12345.okta.com")
```

### Auth0

```go
provider := oauth.Auth0("myapp.us.auth0.com")
```

### Keycloak

```go
provider := oauth.Keycloak("https://keycloak.example.com", "master")
```

### Custom Providers

Define a custom OAuth provider:

```go
provider, err := oauth.CustomProvider(oauth.ProviderConfig{
    ProviderName:          "custom",
    AuthEndpoint:          "https://provider.com/oauth/authorize",
    TokenEndpoint:         "https://provider.com/oauth/token",
    JWKSEndpoint:          "https://provider.com/oauth/jwks",
    IntrospectionEndpoint: "https://provider.com/oauth/introspect",
    IssuerURL:             "https://provider.com",
})

config := &oauth.Config{
    Provider: provider,
    ClientID: "client-id",
    Flow:     oauth.FlowTokenValidation,
    Validation: oauth.TokenValidationConfig{
        Method:  oauth.ValidationJWT,
        JWKSURL: provider.JWKSURL(),
    },
}
```

## Validation Methods

### JWT Validation (Local)

Fast local validation using JWKS:

```go
Validation: oauth.TokenValidationConfig{
    Method:  oauth.ValidationJWT,
    JWKSURL: "https://provider.com/jwks",
}
```

### Introspection (Remote)

Remote validation via OAuth introspection endpoint:

```go
Validation: oauth.TokenValidationConfig{
    Method:           oauth.ValidationIntrospection,
    IntrospectionURL: "https://provider.com/introspect",
}
```

### Hybrid Validation

Try JWT first, fallback to introspection:

```go
Validation: oauth.TokenValidationConfig{
    Method:           oauth.ValidationHybrid,
    JWKSURL:          "https://provider.com/jwks",
    IntrospectionURL: "https://provider.com/introspect",
}
```

## Token Caching

Enable in-memory caching to reduce latency and provider load:

```go
Cache: oauth.CacheConfig{
    Enabled: true,
    MaxSize: 1000,              // LRU eviction after 1000 tokens
    TTL:     5 * time.Minute,   // Cache for 5 minutes
}
```

Clear cache manually:

```go
auth.ClearCache()
```

## Integration with go-auth API

Use OAuth with the api package:

```go
import (
    "github.com/jhahn/go-auth/pkg/api"
    "github.com/jhahn/go-auth/pkg/oauth"
)

oauthAuth, _ := oauth.NewAuthenticator(config)
defer oauthAuth.Close()

service, _ := api.NewService(api.Config{
    Backends: []api.Backend{
        {Name: api.BackendOAuth, Handler: api.OAuth(oauthAuth)},
    },
})

err := service.Login(ctx, api.LoginRequest{
    Backend:  api.BackendOAuth,
    Password: token, // Token goes in password field
})
```

## Configuration Options

### Required Configuration

- `Provider`: OAuth provider (pre-configured or custom)
- `ClientID`: OAuth client identifier
- `Flow`: OAuth flow type

### Flow-Specific Requirements

**FlowTokenValidation:**
- `Validation.JWKSURL` (for JWT validation)
- `Validation.IntrospectionURL` (for introspection)

**FlowClientCredentials:**
- `ClientSecret`

**FlowPassword:**
- `ClientSecret`

**FlowAuthorizationCode:**
- `ClientSecret` (optional for public clients)
- `RedirectURL`

### Optional Configuration

- `Scopes`: OAuth scopes to request
- `Timeout`: HTTP client timeout (default: 30s)
- `TLSConfig`: Custom TLS configuration
- `InsecureSkipVerify`: Disable TLS verification (not recommended)
- `Validation.Issuer`: Expected token issuer
- `Validation.Audience`: Expected token audience
- `Validation.ClockSkew`: Time tolerance (default: 60s)
- `Validation.RequiredClaims`: Claims that must be present

### Configuration Defaults

- Timeout: 30 seconds
- Clock Skew: 60 seconds
- Cache MaxSize: 1000
- Cache TTL: 5 minutes
- Validation Method: Hybrid (when JWKS URL provided)

## Error Handling

Common errors:

```go
claims, err := auth.ValidateToken(ctx, token)
if err != nil {
    switch {
    case errors.Is(err, oauth.ErrMissingToken):
        // No token provided
    case errors.Is(err, oauth.ErrInvalidToken):
        // Token is invalid or malformed
    case errors.Is(err, oauth.ErrExpiredToken):
        // Token has expired
    case errors.Is(err, oauth.ErrInvalidConfiguration):
        // Configuration error
    default:
        // Other error
    }
}
```

## Security Best Practices

1. **Always use TLS in production** - Enabled by default
2. **Use PKCE for authorization code flow** - Prevents code interception
3. **Validate issuer and audience claims** - Prevents token misuse
4. **Set appropriate clock skew** - Accounts for time drift (default: 60s)
5. **Never log secrets or tokens** - Prevents credential leakage
6. **Use state parameter** - Prevents CSRF attacks in auth code flow
7. **Rotate client secrets regularly** - Limits exposure window
8. **Enable caching judiciously** - Balance security and performance

### Security Checklist

- [ ] Use TLS in production (enabled by default)
- [ ] Validate issuer claim
- [ ] Validate audience claim
- [ ] Use PKCE for authorization code flow
- [ ] Set appropriate clock skew tolerance
- [ ] Never log tokens or secrets
- [ ] Use state parameter for CSRF protection
- [ ] Enable caching for performance
- [ ] Set proper timeout values
- [ ] Close authenticator when done

## Thread Safety

The `Authenticator` is thread-safe and can be used concurrently across multiple goroutines. It is immutable after construction.

```go
auth, _ := oauth.NewAuthenticator(config)
defer auth.Close()

// Safe to use from multiple goroutines
go func() {
    claims, _ := auth.ValidateToken(ctx, token1)
}()

go func() {
    claims, _ := auth.ValidateToken(ctx, token2)
}()
```

## Resource Cleanup

Always close the authenticator to release resources:

```go
auth, err := oauth.NewAuthenticator(config)
if err != nil {
    return err
}
defer auth.Close() // Releases JWKS and cache resources
```

## Performance Considerations

- **JWT validation** is faster than introspection (local vs remote)
- **Caching** significantly reduces latency for repeated validations
- **Hybrid validation** provides best balance of speed and reliability
- **Connection pooling** is enabled by default (100 max idle connections)
- **Retry logic** handles transient failures (3 attempts with exponential backoff)

## Testing

The package includes comprehensive tests covering:
- Configuration validation
- Provider implementations
- Token validation
- Caching mechanisms
- Error handling
- Concurrent access

Run unit tests:

```bash
cd pkg/oauth
make test
```

Run integration tests (requires Docker):

```bash
cd pkg/oauth
make integration-test
```

Check coverage:

```bash
cd pkg/oauth
make coverage
```
