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
- Every credential held in [go-enclave](https://github.com/jeremyhahn/go-enclave)
  locked memory — never a plaintext `string` (see
  [Credentials in locked memory](#credentials-in-locked-memory))

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

bearer, _ := enclave.NewMemoryEnclaveFromString(tokenFromRequest)
defer bearer.Destroy() // ValidateToken borrows it

claims, err := auth.ValidateToken(ctx, bearer)
```

### Client Credentials Flow

```go
clientSecret, _ := enclave.NewMemoryEnclave(secretBytes) // wipes secretBytes

config := &oauth.Config{
    Provider:     oauth.Keycloak("https://keycloak.example.com", "master"),
    Flow:         oauth.FlowClientCredentials,
    ClientID:     "service-account",
    ClientSecret: clientSecret, // owned by the Authenticator; Close destroys it
}

auth, _ := oauth.NewAuthenticator(config)
defer auth.Close()

token, err := auth.AuthenticateClientCredentials(ctx)
defer token.Destroy()
```

### Password Flow

```go
config := &oauth.Config{
    Provider:     oauth.Auth0("myapp.us.auth0.com"),
    Flow:         oauth.FlowPassword,
    ClientID:     "client-id",
    ClientSecret: clientSecret,
}

auth, _ := oauth.NewAuthenticator(config)
password, _ := enclave.NewMemoryEnclave(passwordBytes) // borrowed below
defer password.Destroy()

token, err := auth.AuthenticatePassword(ctx, "user@example.com", password)
defer token.Destroy()
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

// Step 1: Generate auth URL. The code verifier comes back in locked memory
// and is destroyed by the exchange.
authURL, verifier, _ := auth.BuildAuthURLPKCE("state", nil)
defer verifier.Destroy()
// Redirect user to authURL

// Step 2: Exchange code for token
token, err := auth.ExchangeAuthorizationCodePKCE(ctx, code, verifier)
defer token.Destroy()

// Step 3, later: refresh. RefreshToken borrows the old refresh token.
next, err := auth.RefreshToken(ctx, token.RefreshToken())
```

### Using a Token

A `Token` owns its access, refresh and ID tokens in enclaves and lends them
through `AccessToken()`, `RefreshToken()` and `IDToken()`. Read one only inside
`WithBytes`, at your own boundary, and never retain the slice:

```go
err := token.AccessToken().WithBytes(func(access []byte) error {
    req.Header.Set("Authorization", "Bearer "+string(access))
    return nil
})
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
claims, _ := auth.ValidateToken(ctx, bearer)

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
import "github.com/jeremyhahn/go-auth/pkg/oauth"

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

// Seal the bearer token as soon as it is read from the request.
bearer, err := enclave.NewMemoryEnclaveFromString(accessToken)
if err != nil {
    return err
}
defer bearer.Destroy() // ValidateToken borrows it

claims, err := auth.ValidateToken(ctx, bearer)
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
    ClientSecret: clientSecret, // *enclave.MemoryEnclave, owned by the Authenticator
    Scopes:       []string{"api.read", "api.write"},
}

auth, err := oauth.NewAuthenticator(config)
if err != nil {
    log.Fatal(err)
}
defer auth.Close()

token, err := auth.AuthenticateClientCredentials(ctx)
if err != nil {
    log.Fatal(err)
}
defer token.Destroy()

fmt.Printf("Access token: %d bytes, expires %s\n", token.AccessToken().Size(), token.Expiry)
```

### Password Flow

Direct username/password authentication:

```go
config := &oauth.Config{
    Provider:     oauth.Auth0("myapp.us.auth0.com"),
    Flow:         oauth.FlowPassword,
    ClientID:     "client-id",
    ClientSecret: clientSecret,
    Scopes:       []string{"openid", "profile", "email"},
}

auth, err := oauth.NewAuthenticator(config)
if err != nil {
    log.Fatal(err)
}
defer auth.Close()

password, err := enclave.NewMemoryEnclave(passwordBytes) // wipes passwordBytes
if err != nil {
    log.Fatal(err)
}
defer password.Destroy() // AuthenticatePassword borrows it

token, err := auth.AuthenticatePassword(ctx, "user@example.com", password)
if err != nil {
    log.Fatal(err)
}
defer token.Destroy()

fmt.Printf("ID token issued: %v\n", token.IDToken().IsAlive())
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
authURL, verifier, err := auth.BuildAuthURLPKCE(state, nil)
if err != nil {
    log.Fatal(err)
}
defer verifier.Destroy() // no-op once the exchange has consumed it

// Redirect user to authURL, keeping the verifier against the state...

// After receiving callback with authorization code:
token, err := auth.ExchangeAuthorizationCodePKCE(ctx, code, verifier)
if err != nil {
    log.Fatal(err)
}
defer token.Destroy()
```

Without PKCE, `BuildAuthURL(state, params)` and
`ExchangeAuthorizationCode(ctx, code)` are the same flow with no verifier. The
authorization code stays a `string`: it arrives in the redirect's query string,
which `net/http` has already parsed, and is redeemable exactly once.

### The code verifier is a credential

A PKCE code verifier is a bearer secret for the length of the flow: whoever
holds it can redeem an intercepted authorization code, which is the whole attack
PKCE exists to stop. `BuildAuthURLPKCE` generates it inside a go-enclave
`MemoryEnclave` and derives the S256 challenge from there,
so it has no plaintext form on the Go heap; `ExchangeAuthorizationCodePKCE`
copies it into a locked request body and destroys it, since RFC 7636 gives a
verifier exactly one authorization code to redeem.

The verifier is an `oauth.Verifier`, and it never yields its value by return.
Single use is enforced rather than documented: the exchange takes the sealed
value out under a lock before it opens or sends anything, so two goroutines
racing on one login cannot both reach the token endpoint — the loser gets
`ErrVerifierConsumed`.

An enclave is process memory and cannot be written to an out-of-process session
store, and nothing exported reads a `Verifier`'s value back out — a Go string
cannot be wiped, so an escape hatch that produced one would undo what the
enclave is for. Hold the `Verifier` in an in-process map keyed by `state`.

An application that keeps its own sealed copy of a verifier — restored into
locked memory from an encrypted session store, say — wraps it with
`oauth.NewVerifier(enclave)`, which takes ownership of the enclave: the
verifier goes in, nothing comes back out.

`additionalParams` may not set a parameter the library owns — `client_id`,
`redirect_uri`, `response_type`, `state`, `scope`, `code_challenge` or
`code_challenge_method`. Silently overriding `code_challenge` would hand back a
verifier that does not match the URL, and the flow would then fail at the token
endpoint with nothing pointing at the cause. Those keys are rejected.

### Credentials in locked memory

Every OAuth credential the package handles lives in a go-enclave
`*enclave.MemoryEnclave`, never in a plaintext `string` ([#47], owner ruling on
[#3]).

| Credential | Where it lives | Owner |
|---|---|---|
| Client secret | `Config.ClientSecret` | The `Authenticator`: `NewAuthenticator` takes it on every return path (it destroys it itself on error), `Close` destroys it |
| Access / refresh / ID token | `Token.AccessToken()`, `RefreshToken()`, `IDToken()` | The `Token`: `Token.Destroy` wipes all three |
| Bearer token being validated | argument to `ValidateToken`, `ValidateIDToken`, `GetUserInfo` | The caller: these methods borrow it |
| Password, refresh token sent | argument to `AuthenticatePassword`, `RefreshToken` | The caller: these methods borrow it |
| PKCE code verifier | `oauth.Verifier` | The `Verifier`; the exchange consumes it. `NewVerifier` takes ownership of the enclave it is given |
| Validated-claims cache | LRU entries, keyed by the token's SHA-256 fingerprint | The cache: destroyed on eviction, expiry, overwrite, `ClearCache` and `Close` |
| UserInfo cache | entries keyed by the access token's SHA-256 fingerprint | The `Authenticator`: bounded by `UserInfoConfig.CacheMaxSize`; destroyed on eviction, expiry, overwrite, `ClearUserInfoCache` and `Close` |

Failing to lock memory is never papered over: `enclave.ErrLockedMemoryUnavailable`
propagates (wrapped, matchable with `errors.Is`), and nothing falls back to
ordinary memory — a claims or UserInfo response that cannot be sealed fails the
call instead of being cached in the clear. Expired cache entries are reclaimed
before a new one is allocated, so dead entries cannot exhaust a locked-memory
budget; both caches are bounded (`CacheConfig.MaxSize` for claims,
`UserInfoConfig.CacheMaxSize`, default 1000, for UserInfo), evict their
least-recently-used entry for capacity before allocating, and on a
locked-memory refusal evict one more entry and retry once before failing
closed; and once `Close` has run both caches refuse inserts with
`ErrCacheClosed`, so a request in flight across `Close` cannot leave an enclave
behind.

A credential is opened only where a dependency forces it, and each such site is
marked in the source:

- **R5 — `net/http` / `crypto/tls`** ([#3] residue register). Form bodies
  (client secret, password, refresh token, PKCE verifier, introspected token)
  are assembled in a locked scratch enclave, and token responses are decoded
  straight into enclaves without passing through a `string`. What remains is
  the transport's own copies of request and response bytes, the
  `Authorization` header for introspection (Basic) and UserInfo (Bearer), which
  `net/http` carries only as a string, and the copy `io.ReadAll` makes of the
  response (wiped once the tokens are sealed out of it).
- **JWT parse boundary.** golang-jwt parses only from a `string`, so a token
  validated as a JWT (`ValidateToken`, `ValidateIDToken`) is copied into one
  for the parse.
- **`pkg/api` adapter.** `Authenticator.Authenticate(ctx, username string,
  token *enclave.MemoryEnclave)` borrows the bearer token `api.LoginRequest`
  carries in an enclave and validates it with `ValidateToken`; no string
  boundary remains ([#48]).

Every site is listed in the
[credential residue register](security/credential-residues.md) and gated by
CI.

[#3]: https://github.com/jeremyhahn/go-auth/issues/3
[#47]: https://github.com/jeremyhahn/go-auth/issues/47
[#48]: https://github.com/jeremyhahn/go-auth/issues/48

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

Enable in-memory caching to reduce latency and provider load. Validated claims
are held JSON-encoded in an enclave, keyed by the token's SHA-256 fingerprint
(never the token), and destroyed on eviction, expiry, overwrite, `ClearCache`
and `Close`:

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
    "github.com/jeremyhahn/go-auth/pkg/api"
    "github.com/jeremyhahn/go-auth/pkg/oauth"
)

oauthAuth, _ := oauth.NewAuthenticator(config)
defer oauthAuth.Close()

service, _ := api.NewService(api.Config{
    Backends: []api.Backend{
        {Name: api.BackendOAuth, Handler: api.OAuth(oauthAuth)},
    },
})

// The bearer token goes in the Password field, as an enclave. Login takes
// ownership of the request's enclaves and destroys them when the attempt
// completes, so hand it a copy rather than an enclave a Token still owns.
err := service.Login(ctx, api.LoginRequest{
    Backend:  api.BackendOAuth,
    Username: "oauth-user", // required by Login, ignored by OAuth
    Password: bearer,       // *enclave.MemoryEnclave holding the token
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
- `ClientSecret` (a live `*enclave.MemoryEnclave`)

**FlowPassword:**
- `ClientSecret` (a live `*enclave.MemoryEnclave`)

**FlowAuthorizationCode:**
- `ClientSecret` (optional for public clients; nil for none)
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
claims, err := auth.ValidateToken(ctx, bearer)
if err != nil {
    switch {
    case errors.Is(err, oauth.ErrMissingToken):
        // No token provided, or the enclave was nil or destroyed
    case errors.Is(err, oauth.ErrInvalidToken):
        // Token is invalid or malformed
    case errors.Is(err, oauth.ErrExpiredToken):
        // Token has expired
    case errors.Is(err, oauth.ErrInvalidConfiguration):
        // Configuration error
    case errors.Is(err, enclave.ErrLockedMemoryUnavailable):
        // The process could not lock memory for a credential; fail closed
    default:
        // Other error
    }
}
```

## Security Best Practices

1. **Always use TLS in production** - Enabled by default
2. **Use PKCE for authorization code flow** - Prevents code interception; take the verifier from `BuildAuthURLPKCE`, which keeps it in protected memory
3. **Validate issuer and audience claims** - Prevents token misuse
4. **Set appropriate clock skew** - Accounts for time drift (default: 60s)
5. **Never log secrets or tokens** - Prevents credential leakage; copy one out of its enclave only inside `WithBytes`, and never retain the copy
6. **Use state parameter** - Prevents CSRF attacks in auth code flow
7. **Rotate client secrets regularly** - Limits exposure window
8. **Enable caching judiciously** - Balance security and performance

### Security Checklist

- [ ] Use TLS in production (enabled by default)
- [ ] Validate issuer claim
- [ ] Validate audience claim
- [ ] Use PKCE for authorization code flow (`BuildAuthURLPKCE` / `ExchangeAuthorizationCodePKCE`)
- [ ] Set appropriate clock skew tolerance
- [ ] Never log tokens or secrets
- [ ] Use state parameter for CSRF protection
- [ ] Enable caching for performance
- [ ] Set proper timeout values
- [ ] Close authenticator when done (destroys the client secret and the caches)
- [ ] `Destroy` every `Token` when done

## Thread Safety

The `Authenticator` is thread-safe and can be used concurrently across multiple goroutines. It is immutable after construction.

```go
auth, _ := oauth.NewAuthenticator(config)
defer auth.Close()

// Safe to use from multiple goroutines
go func() {
    claims, _ := auth.ValidateToken(ctx, bearer1)
}()

go func() {
    claims, _ := auth.ValidateToken(ctx, bearer2)
}()
```

## Resource Cleanup

Always close the authenticator to release resources:

```go
auth, err := oauth.NewAuthenticator(config)
if err != nil {
    return err
}
defer auth.Close() // Releases JWKS and cache resources; destroys the client secret
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
