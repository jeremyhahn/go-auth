// Package oauth provides OAuth 2.0 and OpenID Connect (OIDC) authentication.
//
// The package supports multiple OAuth 2.0 flows and token validation methods,
// with pre-configured providers for common identity services.
//
// # Credentials in Locked Memory
//
// Every OAuth credential this package handles lives in a go-enclave
// *enclave.MemoryEnclave, never in a plaintext string: the client secret
// (Config.ClientSecret), the access, refresh and ID tokens of a Token, a bearer
// token passed to ValidateToken, a password passed to AuthenticatePassword, the
// PKCE code verifier, and the validated-claims and UserInfo caches.
//
// Ownership is explicit:
//
//   - NewAuthenticator takes ownership of Config.ClientSecret on every return
//     path; Close destroys it.
//   - A Token owns its enclaves; the accessors lend them, and Token.Destroy
//     wipes them.
//   - Every method that takes a token or password enclave as an argument
//     (ValidateToken, AuthenticatePassword, RefreshToken, ValidateIDToken,
//     GetUserInfo) borrows it and never destroys it.
//   - NewVerifier takes ownership of the enclave it is given; the exchange
//     consumes the Verifier.
//
// A credential is opened only where a dependency forces it, and each such site
// is marked in the source: request bodies are assembled in locked pages and
// token responses are decoded straight into enclaves, leaving only the copies
// net/http and crypto/tls make internally (residue R5, go-auth#3); and
// golang-jwt parses a token only from a string, so a token being validated as a
// JWT is copied into one for the parse.
//
// # Supported Flows
//
//   - Token Validation: Validate existing access tokens (JWT or introspection)
//   - Client Credentials: Machine-to-machine authentication
//   - Resource Owner Password: Direct username/password authentication
//   - Authorization Code: User-interactive flow with PKCE support
//
// # Token Validation
//
// Tokens can be validated using JWT (local validation with JWKS) or
// OAuth introspection (remote validation). Hybrid mode tries JWT first
// and falls back to introspection.
//
// Example - Token Validation:
//
//	config := &oauth.Config{
//	    Provider: oauth.Google(),
//	    Flow:     oauth.FlowTokenValidation,
//	    ClientID: "your-client-id",
//	    Validation: oauth.TokenValidationConfig{
//	        Method:   oauth.ValidationJWT,
//	        JWKSURL:  "https://www.googleapis.com/oauth2/v3/certs",
//	        Issuer:   "https://accounts.google.com",
//	        Audience: "your-client-id",
//	    },
//	    Cache: oauth.CacheConfig{
//	        Enabled: true,
//	        MaxSize: 1000,
//	        TTL:     5 * time.Minute,
//	    },
//	}
//
//	auth, err := oauth.NewAuthenticator(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer auth.Close()
//
//	// Seal the bearer token as soon as it is read from the request.
//	bearer, err := enclave.NewMemoryEnclave([]byte(accessToken))
//	if err != nil {
//	    return err
//	}
//	defer bearer.Destroy()
//
//	claims, err := auth.ValidateToken(context.Background(), bearer)
//	if err != nil {
//	    log.Printf("Token validation failed: %v", err)
//	    return
//	}
//
//	fmt.Printf("User: %s (%s)\n", claims.Name, claims.Email)
//
// # Client Credentials Flow
//
// Example - Client Credentials:
//
//	clientSecret, err := enclave.NewMemoryEnclave(secretBytes) // wipes secretBytes
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	config := &oauth.Config{
//	    Provider:     oauth.Keycloak("https://keycloak.example.com", "master"),
//	    Flow:         oauth.FlowClientCredentials,
//	    ClientID:     "service-account",
//	    ClientSecret: clientSecret, // owned by the Authenticator from here on
//	    Scopes:       []string{"api.read", "api.write"},
//	}
//
//	auth, err := oauth.NewAuthenticator(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	token, err := auth.AuthenticateClientCredentials(context.Background())
//	if err != nil {
//	    log.Printf("Authentication failed: %v", err)
//	    return
//	}
//	defer token.Destroy()
//
//	err = token.AccessToken().WithBytes(func(access []byte) error {
//	    return callAPI(access) // valid only inside the borrow
//	})
//	fmt.Printf("Expires: %s\n", token.Expiry)
//
// # Password Flow
//
// Example - Resource Owner Password:
//
//	config := &oauth.Config{
//	    Provider:     oauth.Auth0("myapp.us.auth0.com"),
//	    Flow:         oauth.FlowPassword,
//	    ClientID:     "client-id",
//	    ClientSecret: clientSecret,
//	    Scopes:       []string{"openid", "profile", "email"},
//	}
//
//	auth, err := oauth.NewAuthenticator(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	password, err := enclave.NewMemoryEnclave(passwordBytes) // wipes passwordBytes
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer password.Destroy() // borrowed by AuthenticatePassword
//
//	token, err := auth.AuthenticatePassword(context.Background(), "user@example.com", password)
//	if err != nil {
//	    log.Printf("Authentication failed: %v", err)
//	    return
//	}
//	defer token.Destroy()
//
// # Authorization Code Flow
//
// Example - Authorization Code with PKCE:
//
//	config := &oauth.Config{
//	    Provider:    oauth.Microsoft(),
//	    Flow:        oauth.FlowAuthorizationCode,
//	    ClientID:    "client-id",
//	    RedirectURL: "http://localhost:8080/callback",
//	    Scopes:      []string{"openid", "profile", "email"},
//	}
//
//	auth, err := oauth.NewAuthenticator(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Generate authorization URL. The PKCE code verifier comes back in
//	// protected memory: it is a bearer credential for the length of the flow,
//	// since whoever holds it can redeem an intercepted authorization code.
//	state := generateRandomState() // Your CSRF token
//	authURL, verifier, err := auth.BuildAuthURLPKCE(state, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer verifier.Destroy() // no-op once the exchange has consumed it
//
//	// Redirect user to authURL and keep the verifier against the state...
//	// After callback with authorization code:
//
//	token, err := auth.ExchangeAuthorizationCodePKCE(context.Background(), code, verifier)
//	if err != nil {
//	    log.Printf("Token exchange failed: %v", err)
//	    return
//	}
//	defer token.Destroy()
//
//	// Later: refresh with the borrowed refresh token, then drop the old Token.
//	next, err := auth.RefreshToken(ctx, token.RefreshToken())
//
// # Pre-configured Providers
//
// The package includes pre-configured providers for:
//   - Google() - Google OAuth
//   - Microsoft() - Microsoft Azure AD
//   - GitHub() - GitHub OAuth
//   - Okta(domain) - Okta
//   - Auth0(domain) - Auth0
//   - Keycloak(baseURL, realm) - Keycloak
//
// # Custom Providers
//
// For custom OAuth providers, use CustomProvider:
//
//	provider, err := oauth.CustomProvider(oauth.ProviderConfig{
//	    ProviderName:          "custom",
//	    AuthEndpoint:          "https://provider.com/oauth/authorize",
//	    TokenEndpoint:         "https://provider.com/oauth/token",
//	    JWKSEndpoint:          "https://provider.com/oauth/jwks",
//	    IntrospectionEndpoint: "https://provider.com/oauth/introspect",
//	    IssuerURL:             "https://provider.com",
//	})
//
// # Token Caching
//
// The package includes an in-memory LRU cache for validated token claims.
// This reduces latency and load on the OAuth provider. Entries are keyed by the
// token's SHA-256 fingerprint, hold the claims in an enclave, and are destroyed
// on eviction, expiry, overwrite, ClearCache and Close:
//
//	Cache: oauth.CacheConfig{
//	    Enabled: true,
//	    MaxSize: 1000,        // Maximum cached tokens
//	    TTL:     5 * time.Minute, // Cache duration
//	}
//
// # Thread Safety
//
// The Authenticator is thread-safe and can be used concurrently.
// It is immutable after construction and safe to share across goroutines.
//
// # Security Considerations
//
//   - Always use TLS in production (enabled by default)
//   - Use PKCE for authorization code flow
//   - Validate issuer and audience claims
//   - Set appropriate clock skew tolerance
//   - Never log client secrets or tokens; copy one out of its enclave only
//     inside WithBytes, at your own boundary, and never retain the copy
//   - Use state parameter for CSRF protection
//
// # Integration with go-auth API
//
// The Authenticator implements the passwordAuthenticator interface
// and can be used with the api package:
//
//	import "github.com/jeremyhahn/go-auth/pkg/api"
//
//	oauthAuth, _ := oauth.NewAuthenticator(config)
//	service, _ := api.NewService(api.Config{
//	    Backends: []api.Backend{
//	        {Name: api.BackendOAuth, Handler: api.OAuth(oauthAuth)},
//	    },
//	})
package oauth
