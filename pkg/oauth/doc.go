// Package oauth provides OAuth 2.0 and OpenID Connect (OIDC) authentication.
//
// The package supports multiple OAuth 2.0 flows and token validation methods,
// with pre-configured providers for common identity services.
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
//	claims, err := auth.ValidateToken(context.Background(), accessToken)
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
//	config := &oauth.Config{
//	    Provider:     oauth.Keycloak("https://keycloak.example.com", "master"),
//	    Flow:         oauth.FlowClientCredentials,
//	    ClientID:     "service-account",
//	    ClientSecret: "secret",
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
//
//	fmt.Printf("Access Token: %s\n", token.AccessToken)
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
//	    ClientSecret: "client-secret",
//	    Scopes:       []string{"openid", "profile", "email"},
//	}
//
//	auth, err := oauth.NewAuthenticator(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	token, err := auth.AuthenticatePassword(context.Background(), "user@example.com", "password")
//	if err != nil {
//	    log.Printf("Authentication failed: %v", err)
//	    return
//	}
//
//	fmt.Printf("Access Token: %s\n", token.AccessToken)
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
//	// Generate authorization URL
//	state := generateRandomState() // Your CSRF token
//	authURL, codeVerifier, err := auth.BuildAuthURL(state, true, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Redirect user to authURL...
//	// After callback with authorization code:
//
//	token, err := auth.ExchangeAuthorizationCode(context.Background(), code, codeVerifier)
//	if err != nil {
//	    log.Printf("Token exchange failed: %v", err)
//	    return
//	}
//
//	fmt.Printf("Access Token: %s\n", token.AccessToken)
//	fmt.Printf("ID Token: %s\n", token.IDToken)
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
// This reduces latency and load on the OAuth provider:
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
//   - Never log client secrets or tokens
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
