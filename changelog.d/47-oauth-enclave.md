### Changed

- **BREAKING:** `pkg/oauth`: `Config.ClientSecret` is a go-enclave
  `*enclave.MemoryEnclave`; the `string` field is removed ([#47]).
  `NewAuthenticator` takes ownership of it on every return path — it destroys
  the enclave itself before returning an error — and `Authenticator.Close`
  destroys it. Requests made after `Close` fail with the new
  `ErrCredentialUnavailable` instead of going out without the secret.
- **BREAKING:** `pkg/oauth`: `Token.AccessToken`, `Token.RefreshToken` and
  `Token.IDToken` are no longer `string` fields. They are accessor methods
  returning the `*enclave.MemoryEnclave` the `Token` owns (nil when the provider
  issued none), and `Token.Destroy()` wipes all three. `TokenType`, `Expiry`
  and `Scopes` stay plain fields ([#47]).
- **BREAKING:** `pkg/oauth`: every method that took a token or password as a
  `string` takes a borrowed `*enclave.MemoryEnclave` and never destroys it:
  `RefreshToken(ctx, refreshToken)`, `ValidateToken(ctx, token)`,
  `AuthenticatePassword(ctx, username, password)`,
  `ValidateIDToken(ctx, idToken, nonce, accessToken)` and
  `GetUserInfo(ctx, accessToken)` ([#47]).
- **BREAKING:** `pkg/oauth`: the string PKCE path is removed.
  `BuildAuthURL(state, additionalParams)` builds a URL without PKCE and returns
  no verifier; `ExchangeAuthorizationCode(ctx, code)` exchanges without one.
  PKCE is `BuildAuthURLPKCE` / `ExchangeAuthorizationCodePKCE`, unchanged.
  `NewVerifier` takes an `*enclave.MemoryEnclave` (and owns it) instead of a
  `string` ([#47]).
- **BREAKING:** `pkg/oauth`: `TokenCache.Set` returns an `error` — the claims
  could not be sealed into locked memory — and `ValidateToken` fails rather
  than caching them in the clear ([#47]). Both caches are closed for good by
  `Close`: an insert after it — including one from a `ValidateToken` or
  `GetUserInfo` that was in flight across `Close` — allocates nothing and
  fails with the new `ErrCacheClosed`. Expired entries are reclaimed before a
  new entry is allocated, and a read that finds an expired entry destroys it,
  so a locked-memory budget filled with dead entries cannot wedge either cache.
  Both caches also evict their least-recently-used entry for capacity before
  allocating, not after, and if locked memory is still refused they evict one
  more entry and retry once before failing closed, so a budget full of live
  entries does not make `ValidateToken` reject valid tokens.
- `pkg/oauth`: the UserInfo cache is bounded. It was an unbounded map, so it
  could grow locked memory without limit for anyone able to present distinct
  access tokens. New `UserInfoConfig.CacheMaxSize` (default 1000, set by
  `Config.Validate` and `DefaultOIDCConfig`) caps it with LRU eviction. The
  claims cache and the UserInfo cache now share one implementation, so they
  share every lifecycle rule above ([#47]).
- `pkg/oauth` no longer imports `pkg/secret` or `golang.org/x/oauth2`; the
  PKCE verifier is generated with go-enclave directly (`NewMemoryEnclaveSized`
  filled from `crypto/rand` inside `WithBytes`, then frozen), and the unused
  `x/oauth2` config is gone, so the module drops that dependency ([#47]).
  `Authenticator.Authenticate(ctx, username, token string)`, the `pkg/api`
  adapter, keeps its signature and seals the token on arrival.

Migration for a consumer of the client-credentials / authorization-code /
refresh surface (go-recountly `pkg/qbo/oauth.go`):

| Before | After |
|---|---|
| `oauth.Config{ClientSecret: cfg.ClientSecret}` | `secret, err := enclave.NewMemoryEnclaveFromString(cfg.ClientSecret)` (or `enclave.NewMemoryEnclave(b)` from a `[]byte`, which wipes `b`), then `oauth.Config{ClientSecret: secret}` — do not destroy or reuse `secret` afterwards |
| `oauth.NewAuthenticator(cfg)` | unchanged; now owns `cfg.ClientSecret`, also on error |
| `(*oauth.Authenticator).Close()` | unchanged; now also destroys the client secret and both caches |
| `auth.RefreshToken(ctx, refreshToken)` with a `string` | `auth.RefreshToken(ctx, rt)` with `rt *enclave.MemoryEnclave` — pass `tok.RefreshToken()` directly, or seal a stored value with `enclave.NewMemoryEnclaveFromString`; it is borrowed, destroy it yourself |
| `token.AccessToken` (`string`) | `token.AccessToken().WithBytes(func(b []byte) error { … })`; `OpenString()` only at a boundary that demands a string |
| `token.RefreshToken` (`string`) | `token.RefreshToken()` (nil if none issued); read it inside `WithBytes` to persist it |
| `*oauth.Token` | add `defer token.Destroy()` once its credentials are used or copied out |
| `oauth.CustomProvider`, `oauth.ProviderConfig` | unchanged |
| `oauth.FlowAuthorizationCode`, `oauth.FlowClientCredentials` | unchanged |

### Security

- `pkg/oauth` holds no OAuth credential as a plaintext `string` ([#47]): the
  client secret, the access, refresh and ID tokens, a validated bearer token,
  a password, the PKCE verifier, and the validated-claims and UserInfo caches
  all live in go-enclave locked memory. Cache entries are destroyed on
  eviction, expiry, overwrite, `ClearCache` and `Close`; the UserInfo cache is
  now keyed by the access token's SHA-256 fingerprint rather than the token.
  Token request bodies are assembled in a locked scratch enclave and token
  responses are decoded straight into enclaves.
  `enclave.ErrLockedMemoryUnavailable` propagates; nothing falls back to
  ordinary memory. What remains is documented at each site: residue R5
  (`net/http` / `crypto/tls` internal copies, and the Basic and Bearer
  `Authorization` header strings), the golang-jwt parse boundary, and the
  `pkg/api` string boundary that #48 removes.
- `pkg/oauth`: OIDC ID-token validation no longer fails open ([#47]):
  - `at_hash` is checked whenever an access token is supplied. Only a nil
    enclave means "not supplied"; a destroyed one is rejected instead of
    silently skipping the check.
  - An `at_hash` that cannot be checked rejects the token. The error is
    `ErrOIDCInvalidAtHash` joined with the new
    `ErrOIDCUnsupportedAtHashAlgorithm`; the check is never skipped.
  - The `at_hash` hash follows the verified token's JWS `alg`, as OIDC Core
    §3.1.3.6 requires: SHA-256/384/512 for the RS/ES/PS families, SHA-512 for
    EdDSA. Before, SHA-256 was always used, so correct RS384/RS512/ES384/ES512
    tokens were rejected and wrong SHA-256 `at_hash` values on them accepted.
  - ID tokens are parsed with the same asymmetric algorithm allowlist as
    access tokens (one shared list), so `none` and HMAC-signed ID tokens are
    refused (alg confusion).

[#47]: https://github.com/jeremyhahn/go-auth/issues/47
