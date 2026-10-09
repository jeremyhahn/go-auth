# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
the release versioning of the company conventions (`release-versioning.md`).

## [Unreleased]

## [0.5.1-alpha] - 2026-10-09

### Changed

- `make lint` runs actionlint over `.github/workflows/` ([#66]), so workflow
  syntax, expressions and runner labels are checked before CI reads them. The
  new `actionlint` target fails when actionlint or shellcheck is absent:
  without shellcheck actionlint silently disables its `run:` script checks.
  CI's lint job installs actionlint and a pinned, checksum-verified shellcheck
  (`scripts/install-shellcheck.sh`) before `make lint`.
- `make trivy-fs`, and with it `make security`, now fails with an install
  hint when trivy is not on PATH instead of skipping with exit 0. With trivy
  present the scan is unchanged: `vuln,secret` scanners, CRITICAL/HIGH,
  exit code 1.

[#66]: https://github.com/jeremyhahn/go-auth/issues/66

## [0.5.0-alpha] - 2026-10-08

### Changed

- CI tool pins move to the upstream latest, in step with the ci-runner image:
  golangci-lint `v2.13.2` → `v2.14.0` (govulncheck `v1.8.0`, gosec `v2.29.0`
  and Go `1.27.1` are the baked versions) ([#60]).
- go-enclave `v0.6.1-alpha` → `v0.8.0-alpha` ([#62], owner ruling 2026-10-07).
  Every caller of a removed or changed go-enclave API is migrated:
  `NewMemoryEnclaveFromString(s)` → `NewMemoryEnclave([]byte(s))`,
  `OpenString()` → a copy taken inside `WithBytes`, `DestroyErr()` → `Destroy()`,
  `EqualTo` now returns `(bool, error)`, and a `Destroy` error is returned or
  joined to the caller's error instead of being dropped. A `Destroy` that fails
  is reported by `api.Service.Login`, the constructors that take ownership of a
  credential, and every `Close`. Nothing else changes for users of this library
  beyond the two signatures below.
- **BREAKING (source-compatible for callers that ignore the result):**
  `oauth.Token.Destroy` and `oauth.Verifier.Destroy` return `error`, as
  go-enclave's `Destroy` does; it joins the failures of the credentials the
  value holds. `oauth.Authenticator.Close` also reports a failed `Destroy` of a
  cached entry.
- The credential-residue scan in `test/ci` no longer counts `Open` and
  `OpenString`, which go-enclave removed; `WithBytes` is the one plaintext
  method left.

## [0.4.0-alpha] - 2026-10-01

### Changed

- **BREAKING — the `fips140only` build tag no longer exists for RADIUS,
  TACACS+, the YubiCloud validator or `pkg/api` ([#20]).** FIPS boundary
  ruling 1 mandates one FIPS-capable artifact: build with `GOFIPS140=latest`
  and activate FIPS at deployment with `GODEBUG=fips140=only`. `pkg/radius`,
  `pkg/tacacs`, the YubiCloud `HTTPValidator` and the RADIUS/TACACS+ assertions
  in `pkg/api` are now in every build. Anyone building with
  `-tags fips140only` gets these packages linked in, and must handle the
  runtime refusal below instead of relying on their absence.

  | Before | After |
  |---|---|
  | `go build -tags fips140only ./...` removed RADIUS/TACACS+ | `GOFIPS140=latest go build ./...`; constructors return `ErrFIPSUnsupported` under `GODEBUG=fips140=only` |
  | `yubikey.NewAuthenticator(cfg, nil)` → `errSystemValidatorUnavailable` under the tag | → `yubikey.ErrFIPSUnsupported` under FIPS activation; the YubiCloud default is always installed by `init()` |
  | absence of `pkg/radius` / `pkg/tacacs` at link time | `errors.Is(err, radius.ErrFIPSUnsupported)` / `errors.Is(err, tacacs.ErrFIPSUnsupported)` at startup |

- `pkg/tacacs`: `NewAuthenticator` returns the
  new typed `tacacs.ErrFIPSUnsupported` when FIPS is activated, ahead of every
  argument check and before the shared secret is sealed or locked, and
  `Authenticate` returns it before building a packet ([#20]). RFC 8907 §4.5
  obfuscates every packet body with an MD5 keystream, so without the refusal a
  FIPS-activated process panicked inside `crypto/md5` on the first login. Same
  shape as `radius.ErrFIPSUnsupported`.
- `pkg/yubikey`: new typed `yubikey.ErrFIPSUnsupported` ([#20]). Under FIPS
  activation `NewAuthenticator` returns it — ahead of the configuration checks
  — when the validator it would use is the YubiCloud `HTTPValidator`, passed
  explicitly or as the package default, and `HTTPValidator.Validate`
  returns it before any request is built. Yubico
  Validation Protocol 2.0 signs with HMAC-SHA-1. An injected `OTPValidator`
  for an approved service keeps working under FIPS activation.
- CI's `fips` job no longer passes `-tags fips140only` ([#20]). It builds and
  tests the whole module under `GOFIPS140=latest` and `GODEBUG=fips140=only`,
  so it proves every backend either works or refuses with its typed error.
- **BREAKING:** `pkg/otp`: the OTP seed lives only in a go-enclave
  `*enclave.MemoryEnclave`, as `Config.Seed` ([#46], owner ruling go-auth#3,
  2026-10-01). The plaintext `Config.Secret string` path is removed outright, as
  is `Config.SecretKey *secret.Secret`; `pkg/otp` no longer imports
  `pkg/secret`.
- **BREAKING:** `pkg/otp`: `NewAuthenticator` takes ownership of `Config.Seed`
  on every return path — it destroys the seed itself when the configuration is
  refused — and the new `Authenticator.Close` destroys it otherwise. Callers
  must not use or destroy a seed after handing it over, and two authenticators
  over one key need two enclaves.
- **BREAKING:** `pkg/otp`: `GenerateSecret` (string), `NewProtectedSecret` and
  the deprecated `GetProvisioningURI` are removed. `DecodeSeed` replaces
  `NewProtectedSecret`; `GenerateProtectedSecret` and `EncodeSecret` keep their
  names and now return / take `*enclave.MemoryEnclave`.
- **BREAKING:** `pkg/otp`: the `fips140only` build tag is gone from the package
  (go-auth#20). FIPS 140-only mode is detected at runtime by probing
  HMAC-SHA-1, as `pkg/radius` does; under it `Config.Algorithm` must be set
  explicitly to SHA-256 or SHA-512 — `NewAuthenticator` refuses SHA-1, an
  omitted algorithm, and seeds under 112 bits with the new typed
  `ErrFIPSUnsupported` (also matching `ErrInvalidConfig`). An omitted
  algorithm is refused rather than defaulted so that activating FIPS cannot
  silently change the digest existing enrollments are validated with. Outside
  FIPS the RFC 6238 default, SHA-1, is unchanged. The same binary serves both
  deployments.
- `pkg/otp`: `Generate` on an HOTP authenticator without a counter now returns
  the sentinel `ErrCounterRequired`.
- `github.com/pquerna/otp` is removed from the module, and
  `github.com/boombuler/barcode` with it. HOTP (RFC 4226) and TOTP (RFC 6238),
  including the `otpauth://` Key URI, are implemented in-repo and checked
  against the RFC 4226 Appendix D and RFC 6238 Appendix B vectors.

Migration (go-quicbaas and other `pkg/otp` consumers):

| Before | After |
|---|---|
| `otp.Config{Secret: base32}` | `seed, err := otp.DecodeSeed(base32)`; `otp.Config{Seed: seed}` |
| `otp.Config{SecretKey: s}` (`*secret.Secret`) | `otp.Config{Seed: seed}` (`*enclave.MemoryEnclave`) |
| `otp.GenerateSecret()` → `string` | `otp.GenerateProtectedSecret()` → `*enclave.MemoryEnclave` |
| `otp.GenerateProtectedSecret()` → `*secret.Secret` | same name → `*enclave.MemoryEnclave` |
| `otp.NewProtectedSecret(base32)` | `otp.DecodeSeed(base32)` |
| `otp.EncodeSecret(*secret.Secret)` | `otp.EncodeSecret(*enclave.MemoryEnclave)` |
| `defer key.Destroy()` after `NewAuthenticator` | `defer auth.Close()` — the authenticator owns the seed |
| `auth.GetProvisioningURI()` → `string` | `auth.ProvisioningURI()` → `(string, error)` |
| `-tags fips140only` build of `pkg/otp` (omitted algorithm → SHA-256) | no tag; activate with `GODEBUG=fips140=only`; set `Algorithm: otp.AlgorithmSHA256` or `AlgorithmSHA512` explicitly; handle `otp.ErrFIPSUnsupported` |
| `otp.Algorithm*`, `otp.TypeTOTP`, `otp.TypeHOTP` | unchanged |
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
- **BREAKING:** one credential type across the library: every password, PIN,
  one-time password, shared secret, service-account password and API key is a
  go-enclave `*enclave.MemoryEnclave` ([#48], owner ruling on go-auth#3,
  2026-10-01). Every plaintext-`string` credential path is removed, with no
  deprecated shims. Usernames, DNs and client IDs stay `string`.
- **BREAKING:** the common authenticator interface is
  `Authenticate(ctx, username string, password *enclave.MemoryEnclave) error`
  in `pkg/pam`, `pkg/ldap`, `pkg/radius`, `pkg/tacacs` and the `pkg/oauth`
  adapter; `pkg/pkcs11`, `pkg/tpm2`, `pkg/yubikey` and `pkg/otp` take their
  single credential as `*enclave.MemoryEnclave`. Per-call credentials are
  **borrowed**: the callee reads them inside `WithBytes` and never destroys
  them. A nil credential fails with the package's typed sentinel; a destroyed
  one fails with that sentinel joined with `enclave.ErrEnclaveDestroyed` ([#48]).
- **BREAKING:** `pkg/api`: `Handler.Authenticate` and `HandlerFunc` take
  `(ctx, username string, password, otp *enclave.MemoryEnclave)`;
  `LoginRequest.Password` and `LoginRequest.OTP` are `*enclave.MemoryEnclave`.
  `Service.Login` **takes ownership** of both and destroys them when the
  attempt completes — on success, on failure and on every refusal
  (`ErrNoBackends`, `ErrMissingCredentials`, `ErrBackendNotFound`, a canceled
  context) ([#48]).
- **BREAKING:** shared and service secrets are enclave-only and **owned** by
  the authenticator: `radius.NewAuthenticator`, `tacacs.NewAuthenticator`,
  `ldapauth.WithServiceAccount` and `yubikey.Config.APIKey` take an
  `*enclave.MemoryEnclave`, the constructor destroys it on every return path
  (including `ErrFIPSUnsupported` and argument refusals), and the new `Close()
  error` on each authenticator destroys it once every in-flight call has
  returned — a YubiCloud response that arrives after `Close` was called is
  still verified with the API key; use after `Close` fails with the package's
  new `ErrClosed` ([#48]).
- **BREAKING:** `pkg/yubikey`: `OTPValidator.Validate` is
  `Validate(ctx, clientID string, apiKey, otp *enclave.MemoryEnclave) error`;
  `ProtectedOTPValidator` and `HTTPValidator.ValidateProtected` are removed
  ([#48]).
- **BREAKING:** collaborator interfaces carry enclaves:
  `pam.Session.Authenticate(ctx, password *enclave.MemoryEnclave)`,
  `pkcs11.Session.Login(ctx, pin *enclave.MemoryEnclave)`, and
  `tpm2.TPMSession.Unseal(ctx, handle, password *enclave.MemoryEnclave)
  (*enclave.MemoryEnclave, error)` — the unsealed data now comes back in an
  enclave, which `tpm2.Authenticator.Authenticate` destroys before returning,
  on every path ([#48]).
- **BREAKING:** `pkg/secret` is deleted, with `docs/secret.md`. go-enclave is
  the portfolio's single implementation ([#48]); see `docs/credentials.md`.
- `pkg/tacacs` now has a release point for its shared secret. tacplus v0.0.3
  reads `ConnConfig.Secret` only on the goroutine that calls `SendAuthenStart`
  / `Continue`, so the authenticator lends it the locked pages for one
  `Authenticate` and `Close` destroys them; the never-released locked copy is
  gone ([#48]).
- New typed sentinels replace ad-hoc errors on the touched paths:
  `ldapauth.ErrEmptyURL`, `ErrMissingCredentials`, `ErrServicePasswordRequired`,
  `ErrClosed`; `radius.ErrEmptyAddress`, `ErrMissingSharedSecret`,
  `ErrMissingUsername`, `ErrMissingPassword`, `ErrClosed`; the same five in
  `pkg/tacacs`; `pam.ErrEmptyServiceName`, `ErrMissingUsername`,
  `ErrMissingPassword`; `pkcs11.ErrNilAuthenticator`, `ErrMissingPIN`,
  `ErrMissingModulePath`, `ErrMissingTokenSelector`;
  `yubikey.ErrNilAuthenticator`, `ErrMissingClientID`, `ErrMissingAPIKey`,
  `ErrMissingOTP`, `ErrClosed`, `ErrResponseNonceMismatch`,
  `ErrResponseOTPMismatch`, `ErrResponseSignatureInvalid`; `otp.ErrMissingCode`
  (joined with `ErrInvalidCode`) ([#48]).

Migration:

| Before | After |
|---|---|
| `api.LoginRequest{Password: "pw", OTP: "123456"}` | `api.LoginRequest{Password: pw, OTP: code}` with `*enclave.MemoryEnclave`s; `Login` destroys them — build fresh ones per request |
| `api.HandlerFunc(func(ctx, user, password, otp string) error)` | `api.HandlerFunc(func(ctx context.Context, user string, password, otp *enclave.MemoryEnclave) error)` |
| `pam.(*Authenticator).Authenticate(ctx, user, "pw")` | `Authenticate(ctx, user, pw)` — `pw` borrowed |
| `pam.Session.Authenticate(ctx, password string)` | `Authenticate(ctx, password *enclave.MemoryEnclave)` |
| `ldapauth.WithServiceAccount(dn, "pw")` | `ldapauth.WithServiceAccount(dn, pw)` — the authenticator owns `pw`; `defer auth.Close()` |
| `ldapauth.WithProtectedServiceAccount(dn, *secret.Secret)` | `ldapauth.WithServiceAccount(dn, *enclave.MemoryEnclave)` |
| `ldapauth.(*Authenticator).Authenticate(ctx, user, "pw")` | `Authenticate(ctx, user, pw)` |
| `radius.NewAuthenticator(addr, "secret", opts...)` | `radius.NewAuthenticator(addr, secret, opts...)` with `secret *enclave.MemoryEnclave`, owned; `defer auth.Close()` |
| `radius.NewAuthenticatorWithSecret(addr, *secret.Secret, opts...)` | `radius.NewAuthenticator(addr, *enclave.MemoryEnclave, opts...)` |
| `radius.(*Authenticator).Authenticate(ctx, user, "pw")` | `Authenticate(ctx, user, pw)`; nil `pw` with EAP-TLS |
| `tacacs.NewAuthenticator(addr, "secret", opts...)` | `tacacs.NewAuthenticator(addr, secret, opts...)`, owned; `defer auth.Close()` |
| `tacacs.NewAuthenticatorWithSecret(addr, *secret.Secret, opts...)` | `tacacs.NewAuthenticator(addr, *enclave.MemoryEnclave, opts...)` |
| `tacacs.(*Authenticator).Authenticate(ctx, user, "pw")` | `Authenticate(ctx, user, pw)` |
| `pkcs11.(*Authenticator).Authenticate(ctx, "1234")` | `Authenticate(ctx, pin)` |
| `pkcs11.Session.Login(ctx, pin string)` | `Login(ctx, pin *enclave.MemoryEnclave)` |
| `tpm2.(*Authenticator).Authenticate(ctx, "pw")` | `Authenticate(ctx, pw)` |
| `tpm2.TPMSession.Unseal(ctx, h, password string) ([]byte, error)` | `Unseal(ctx, h, password *enclave.MemoryEnclave) (*enclave.MemoryEnclave, error)` — return `enclave.NewMemoryEnclave(rsp.OutData.Buffer)` |
| `yubikey.Config{APIKey: "key"}` / `Config{ProtectedAPIKey: *secret.Secret}` | `yubikey.Config{APIKey: key}` with `key *enclave.MemoryEnclave`, owned; `defer auth.Close()` |
| `yubikey.OTPValidator.Validate(ctx, clientID, apiKey, otp string)` | `Validate(ctx, clientID string, apiKey, otp *enclave.MemoryEnclave)` |
| `yubikey.ProtectedOTPValidator`, `HTTPValidator.ValidateProtected` | removed — `OTPValidator` / `HTTPValidator.Validate` |
| `yubikey.(*Authenticator).Authenticate(ctx, "otp")` | `Authenticate(ctx, otp)` |
| `otp.(*Authenticator).Authenticate(ctx, "123456")` | `Authenticate(ctx, code)` |
| `otp.(*Authenticator).ValidateCounter(ctx, "123456", n)` | `ValidateCounter(ctx, code, n)` |
| `oauth.(*Authenticator).Authenticate(ctx, user, token string)` | `Authenticate(ctx, user string, token *enclave.MemoryEnclave)` |
| `secret.New(b)` / `secret.NewString(s)` / `secret.NewRandom(n)` | `enclave.NewMemoryEnclave(b)` / `enclave.NewMemoryEnclaveFromString(s)` / `enclave.NewMemoryEnclaveSized(n)` filled inside `WithBytes`, then `Freeze` |
| `(*secret.Secret).Open(fn)` / `OpenString(fn)` | `(*enclave.MemoryEnclave).WithBytes(fn)` |
| `secret.Scratch(n, fn)` | `enclave.NewMemoryEnclaveSized(n)` + `WithBytes` + `Destroy` |
| `(*secret.Secret).Lock()` / `secret.Locked` | removed — no remaining user |
| `secret.ErrDestroyed` | `enclave.ErrEnclaveDestroyed` |

### Security

- `pkg/otp`: the OTP seed now has no plaintext form outside locked memory for
  its whole lifetime. It is generated or decoded straight into locked pages,
  borrowed through `WithBytes` for exactly one HMAC per code, and wiped by
  `Close`. Codes are compared in constant time, and a TOTP check evaluates
  every step in its window. The remaining residues are the documented ones:
  `ProvisioningURI` and `EncodeSecret` return the seed as a string because QR
  rendering and storage need it, and `DecodeSeed`'s input is a string the
  caller already holds ([#46]).
- `pkg/otp`: a FIPS-activated process can no longer be made to panic in
  `crypto/hmac` by an OTP configuration. SHA-1, an omitted algorithm and short
  seeds are refused at construction, and the derivation re-checks before every
  HMAC ([#46]).
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
- No credential in go-auth is a plaintext Go `string` any more ([#48]). The
  places where a third-party API still forces plaintext out of locked memory
  are finite and enumerated in `docs/security/credential-residues.md` (R1
  go-ldap bind, R2 layeh MD5/HMAC-MD5 state, R3 tacplus, R5 `net/http` /
  `crypto/tls` / golang-jwt, R6 msteinert/pam and miekg/pkcs11 cgo copies, R7
  configuration origin, R8 OTP enrollment text and codes; R4 closed by #46).
  Where a dependency demands a `string`, go-auth lends one backed by a buffer
  it zeroes as soon as the dependency returns, instead of an immutable copy.
- CI gate: `test/ci/credential_residue_test.go` enumerates every
  `WithBytes` / `OpenString` / `Open` call and every
  `credential.WithTransientString` call in `pkg/` — cgo files included — and
  fails on any site not listed in `test/ci/testdata/credential-residues.allow`
  with a residue ID, or listed but gone ([#48]).
- RADIUS PAP passwords are obfuscated straight out of their borrow
  (`rfc2865.UserPassword_Set`); no plaintext copy of the password is made.
- TPM 2.0 unsealed material no longer reaches the garbage-collected heap
  through go-auth: it comes back in an enclave and is destroyed before
  `Authenticate` returns ([#48]).
- `MemoryEnclave` is locked-only (mlock, guard pages, canary, wipe — no
  cryptography) and fails closed with `enclave.ErrLockedMemoryUnavailable`; no
  path falls back to ordinary memory.

### Fixed

- `pkg/radius`: a RADIUS/TLS exchange cancelled by its caller now always
  returns `context.Canceled` (or the deadline error) instead of sometimes
  `io.EOF` ([#53]). `context` closes a parent's `Done` channel before it
  cancels the children, so a peer that closed the connection in reaction to
  the caller's cancellation could fail the read while the exchange's derived
  context still read as live. The read error is now judged against the
  caller's context. A deterministic regression test reproduces the losing
  order with a parent context that withholds propagation.

[#20]: https://github.com/jeremyhahn/go-auth/issues/20
[#46]: https://github.com/jeremyhahn/go-auth/issues/46
[#47]: https://github.com/jeremyhahn/go-auth/issues/47
[#48]: https://github.com/jeremyhahn/go-auth/issues/48
[#53]: https://github.com/jeremyhahn/go-auth/issues/53

## [0.3.0-alpha] - 2026-10-01

### Changed

- The module's `go` directive is raised from `1.26.7` to `1.27.0`, the
  portfolio toolchain (owner ruling 2026-09-01); consumers now need Go 1.27.
  CI lints with golangci-lint `v2.13.2`, moved in the same change because
  `v2.12.2` cannot lint Go 1.27, and on Gitea it uses the ci-runner image's
  baked golangci-lint, gosec and govulncheck instead of installing over them,
  failing if a tool is absent or golangci-lint is not the pinned version
  ([#26]). The checks are `make verify-lint-tool` and
  `make verify-security-tools` (`scripts/verify-ci-tools.sh`); the pin lives
  in the Makefile, and `test/ci` covers the fail-closed paths and the
  workflow's wiring.
- `pkg/secret`: the protected-memory backing moved from
  [memguard](https://github.com/awnumar/memguard) to
  [go-enclave](https://github.com/jeremyhahn/go-enclave) `v0.3.0-alpha`
  (`MemoryEnclave`), the portfolio's locked-memory primitive. A `Secret` now
  holds one locked, guard-paged region for its whole lifetime and lends it under
  a lock, instead of decrypting into a fresh `mlock`ed buffer on every `Open`.
  A repeated or concurrent `Open` therefore allocates no locked memory, and an
  `RLIMIT_MEMLOCK` exhaustion now returns a typed error matching
  `enclave.ErrLockedMemoryUnavailable` from the constructor instead of purging
  every protected buffer in the process and panicking — closing the login-path
  memlock-exhaustion DoS ([#21]). `Destroy` now wipes and unmaps the region
  rather than dropping the reference. The public constructors, `Open`,
  `OpenString`, `Scratch`, `Lock`, `Size` and the redaction behaviour are
  unchanged, so backends are unaffected.
- The Go toolchain moves to `1.27.1` in one pass: the module's `go`
  directive, `GO_VERSION` in `ci.yml` and `integration.yml`, and every
  integration image under `pkg/` (`FROM golang:1.27.1-bookworm`) ([#43]).
  Consumers now need Go 1.27.1, the portfolio toolchain.
- `pkg/secret`: go-enclave is raised from `v0.3.0-alpha` to `v0.6.1-alpha`
  ([#43]). The `MemoryEnclave` calls this package makes — `NewMemoryEnclave`,
  `NewMemoryEnclaveSized`, `WithBytes`, `Open`, `IsAlive`, `Size` and
  `Destroy` — have the same signatures and the same wipe-on-construct,
  wipe-and-unmap-on-destroy semantics, so `pkg/secret` needed no code change
  and its exported API and behaviour are unchanged. One tightening arrives
  with it: an enclave whose release failed after its material was wiped now
  reports itself destroyed, so `Open` on such a `Secret` returns
  `ErrDestroyed` rather than handing back zeroes.
- Every third-party module is brought to its latest release ([#43]):
  `golang.org/x/crypto` `v0.57.0`, `golang.org/x/sys` `v0.48.0`,
  `golang.org/x/oauth2` `v0.37.0`, `golang.org/x/time` `v0.16.0`,
  `github.com/go-ldap/ldap/v3` `v3.4.14`, `github.com/go-asn1-ber/asn1-ber`
  `v1.5.8`, `github.com/Azure/go-ntlmssp` `v0.1.1`,
  `github.com/MicahParks/keyfunc/v3` `v3.8.2`, `github.com/MicahParks/jwkset`
  `v0.11.3`, `github.com/google/go-tpm-tools` `v0.4.10` and
  `github.com/stretchr/testify` `v1.12.1`.

### Fixed

- CI: the `Integration Suites` leg was red on `main` from `2c0f220` because
  that commit raised the `go` directive to `1.26.7` while all seven
  integration images still built `FROM golang:1.26.6-bookworm`, and those
  images run with `GOTOOLCHAIN=local`, so no Docker-backed suite could build
  the module ([#25]). The Go 1.27.0 move put go.mod, the images and the
  workflow back in step. `test/ci` now fails when any `golang:` base image
  under `pkg/` or `integration.yml`'s `GO_VERSION` differs from the go
  directive, so the per-push gate catches this drift instead of the nightly
  integration run.
- Build: `make release-alpha` is replaced by the handbook's release-alpha
  template v2.3.9, vendored unmodified at `mk/release-alpha.mk` with its
  regression harness ([#22]). The old recipe guessed a patch-only bump,
  created lightweight unsigned tags as the local git identity, pushed every
  local tag to a `dev` remote this repo does not have, and let `|| true` hide
  a failed VERSION commit. A release is now
  `make release-alpha VERSION=vX.Y.Z-alpha`. It runs only on a clean `main`,
  makes every git write through `agent-git.sh` (found on `PATH`) as
  `go-auth`, and pushes the release commit and that one annotated tag to
  `origin`.
- Build: the release now assembles `changelog.d/` fragments
  (release-versioning.md §5). `make release-changelog`, which `release-alpha`
  runs first, folds every fragment and any existing `## [Unreleased]` content
  into a dated `## [X.Y.Z-alpha]` section (`scripts/changelog-assemble.sh`),
  deletes the fragments, and commits that before the tag is cut, so the
  tagged commit carries the entries. It refuses — before any commit — a
  misnamed fragment, a fragment with its own release heading, or fragments
  that would be stranded beside an existing section. `test/ci` runs the real
  Makefile against a throwaway remote, including a signing wrapper that
  rejects each commit, plus the template's own harness.
- CI: the `Integration` workflow is green again ([#42]). Every integration
  image build failed at `RUN go mod download`: `go.mod` requires the private
  `github.com/jeremyhahn/go-enclave`, and `docker build` inherits none of the
  job's private-module configuration. The seven integration images now build
  through `scripts/docker-build-integration.sh`. The script stages `GOPRIVATE`
  and the `GIT_CONFIG_*` rewrite in a 0600 file outside the build context,
  hands it over as the optional BuildKit secret `gomodauth`, and removes it on
  every exit path. Each Dockerfile sources that secret for its single
  `go mod download` only, so the token reaches no layer, no image metadata and
  no command line. Without credentials, the build resolves from the public
  proxy. `test/ci` holds the Dockerfiles, Makefiles and script to this.

### Removed — BREAKING

- **BREAKING — `pkg/secret`: `Purge` and `ErrOpen` are removed, with no
  deprecated shim.** Both were specific to memguard's process-wide session
  purge, which go-enclave does not have and which a library must never trigger.
  A no-op shim keeping the name while dropping the guarantee would be a false
  promise in the API's own vocabulary: a caller who invokes a security function
  and gets silence is worse off than one that fails to compile, because the
  compile error is found once at build time by the person who can fix it, while
  the silent no-op is found after an incident, if ever. So callers of these two
  symbols get a compile error. Verified zero consumers before removal — no
  reference anywhere in go-auth (source or tests) and none in the three in-house
  consumers (go-quicbaas, go-recountly, go-trusted-platform). Ordered shutdown
  wiping, where a program wants it, is go-enclave's `WipeAll` and belongs to the
  process owner, never to this library.

### Security

- The dependency moves clear three advisories govulncheck reported against
  this module ([#43]): GO-2026-5543, a panic on a malformed NTLM challenge in
  `github.com/Azure/go-ntlmssp`, whose package `pkg/ldap` imports through
  go-ldap (fixed in `v0.1.1`); and GO-2026-6354 and GO-2026-6355 in
  `golang.org/x/crypto` `v0.55.0` (fixed by `v0.57.0`). govulncheck found no
  call path to any of them from this module's code.

[#21]: https://github.com/jeremyhahn/go-auth/issues/21
[#25]: https://github.com/jeremyhahn/go-auth/issues/25
[#26]: https://github.com/jeremyhahn/go-auth/issues/26
[#22]: https://github.com/jeremyhahn/go-auth/issues/22
[#42]: https://github.com/jeremyhahn/go-auth/issues/42
[#43]: https://github.com/jeremyhahn/go-auth/issues/43
[#60]: https://github.com/jeremyhahn/go-auth/issues/60
[#62]: https://github.com/jeremyhahn/go-auth/issues/62

## [0.2.0-alpha] - 2026-08-19

### Added

- `pkg/secret`: `Secret.Lock` and `secret.Locked`, for a value a dependency
  keeps and reads from goroutines it does not join: a locked, non-swappable,
  undumpable buffer that stays readable until it is destroyed. Used by
  `pkg/tacacs`.
- `pkg/secret`: credential material — keys, passwords, shared secrets and
  tokens — held in protected memory. A `secret.Secret` is a
  [memguard](https://github.com/awnumar/memguard) enclave: the value is
  encrypted at rest under a session key in locked, non-swappable memory, and is
  decrypted only for the duration of one `Open` call, into a locked buffer that
  is wiped and unmapped before that call returns. See [docs/secret.md](docs/secret.md).
- `pkg/otp`: `Config.SecretKey`, `NewProtectedSecret`, `GenerateProtectedSecret`,
  `EncodeSecret` and `ProvisioningURI`. With `SecretKey` set, codes are derived in this package
  from the opened enclave (RFC 4226 §5.3, RFC 6238 §4.2) instead of by
  `github.com/pquerna/otp`, which takes the secret as a `string` and decodes it
  on every call. Both paths produce identical codes.
- `pkg/radius`: `NewAuthenticatorWithSecret`.
- `pkg/tacacs`: `NewAuthenticatorWithSecret`.
- `pkg/ldap`: `WithProtectedServiceAccount`.
- `pkg/yubikey`: `Config.ProtectedAPIKey` and the `ProtectedOTPValidator`
  interface. `HTTPValidator` implements it and keys HMAC-SHA1 from locked
  scratch memory.
- `pkg/oauth`: `Verifier`, `NewVerifier` and `ErrVerifierConsumed`. A `Verifier`
  is a PKCE code verifier in protected memory, redeemable exactly once: the
  exchange takes the sealed value out under a lock before it opens or sends
  anything, so two goroutines racing on one login cannot both reach the token
  endpoint. Nothing exported reads a `Verifier`'s value back out — a Go string
  cannot be wiped. `NewVerifier` seals a verifier an application already holds,
  so code still on the deprecated string flow can at least redeem it through
  protected memory.
- `pkg/oauth`: `Authenticator.BuildAuthURLPKCE` and
  `Authenticator.ExchangeAuthorizationCodePKCE`, which carry the PKCE code
  verifier in protected memory. The verifier is a bearer credential for the
  length of the flow — whoever holds it can redeem an intercepted authorization
  code — so it is generated inside an enclave, its S256 challenge is derived
  from the enclave, and the exchange copies it into a locked request body. The
  exchange destroys it afterwards: RFC 7636 gives a verifier exactly one
  authorization code to redeem.
- `fips140only` build tag, selecting the subset of this library that can run
  under `GODEBUG=fips140=only`. It excludes the code whose wire protocol
  mandates a non-approved primitive — the RADIUS (MD5, RFC 2865 §3) and
  TACACS+ (MD5, RFC 8907 §4.5) backends, and the YubiCloud validator
  (HMAC-SHA-1, Yubico Validation Protocol 2.0) — so a FIPS build cannot link
  them rather than shipping a backend that panics on first use. Everything the
  tag removes is still built, linted, scanned and tested by the other CI jobs.
  Default builds keep every backend. See [docs/fips.md](docs/fips.md).
- `docs/fips.md`, recording each exemption with the citation that mandates the
  primitive and the scope it covers.

### Fixed

- `pkg/oauth`: the PKCE code verifier was the constant byte sequence
  `0x00 0x01 … 0x1f` — every process and every deployment emitted the verifier
  `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8` and the same `code_challenge`.
  An attacker who intercepted an authorization code already held the verifier,
  so the authorization-code flow had exactly the security of no PKCE. It is now
  read from `crypto/rand`. `BuildAuthURL` returns an error where it previously
  could not fail. (#9)

- `pkg/oauth`: `BuildAuthURL` applied `additionalParams` after the parameters the
  library owns, so a caller could override `code_challenge` — receiving a
  verifier that did not match the authorization URL, and a token exchange that
  could only fail later, at the provider, with nothing pointing at the cause.
  `state`, `client_id`, `redirect_uri`, `response_type` and `scope` were
  overridable the same way. Those keys are now rejected with
  `ErrInvalidConfiguration` rather than applied.

### Changed

- Every backend that holds a long-lived secret now stores it in protected
  memory internally, including on the deprecated string entry points: those
  seal what they are given before doing anything else. No exported signature
  changed, and no consumer needs to change to get this.
- `pkg/tacacs` no longer holds the shared secret as a plaintext `[]byte`, and
  no longer copies it to the heap per authentication: it keeps one
  `secret.Locked` for the authenticator's lifetime and hands `tacplus` that.
  The authenticator owns that copy and there is no safe way to release it while
  `tacplus` can still read it, so it is held for the authenticator's lifetime:
  construct one per server and reuse it.

- CI's FIPS job runs `GODEBUG=fips140=only`, not `fips140=on`. `on` loads the
  Go Cryptographic Module but still permits MD5 and SHA-1, so the gate could
  report green while a regulated path used a prohibited primitive
  (`configuration.md` §5).
- `pkg/otp` fails closed in `fips140only` builds instead of leaving a panic to
  the runtime: `Algorithm: AlgorithmSHA1` and secrets below the 112-bit HMAC
  key floor are rejected by `NewAuthenticator`, and an omitted `Algorithm`
  defaults to SHA-256 rather than SHA-1. `crypto/hmac` panics rather than
  erroring on both under `fips140=only`, so accepting either would turn an
  authentication attempt into a process crash. Default builds are unchanged.
- `pkg/otp` no longer decodes the deprecated `Config.Secret` string onto the
  heap to validate it. It decodes into a `secret.Secret` enclave, reads the
  key's length there and destroys it, so only a bit count leaves. Padding is
  now optional on that path, matching `NewProtectedSecret`; a trailing group
  too short to encode a whole byte is still rejected, which Go's unpadded
  decoder would otherwise drop silently.
- `otp.Config.Skew` is now rejected above 10 time steps, on both the protected
  and the deprecated string path. A wider window keeps every code valid for
  longer and costs an HMAC per step (RFC 6238 §5.2 asks for the smallest window
  a deployment can tolerate); the protected path's validation loop is also
  bounded so no configuration can make it iterate indefinitely.

### Fixed

- `otp.Authenticator.Authenticate` and `ValidateCounter` ignored the configured
  digest and digit count on the string-secret path: both called
  `hotp.Validate`, which hardcodes 6 digits and SHA-1, while `Generate`
  honoured the configuration. An HOTP secret using SHA-256/SHA-512 or 7/8
  digits could therefore never validate a code this package had just generated.
  Both now call `hotp.ValidateCustom` with the configured options.
- `yubikey`'s `init()` installed the YubiCloud validator as the package
  default, so `NewAuthenticator(cfg, nil)` reached HMAC-SHA-1 without the
  caller choosing it. Under `fips140only` no default is installed and
  construction fails fast instead.

### Deprecated

These all still work and are not removed in this release. They are replaced in
the coordinated breaking release, when the whole stack migrates bottom-up.

| Deprecated | Replacement |
|---|---|
| `otp.Config.Secret` | `otp.Config.SecretKey` with `otp.NewProtectedSecret` |
| `otp.GenerateSecret` | `otp.GenerateProtectedSecret` (+ `otp.EncodeSecret` to enroll) |
| `otp.Authenticator.GetProvisioningURI` | `otp.Authenticator.ProvisioningURI`, which reports why it could not build one |
| `radius.NewAuthenticator` | `radius.NewAuthenticatorWithSecret` |
| `tacacs.NewAuthenticator` | `tacacs.NewAuthenticatorWithSecret` |
| `ldap.WithServiceAccount` | `ldap.WithProtectedServiceAccount` |
| `yubikey.Config.APIKey` | `yubikey.Config.ProtectedAPIKey` |
| `yubikey.OTPValidator` | `yubikey.ProtectedOTPValidator` |
| `oauth.Authenticator.BuildAuthURL` with `usePKCE` true | `oauth.Authenticator.BuildAuthURLPKCE` |
| `oauth.Authenticator.ExchangeAuthorizationCode` with a `codeVerifier` | `oauth.Authenticator.ExchangeAuthorizationCodePKCE` |

Both oauth entry points still generate the verifier in protected memory; their
signatures are what force the plaintext string copy back out. Passing `usePKCE`
false, or an empty `codeVerifier`, involves no secret and is not deprecated.

Not yet covered, and tracked by the repository-wide protected-memory audit:
the rest of `pkg/oauth` (`ClientSecret`, token cache), `pkg/api`
(`LoginRequest.Password`) and the `pkg/pam` cgo boundary.

## [0.1.1-alpha]

Released before this changelog was started; see the git history.
