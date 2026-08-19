# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
the release versioning of the company conventions (`release-versioning.md`).

## [Unreleased]

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
