# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
the release versioning of the company conventions (`release-versioning.md`).

## [Unreleased]

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
