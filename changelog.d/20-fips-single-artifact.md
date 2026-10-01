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

- `pkg/tacacs`: `NewAuthenticator` and `NewAuthenticatorWithSecret` return the
  new typed `tacacs.ErrFIPSUnsupported` when FIPS is activated, ahead of every
  argument check and before the shared secret is sealed or locked, and
  `Authenticate` returns it before building a packet ([#20]). RFC 8907 §4.5
  obfuscates every packet body with an MD5 keystream, so without the refusal a
  FIPS-activated process panicked inside `crypto/md5` on the first login. Same
  shape as `radius.ErrFIPSUnsupported`.
- `pkg/yubikey`: new typed `yubikey.ErrFIPSUnsupported` ([#20]). Under FIPS
  activation `NewAuthenticator` returns it — ahead of the configuration checks
  — when the validator it would use is the YubiCloud `HTTPValidator`, passed
  explicitly or as the package default, and `HTTPValidator.Validate` /
  `ValidateProtected` return it before any request is built. Yubico
  Validation Protocol 2.0 signs with HMAC-SHA-1. An injected `OTPValidator`
  for an approved service keeps working under FIPS activation.
- CI's `fips` job no longer passes `-tags fips140only` ([#20]). It builds and
  tests the whole module under `GOFIPS140=latest` and `GODEBUG=fips140=only`,
  so it proves every backend either works or refuses with its typed error.

[#20]: https://github.com/jeremyhahn/go-auth/issues/20
