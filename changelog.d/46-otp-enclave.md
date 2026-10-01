### Changed

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

[#46]: https://github.com/jeremyhahn/go-auth/issues/46
