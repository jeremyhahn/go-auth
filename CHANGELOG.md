# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
the release versioning of the company conventions (`release-versioning.md`).

## [Unreleased]

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

- `otp.Config.Skew` is now rejected above 10 time steps, on both the protected
  and the deprecated string path. A wider window keeps every code valid for
  longer and costs an HMAC per step (RFC 6238 §5.2 asks for the smallest window
  a deployment can tolerate); the protected path's validation loop is also
  bounded so no configuration can make it iterate indefinitely.

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

Not yet covered, and tracked by the repository-wide protected-memory audit:
`pkg/oauth` (`ClientSecret`, token cache), `pkg/api` (`LoginRequest.Password`)
and the `pkg/pam` cgo boundary.

## [0.1.1-alpha]

Released before this changelog was started; see the git history.
