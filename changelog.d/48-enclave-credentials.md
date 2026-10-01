### Changed

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

[#48]: https://github.com/jeremyhahn/go-auth/issues/48
