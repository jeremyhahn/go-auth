# Credential residue register

> **Status: NORMATIVE** · Scope: go-auth · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.

go-auth holds every credential in a go-enclave `*enclave.MemoryEnclave`
([credentials.md](../credentials.md)). This register lists every place where
plaintext must nevertheless leave locked memory because a dependency accepts
it only as a `string`, keeps its own copy, or derives state from it. Owner
ruling on [#3](https://github.com/jeremyhahn/go-auth/issues/3) §10.6:
**accept, document, gate** — fix what go-auth owns, register what third-party
APIs force, and do not fork upstream libraries.

The register is enforced. `test/ci/credential_residue_test.go` enumerates every
`WithBytes` call and every
`credential.WithTransientString` call in `pkg/`, and compares them with
`test/ci/testdata/credential-residues.allow`, where each site carries one of
the IDs below or `internal`. A site that is added or removed without updating
the list fails CI, and every ID the list uses must have a row here.

`internal` means the plaintext is read inside the borrow and stays there or in
the process's own primitive: filling an enclave, a constant-time comparison, a
length check, a SHA-256 fingerprint, the key schedule of an HMAC (`crypto/hmac`
keeps its ipad/opad blocks in the hash state until it is collected; replacing
it would move the construction outside the FIPS 140-3 boundary).

Where a dependency demands a `string`, go-auth lends it one backed by a heap
buffer it zeroes as soon as the dependency returns
(`pkg/internal/credential.WithTransientString`); the bound below is then the
dependency's own copies, not go-auth's.

| ID | file:function | Dependency / cause | Bound (how long plaintext lives) | What would remove it |
|---|---|---|---|---|
| R1 | `pkg/ldap/authenticator.go:Authenticator.Authenticate` (service bind and user bind) | `github.com/go-ldap/ldap/v3` v3.4.14 `Conn.Bind(username, password string)`: the `SimpleBindRequest` keeps the string and `ber.NewString` copies it into the BER packet, which is serialized into the connection's write path (and `crypto/tls` record buffers under `ldaps://` or StartTLS). | go-auth's string: zeroed when `Bind` returns. go-ldap's packet and write buffers: unwiped, unreachable once `Bind` returns, resident until the allocator reuses them. | A go-ldap bind that takes `[]byte` and wipes its packet, or an in-repo encoder for the simple-bind request written from inside `WithBytes`. |
| R2 | `pkg/radius/authenticator.go:Authenticator.Authenticate` | `layeh.com/radius`: `Packet.Secret` aliases the locked pages (no copy), but encoding the request and checking the Response Authenticator (RFC 2865 §3) hash the shared secret with `crypto/md5`, whose digest state is a heap struct. The password is **not** a residue: `rfc2865.UserPassword_Set` obfuscates it (RFC 2865 §5.2) straight out of its borrow into the attribute. | One exchange; the digest state is unwiped until collected. | An MD5 whose state lives in locked memory (the standard library offers none). |
| R2 | `pkg/radius/eaptls.go:Authenticator.authenticateEAPTLS` (with `eap.go` `setMessageAuthenticator` / `verifyMessageAuthenticator`) | The RFC 2869 §5.14 / RFC 3579 §3.2 Message-Authenticator is HMAC-MD5 keyed by the shared secret: `crypto/hmac` derives ipad/opad blocks, and the request/response hashing above, for every round trip of the conversation. | One EAP-TLS conversation; derived state unwiped until collected. | As above, for HMAC-MD5. |
| R3 | `pkg/tacacs/authenticator.go:Authenticator.Authenticate` | `github.com/nwaples/tacplus` v0.0.3 `ConnConfig.Secret []byte` is lent the locked pages for the exchange; its `crypt` (RFC 8907 §4.5) copies key and session id into a fresh heap buffer for **every packet** and hashes it with `crypto/md5`. tacplus reads the key only on the goroutine that called `SendAuthenStart` / `Continue`, so nothing reads it after `Authenticate` returns and `Close` can unmap it (re-verify on any tacplus upgrade). | Per-packet heap copies of the key, unwiped until collected. | A tacplus `crypt` that hashes from the key slice without copying and wipes its state. |
| R3 | `pkg/tacacs/authenticator.go:Authenticator.handleReply` | tacplus `ClientSession.Continue(ctx, msg string)` takes the password reply as a string and appends it into the packet buffer. | go-auth's string: zeroed when `Continue` returns. tacplus's packet buffer holds the plaintext only between marshalling and `crypt`, which obfuscates it in place before the write. | `Continue` taking `[]byte`. |
| R4 | `pkg/otp` (closed) | `github.com/pquerna/otp` took the seed as a base32 `string` on every validation. | — | **Removed** by [#46](https://github.com/jeremyhahn/go-auth/issues/46): in-repo RFC 4226 / RFC 6238 over the seed's borrow. No call site remains. |
| R5 | `pkg/oauth/credential.go:withFormBody` | `net/http` / `crypto/tls`: token-request bodies (client secret, refresh token, password, code verifier) are assembled in a locked scratch enclave, then copied by the transport into its write and TLS record buffers; token responses pass through its read buffers before being decoded straight into enclaves. | One request; transport buffers are pooled and unwiped. | A transport that writes and encrypts from locked memory. |
| R5 | `pkg/oauth/validator.go:tokenValidator.sendIntrospection` | `net/http` `Request.SetBasicAuth(clientID, secret string)`: the client secret becomes part of an `Authorization` header string. | One request; the header string is unwiped until collected. | A transport that renders headers from locked memory. |
| R5 | `pkg/oauth/oidc_userinfo.go:userInfoClient.fetchUserInfo` | `net/http` header: `Authorization: Bearer <access token>` as a string. | One request; unwiped until collected. | As above. |
| R5 | `pkg/oauth/validator.go:tokenValidator.validateJWT` | `github.com/golang-jwt/jwt/v5` parses only from a `string`: one copy of the bearer token per validation. | One validation; unwiped until collected. | A JWT parser over `[]byte`. |
| R5 | `pkg/oauth/oidc_validator.go:oidcValidator.ValidateIDToken` | golang-jwt, as above, for the ID token. | One validation; unwiped until collected. | As above. |
| R5 | `pkg/yubikey/yubicloud_validator.go:HTTPValidator.Validate` | Yubico Validation Protocol 2.0 is an HTTP GET: the OTP is a query parameter, which `net/url` and `net/http` carry only as strings (the encoded query, the request URL, the request line). | go-auth's string: zeroed when the exchange returns. `net/url` / `net/http` copies: unwiped until collected. A YubiKey OTP is single-use and worthless once validated. | Inherent in the protocol's transport; a validation service with a POST body could use the R5 form-body path. |
| R6 | `pkg/pam/pam_default_cgo.go:pamSession.Authenticate` | `github.com/msteinert/pam/v2` v2.1.0: the conversation callback must return a Go `string`, and the binding's `cbPAMConv` copies it with `C.CString` and hands the C buffer to the PAM module, which owns and frees it (Linux-PAM's `pam_get_authtok` overwrites it before `free`; other modules may not). The module stack keeps its own copies (`PAM_AUTHTOK`). | go-auth's string: zeroed when `pam_authenticate` / `pam_acct_mgmt` return. The C copy: the module's, until it frees it. | A binding whose conversation fills a `C.malloc`ed buffer from inside `WithBytes`; PAM's contract makes the module its owner, so go-auth can never wipe it after the call. |
| R6 | `pkg/pkcs11/system_provider_pkcs11.go:nativeSession.Login` | `github.com/miekg/pkcs11` v1.1.2 `Ctx.Login(sh, userType, pin string)` does `C.CString(pin)` and `C.free` without wiping; the vendor module may keep its own copy. | go-auth's string: zeroed when `Login` returns. The freed C buffer: until `malloc` reuses it. | A binding that calls `C_Login` from a buffer go-auth `malloc`s, fills inside `WithBytes` and `explicit_bzero`s before `free`. |
| R7 | Caller configuration — no `pkg/` call site; includes `pkg/otp/seed.go:DecodeSeed`'s input | Credentials that reach the program as strings — environment variables, YAML, flags, a stored base32 OTP seed — and are brought in with `enclave.NewMemoryEnclave([]byte(s))` or `otp.DecodeSeed(string)`. | The caller's string lives until it is collected; go-auth copies it into an enclave and keeps nothing else. | The consumer reads the secret into a `[]byte` (a file, a KMS response) and calls `enclave.NewMemoryEnclave`, which wipes it. |
| R8 | `pkg/otp/seed.go:EncodeSecret` (and `Authenticator.ProvisioningURI`, which uses it) | Enrollment needs the seed as text: base32 for storage, an `otpauth://` URI for the QR code. The encoding is done in a locked scratch enclave, then returned as a string. | The returned string is the caller's to drop. | QR rendering from bytes, and a `ProvisioningURI` that returns an enclave. |
| R8 | `pkg/otp/authenticator.go:Authenticator.derive` (used by `Generate` and HOTP validation) | An HOTP/TOTP code is rendered as a decimal string; `Generate` returns it, and HOTP validation compares against it in constant time. | A code is valid for one counter value or period; the heap string is unwiped until collected. | Deriving into a fixed locked buffer, and a `Generate` that returns an enclave. |

## Not a go-auth call site

`tpm2.TPMSession` implementations live in the consumer (go-auth ships none; the
integration test has one over `github.com/google/go-tpm`). They are lent the
authorization value through `WithBytes`, and should move the TPM's unseal
response into an enclave with `enclave.NewMemoryEnclave`, which wipes the
response buffer. go-tpm's command and response buffers are the provider's
residue, outside this module.
