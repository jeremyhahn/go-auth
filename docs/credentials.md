# Credentials in go-enclave memory

> **Status: NORMATIVE** · Scope: go-auth · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.

Every credential go-auth handles — passwords, PINs, one-time passwords, shared
secrets, service-account passwords, API keys, OTP seeds, OAuth client secrets
and tokens — is a [go-enclave](https://github.com/jeremyhahn/go-enclave)
`*enclave.MemoryEnclave`, and nothing else
([#48](https://github.com/jeremyhahn/go-auth/issues/48), owner ruling on
[#3](https://github.com/jeremyhahn/go-auth/issues/3)). There is no
plaintext-string credential path anywhere in the library: no `string`
password parameter, no `string` secret field, no deprecated shim.

Identifiers are not credentials and stay `string`: usernames, bind DNs, OAuth
client IDs, Yubico client IDs, token labels (ruling §10.8).

## What a MemoryEnclave is

A `MemoryEnclave` holds plaintext in a page-aligned region that is
`mlock(2)`ed (never swapped), marked `MADV_DONTDUMP` (never in a core dump),
fenced by inaccessible guard pages with a canary in front of the data, and
frozen read-only once filled. `Destroy` zeroes the region and unmaps it. It
renders as `MemoryEnclave(redacted)` under every `fmt` verb.

It is **locked-only**: it performs no cryptography. There is no sealing key,
no cipher, no hash — so the protected-memory layer sits entirely outside the
FIPS 140-3 boundary question. What a FIPS deployment restricts is only the
primitive a backend keys with the borrowed credential; see [fips.md](fips.md).

When the kernel refuses to lock memory, every constructor fails **closed**
with an error matching `enclave.ErrLockedMemoryUnavailable`. go-auth surfaces
that error and never falls back to ordinary memory (ruling §10.4).

## Building one

| Constructor | Use it when | Plaintext left on the heap |
|---|---|---|
| `enclave.NewMemoryEnclaveSized(n)` + `WithBytes` fill + `Freeze` | the value is generated or decoded here | none |
| `enclave.NewMemoryEnclave(b)` | the value was read into a `[]byte` you own | none — `b` is wiped for you |
| `enclave.NewMemoryEnclave([]byte(s))` | the value only exists as a Go string (env var, YAML, flag) | `s` itself, which cannot be wiped — residue R7 |

```go
raw, err := os.ReadFile("/run/secrets/radius")   // []byte, not string
if err != nil {
    return err
}
secret, err := enclave.NewMemoryEnclave(bytes.TrimSpace(raw)) // wipes raw's bytes
if err != nil {
    return err // enclave.ErrLockedMemoryUnavailable: fail closed
}
auth, err := radius.NewAuthenticator("radius.example.com:1812", secret)
if err != nil {
    return err // secret has already been destroyed
}
defer auth.Close() // destroys secret
```

Read the material only through `WithBytes`: the slice it lends aliases the
locked pages and is valid for the callback alone. go-enclave v0.8.0-alpha
removed `Open` and `OpenString`, whose slice outlived the lock. A dependency
that forces a copy gets one taken inside `WithBytes`; every place this module
does that is registered (below).

## Ownership rules

Three rules, the same in every package:

1. **Constructors take ownership.** An enclave given to a constructor or put in
   a configuration struct — `radius.NewAuthenticator`'s shared secret,
   `tacacs.NewAuthenticator`'s shared secret, `ldap.WithServiceAccount`'s
   password, `yubikey.Config.APIKey`, `otp.Config.Seed`,
   `oauth.Config.ClientSecret` — belongs to the authenticator from that call
   on. The constructor destroys it on **every** return path, including its
   refusals (an empty address, a FIPS refusal). Do not use or destroy it
   afterwards, and give each authenticator its own.
2. **`Close` destroys.** Each owning authenticator has `Close() error`, which
   waits for in-flight borrows to finish, destroys what it owns, and makes the
   authenticator refuse further use with a typed `ErrClosed` (or, in
   `pkg/oauth`, `ErrCredentialUnavailable`). `pkg/otp`'s `Close` destroys the
   seed and has no `ErrClosed`; later use fails on the destroyed seed.
3. **Per-call arguments are borrowed.** The credential passed to
   `Authenticate` (and `ValidateCounter`, `ValidateToken`, `Login` on a
   session, `Unseal`, …) stays the caller's. The callee reads it inside
   `WithBytes` and never destroys it.

The one exception is the facade: **`api.Service.Login` takes ownership of
`LoginRequest.Password` and `LoginRequest.OTP`** and destroys both when the
attempt completes — on success, on failure and on every refusal. The backends
it dispatches to borrow them for their attempt. A `Destroy` that fails is
joined to the error `Login` returns, so a login that succeeded still reports a
credential that could not be wiped. Build a fresh request per login.

A nil enclave is "not supplied" and fails with the package's typed sentinel
(`ErrMissingPassword`, `ErrMissingPIN`, `ErrMissingOTP`, …). A destroyed one
fails with the same sentinel joined with `enclave.ErrEnclaveDestroyed`, so
`errors.Is` can tell a missing field from a lifecycle bug.

## The common interface

Every backend authenticates through one method shape:

| Backend | Method |
|---|---|
| `pam`, `ldap`, `radius`, `tacacs` | `Authenticate(ctx, username string, password *enclave.MemoryEnclave) error` |
| `oauth` (the `pkg/api` adapter) | `Authenticate(ctx, username string, token *enclave.MemoryEnclave) error` — username ignored |
| `pkcs11` | `Authenticate(ctx, pin *enclave.MemoryEnclave) error` |
| `tpm2` | `Authenticate(ctx, password *enclave.MemoryEnclave) error` |
| `yubikey`, `otp` | `Authenticate(ctx, otp *enclave.MemoryEnclave) error` |

`pkg/api`'s `Handler` takes `(ctx, username string, password, otp
*enclave.MemoryEnclave)`. A YubiKey or TOTP code is a credential for as long
as it would be accepted, so it travels in an enclave too.

Injected collaborators follow the same rules: `pam.Session.Authenticate`,
`pkcs11.Session.Login`, `tpm2.TPMSession.Unseal` and `yubikey.OTPValidator`
borrow their credential arguments. `TPMSession.Unseal` returns the unsealed
data in an enclave the caller owns — move the TPM response in with
`enclave.NewMemoryEnclave`, which wipes the response buffer — and
`tpm2.Authenticator` destroys it before returning, on every path.

## Where plaintext still leaves locked memory

Some dependencies accept a credential only as a `string` or keep their own
copy. Those places are finite, each is named at its call site with a residue
ID, and they are listed in the
[credential residue register](security/credential-residues.md). CI enforces
the list: `test/ci/credential_residue_test.go` enumerates every
`WithBytes` call and every
`credential.WithTransientString` call in `pkg/` and fails on any site that is
not in `test/ci/testdata/credential-residues.allow`, or listed but gone.

Where a dependency demands a `string`, go-auth lends it one backed by a heap
buffer that is zeroed the moment the dependency returns
(`pkg/internal/credential.WithTransientString`), instead of an immutable copy
that would linger until the collector reused it.

## What it does not defend against

An attacker who can execute code in the process, or attach a debugger, can
read a credential while it is borrowed. Locked memory defends a value's
*residency* — swap, core dumps, crash reporters, heap snapshots and the copies
a garbage-collected runtime leaves behind — not a live adversary in the
address space. Values derived from a credential inside a primitive (the
ipad/opad blocks `crypto/hmac` keeps, an MD5 state) are covered by the
register, not by the enclave.

## Operational requirements

Locked memory is bounded by `RLIMIT_MEMLOCK`. Each enclave reserves at least
one page plus guard pages for its lifetime; an authentication borrows the
pages the credential already holds, and `Service.Login` holds the request's
enclaves for one attempt. Size the limit for the long-lived credentials (one
per authenticator) plus the logins in flight:

```yaml
# docker-compose
ulimits:
  memlock:
    soft: 67108864
    hard: 67108864
```

```ini
# systemd unit
[Service]
LimitMEMLOCK=64M
```

Exhaustion fails the allocating call with `enclave.ErrLockedMemoryUnavailable`
and touches no other enclave. Wiping every enclave at shutdown is the
program's decision (go-enclave's `WipeAll`), never this library's.
