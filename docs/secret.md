# Protected Memory (`pkg/secret`)

The `secret` package holds credential material — keys, passwords, shared
secrets and tokens — in protected memory, and is the mechanism behind the
protected-secret API of every backend in this library.

## The rule

> Every key, password, shared secret and token this module holds for longer
> than a single call lives in a `secret.Secret`, and is released when the
> component holding it is done with it. It is never kept in a Go `string`, and
> never in a plain `[]byte` on the heap.

A `string` cannot be wiped at all. A heap `[]byte` can be wiped only if every
copy of it is accounted for, and it can be paged to swap or captured in a core
dump before that happens.

A `Secret` is a [go-enclave](https://github.com/jeremyhahn/go-enclave)
`MemoryEnclave`: the value lives in page-aligned, `mlock(2)`ed, non-swappable
memory, fenced between inaccessible guard pages with a canary and marked
`MADV_DONTDUMP` so it is excluded from core dumps. It is read only through a
borrow held under the enclave's lock, for the duration of one `Open` call. The
locked region is held for the secret's whole lifetime rather than re-mapped per
`Open`, so a repeated or concurrent `Open` allocates no locked memory — the
property that closes the login-path memlock-exhaustion DoS
([#21](https://github.com/jeremyhahn/go-auth/issues/21)).

## Using it

```go
import "github.com/jeremyhahn/go-auth/pkg/secret"

sec, err := secret.NewString(os.Getenv("RADIUS_SECRET"))
if err != nil {
    return err
}
defer sec.Destroy()

err = sec.Open(func(key []byte) error {
    // key is valid here and nowhere else.
    return send(newPacket(key))
})
```

| Constructor | Use it when | Plaintext on the heap? |
|---|---|---|
| `secret.NewWith(size, fill)` | the value is decoded or derived here | never |
| `secret.NewRandom(size)` | this process is generating the key | never |
| `secret.New(b)` | the value was read into a buffer you own | `b` is wiped for you |
| `secret.NewString(s)` | the value is already in a Go string | the string cannot be wiped |

`secret.Scratch(size, fn)` gives a locked, wiped-on-return buffer for a value
that is only needed for one operation — decoding a sealed API key out of base64
to key an HMAC, for instance.

### `Locked`, for values a dependency keeps

`sec.Lock()` returns a `*secret.Locked`: the value in a locked buffer that
stays readable until it is destroyed. It exists for code that offers no scope
to read a key in — a client that keeps the secret for the life of a connection
and uses it from goroutines it does not join, which is `pkg/tacacs` and
`tacplus`. Handing such a reader enclave memory would fault it when the `Open`
returns; handing it an ordinary heap copy would put the plaintext where it can
be swapped, dumped and duplicated by the collector, and wiping that copy
afterwards would race the reader.

The buffer is `mlock(2)`ed, marked `MADV_DONTDUMP`, guard-paged and canaried,
and never lives in the Go heap. The difference from a `Secret` is only the
window of exposure: a `Secret` is read under a borrow that ends with the `Open`
call, while a `Locked` stays readable — resident in locked memory — for its
whole lifetime, which is the price of being readable at a moment its holder does
not choose. Neither is encrypted at rest; both hold the plaintext in locked,
guarded pages. Prefer `Secret`; reach for `Locked` only where a dependency's
lifetime makes `Secret` unusable, and say which dependency in a comment.

`Secret` renders as `secret.Secret(redacted)` under every `fmt` verb, so a
stray `%v` or a structured-log field cannot print a credential.

## Ownership

A `Secret` passed to an authenticator is **borrowed**, not owned: destroy it
when the last component using it is done. The deprecated string constructors
seal the value they are given and own that enclave for the authenticator's
lifetime.

## Where it is used

| Package | Protected API | Deprecated plain path |
|---|---|---|
| `pkg/otp` | `Config.SecretKey`, `NewProtectedSecret`, `GenerateProtectedSecret`, `ProvisioningURI` | `Config.Secret`, `GenerateSecret`, `GetProvisioningURI` |
| `pkg/radius` | `NewAuthenticatorWithSecret` | `NewAuthenticator` |
| `pkg/tacacs` | `NewAuthenticatorWithSecret` | `NewAuthenticator` |
| `pkg/ldap` | `WithProtectedServiceAccount` | `WithServiceAccount` |
| `pkg/yubikey` | `Config.ProtectedAPIKey`, `ProtectedOTPValidator` | `Config.APIKey`, `OTPValidator` |
| `pkg/oauth` | `BuildAuthURLPKCE`, `ExchangeAuthorizationCodePKCE` (PKCE code verifier) | `BuildAuthURL(state, true, …)`, `ExchangeAuthorizationCode`'s `codeVerifier` |

The deprecated entry points still work and are not going away in this release.
They now seal what they are given before doing anything else, so the exposure
they carry is limited to the caller's own copy of the value.

The rest of `pkg/oauth` (`ClientSecret`, the token cache) and `pkg/api`
(`LoginRequest.Password`) are not covered yet; they are tracked by the
repository-wide protected-memory audit.

## What it does not defend against

An attacker who can execute code in this process, or attach a debugger to it,
can wait for an `Open` and read the buffer. Protected memory is a defense
against a value's *residency* — swap, core dumps, crash reporters, heap
snapshots, and the long tail of copies a garbage-collected runtime leaves
behind — not against a live adversary inside the address space.

Values derived from a secret are not covered either, and neither are copies
taken by code this library calls:

- **`crypto/hmac`** derives its ipad/opad blocks from the key and holds them in
  the hash state until the collector reclaims it. There is no API to wipe it,
  and re-implementing HMAC to avoid it would move the construction outside the
  FIPS 140-3 boundary — a worse trade than one short-lived derivative. The
  derivation in `pkg/otp` and `pkg/yubikey` keeps that state local to a single
  call.
- **`go-ldap`'s `Bind`** takes the password as a `string`, so the service bind
  materializes one immutable copy per bind. It is unreachable once the bind
  returns but cannot be wiped.
- **`tacplus`** keeps the shared secret for the life of a connection and
  decrypts with it from goroutines it does not join, so `pkg/tacacs` holds its
  key in a `secret.Locked` (below) rather than opening an enclave per exchange.
  There is no heap copy and nothing to wipe, but the plaintext is resident —
  locked and undumpable — for the authenticator's lifetime, with no safe
  release point, so a TACACS+ authenticator should be constructed once per
  server and reused.
- **`github.com/pquerna/otp`** takes the OTP secret as a `string` and decodes it
  on every call. That is the reason `pkg/otp` derives codes itself (RFC 4226
  §5.3, RFC 6238 §4.2) when `Config.SecretKey` is used; the dependency is still
  used for the deprecated `Config.Secret` path.

## Operational requirements

An enclave locks its pages with `mlock(2)`, which is bounded by
`RLIMIT_MEMLOCK`. Locked memory is allocated once, when a `Secret` is
constructed, and released when it is destroyed — **not** per `Open`. The
requirement therefore scales with the number of secrets held, a small and
bounded figure, and not with the number of in-flight authentications: an
authentication borrows the region the secret already holds and allocates
nothing. Exhausting `RLIMIT_MEMLOCK` fails the allocating constructor with a
typed error matching `enclave.ErrLockedMemoryUnavailable`, touching no other
secret — never the process-wide purge-and-panic the memguard backing did, which
was the login-path DoS in [#21](https://github.com/jeremyhahn/go-auth/issues/21).

A container with the common 8 MiB default holds far more small secrets than a
process needs, but an image that drops the limit to a few pages can starve
construction — which now fails closed with an error rather than crashing.
Deployments should still raise the limit rather than discover it under load:

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

There is no process-wide purge, and `pkg/secret` exposes no `Purge`: wiping
every enclave at shutdown is a deliberate, ordered act that belongs to the
program owning the process lifetime (go-enclave's `WipeAll`), never to a
library. This package destroys only the secrets it is handed, when their holders
release them — `Destroy` wipes and unmaps that one region.

## FIPS 140-3

go-enclave holds the credential as plaintext in locked, guarded pages; it seals
with no cipher at all, so — unlike the memguard backing this replaced, which
sealed with BLAKE2b and NaCl secretbox from `golang.org/x/crypto` — nothing in
the protected-memory layer touches a cryptographic primitive, approved or
otherwise. What a FIPS build restricts is only the primitive a backend keys with
the opened credential. The package builds and its tests pass under
`GOFIPS140=latest` with `fips140=only`.
