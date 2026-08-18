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

A `Secret` is a [memguard](https://github.com/awnumar/memguard) enclave: the
value is encrypted at rest under a session key that itself lives in locked,
guarded, non-swappable memory, and is decrypted only for the duration of one
`Open` call, into a locked buffer that is wiped and unmapped before `Open`
returns.

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
and never lives in the Go heap. What it does not have is a `Secret`'s
encryption at rest: the plaintext is resident for the lifetime of the `Locked`,
which is the price of being readable at a moment its holder does not choose.
Prefer `Secret`; reach for `Locked` only where a dependency's lifetime makes
`Secret` unusable, and say which dependency in a comment.

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

The deprecated entry points still work and are not going away in this release.
They now seal what they are given before doing anything else, so the exposure
they carry is limited to the caller's own copy of the value.

`pkg/oauth` (`ClientSecret`, token cache) and `pkg/api`
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

memguard locks its pages with `mlock(2)`, which is bounded by
`RLIMIT_MEMLOCK`. Exhausting that limit is fatal: memguard purges the session
and panics rather than continuing with a page that could be swapped.

One locked allocation is made per concurrent `Open` and freed at the end of it,
so the requirement scales with in-flight authentications, not with the number
of secrets held. A container with the common 8 MiB default has room for roughly
two thousand simultaneous opens. Deployments that authenticate concurrently
should raise the limit — 64 MiB is generous — rather than discover it under
load:

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

`secret.Purge()` wraps memguard's session purge for a program's shutdown path.
It wipes the session key, which invalidates every `Secret` in the process, so it
belongs to the program that owns the process lifetime and never to a library —
nothing in `go-auth` calls it.

## FIPS 140-3

memguard seals with BLAKE2b and NaCl secretbox from `golang.org/x/crypto`,
outside the Go Cryptographic Module, so its own sealing neither participates in
nor is restricted by `GODEBUG=fips140`. The credential itself is unaffected:
what a FIPS build restricts is the primitive a backend keys with it.
The package builds and its tests pass under `GOFIPS140=latest` with
`fips140=only`.
