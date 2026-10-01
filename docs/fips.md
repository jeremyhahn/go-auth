# FIPS 140-3 compliance

go-auth's CI runs a FIPS job with `GOFIPS140=latest` and `GODEBUG=fips140=only`
(company convention `configuration.md` §5).

`fips140=only` is deliberately stricter than `fips140=on`. `on` loads the Go
Cryptographic Module but still *permits* non-approved algorithms, so a test
exercising MD5 or SHA-1 succeeds and the gate reports green while a regulated
path uses prohibited cryptography. `only` makes non-approved operations panic,
which is what a FedRAMP / PCI DSS / HIPAA gate has to do.

## Building for a FIPS-140-only deployment

```sh
GOFIPS140=latest GODEBUG=fips140=only go build -tags fips140only ./...
GOFIPS140=latest GODEBUG=fips140=only go test -count=1 -tags fips140only ./...
```

The `fips140only` build tag selects the subset of this library that can operate
under `fips140=only`. It is not a "skip the awkward tests" switch: it removes
code that is *incapable* of FIPS-140-only operation, so that a FIPS build
cannot link it at all rather than shipping a backend that panics the first
time it is used. Everything the tag removes is still built, linted, scanned by
gosec and unit-tested by the non-FIPS CI jobs.

Default builds (no tag) are unchanged and keep every backend.

## Exemptions

An exemption here means: an external format or protocol mandates a
non-approved primitive, so its use is not a compliance defect — FedRAMP, PCI
DSS and HIPAA govern the protection of regulated data, not every hash in the
process. The primitive is nonetheless kept out of the FIPS-gated path.

### RADIUS — `pkg/radius`, excluded by `fips140only`

| | |
|---|---|
| Primitive | MD5, and HMAC-MD5 |
| Mandated by | RFC 2865 §3 (Request/Response Authenticator = `MD5(Code \|\| ID \|\| Length \|\| RequestAuth \|\| Attributes \|\| Secret)`); RFC 2869 §5.14 and RFC 3579 §3.2 (Message-Authenticator = HMAC-MD5) |
| Scope | The whole backend. Every RADIUS packet carries an MD5 authenticator, so no code path avoids it. |

RadSec (RFC 6614) does not resolve this. It carries RADIUS inside TLS, but the
inner packet's MD5 authenticator is still computed, so a RadSec client panics
under `fips140=only` just as a UDP one does.

Deployments subject to FIPS 140-3 must not use the RADIUS backend. Two
independent mechanisms enforce that, for the two shapes of artifact:

- **Link time** — building with `-tags fips140only` removes the package, so a
  FIPS-only artifact cannot contain MD5 at all.
- **Run time** — an ordinary build contains the backend, and
  `NewAuthenticator` / `NewAuthenticatorWithSecret` return
  `radius.ErrFIPSUnsupported` when FIPS is activated. This is the company FIPS
  product ruling 7 case ("disabled with a clear typed error"), and it is what
  serves boundary ruling 1's model of one FIPS-capable artifact activated at
  deployment with `GODEBUG=fips140=only`. Configuring RADIUS in such a
  deployment fails at startup instead of panicking inside `crypto/hmac` on the
  first login.

`pkg/radius/fips.go` detects activation by computing one HMAC-MD5 over a fixed
non-secret input and observing whether the runtime refuses. That is not the
obvious mechanism, so the reason is worth recording. `crypto/fips140.Enabled()`
answers a different question — measured on go1.26.6:

| build | `GODEBUG` | `fips140.Enabled()` | HMAC-MD5 |
|---|---|---|---|
| plain | *(none)* | false | ok |
| plain | `fips140=on` | true | ok |
| plain | `fips140=only` | true | panics |
| `GOFIPS140=latest` | *(none)* | **true** | **ok** |
| `GOFIPS140=latest` | `fips140=on` | true | ok |
| `GOFIPS140=latest` | `fips140=only` | true | panics |

`Enabled()` reports that the FIPS module is linked in, which under ruling 1 is
true of every binary the company ships. Gating on it would disable RADIUS in
every deployment, including the ones entitled to use it. Nothing exported
distinguishes `only` from `on`, and reading `GODEBUG` from the environment
would miss a `//go:debug fips140=only` directive compiled into the main
package. Executing the primitive measures the condition the backend actually
depends on, however it was set.

`TestFIPSActivationRefusesRADIUS` proves it end to end by re-executing the test
binary under `GODEBUG=fips140=only` — the plain unit-test job is enough, since
`fips140=only` applies to an ordinary build.

### TACACS+ — `pkg/tacacs`, excluded by `fips140only`

| | |
|---|---|
| Primitive | MD5 |
| Mandated by | RFC 8907 §4.5 — the packet body is obfuscated with an MD5-based keystream (`MD5(session_id \|\| key \|\| version \|\| seq_no \|\| prev_hash)` chained and XORed over the body) |
| Scope | The whole backend. It is the only body encoding the protocol defines. |

Same conclusion: not available to FIPS 140-3 deployments, enforced by the tag.

### YubiCloud — `pkg/yubikey/yubicloud_validator.go`, excluded by `fips140only`

| | |
|---|---|
| Primitive | HMAC-SHA-1 |
| Mandated by | Yubico Validation Protocol 2.0 — every request and response is signed with HMAC-SHA-1 over the sorted parameter list, and the service rejects any other digest |
| Scope | The YubiCloud HTTP validator only, not the whole backend |

`pkg/yubikey` stays in the FIPS build. Only the YubiCloud validator is
excluded, and with it the `init()` that installed it as the package default —
so under the tag `NewAuthenticator(cfg, nil)` fails fast with
`errSystemValidatorUnavailable` rather than panicking mid-request. A caller
that injects its own `OTPValidator`, pointed at a validation service that
speaks an approved digest, keeps the full YubiKey authentication path.

This one is worth calling out because it is the failure mode a FIPS gate is
worst at catching on its own: every unit test injected a fake validator, so the
HMAC-SHA-1 path was never executed and the job passed while the artifact still
contained a backend that would panic on first real use.
`TestYubiCloudUnreachableUnderFIPS` guards it by asserting that package
initialization installs no default validator.

### OTP — `pkg/otp`, partial

| | |
|---|---|
| Primitive | HMAC-SHA-1 |
| Mandated by | RFC 4226 §5.3 (HOTP is HMAC-SHA-1); RFC 6238 §1.2 (SHA-1 is TOTP's default and what mainstream authenticator apps implement) |
| Scope | `Algorithm: AlgorithmSHA1`, an omitted `Algorithm` (whose RFC default is SHA-1), and seeds below the 112-bit HMAC key floor |

This package is **not** excluded from anything, and carries no build tag. RFC
6238 §1.2 also permits SHA-256 and SHA-512, `pkg/otp` supports both, and Go's
`fips140=only` admits HMAC over SHA-2 and SHA-3 — so approved OTP works. Only
`AlgorithmSHA1` and short seeds are unusable, and the algorithm must be named.

FIPS activation is detected at runtime, by executing HMAC-SHA-1 once per
process and treating a runtime refusal as "activated" — the same probe
`pkg/radius/fips.go` uses, for the same reason: `crypto/fips140.Enabled()` is
true of every `GOFIPS140` binary whether or not FIPS was activated, and gating
on it would refuse SHA-1 TOTP to every deployment. When the probe reports
activation the package fails closed rather than leaving that to the runtime:

- `Algorithm: AlgorithmSHA1` is rejected by `NewAuthenticator` with
  `ErrFIPSUnsupported` (wrapped in `ErrInvalidConfig`) naming the approved
  alternatives.
- An omitted `Algorithm` is rejected too, with `ErrFIPSUnsupported` saying the
  algorithm must be set explicitly to SHA256 or SHA512. RFC 6238's default is
  SHA-1, and silently substituting an approved digest would validate seeds
  enrolled under that default with the wrong one — every login failing, with
  nothing at startup to say why. Refusing makes the choice, and any
  re-enrollment it implies, deliberate.
- A seed shorter than **112 bits** is rejected with `ErrFIPSUnsupported` too.
  FIPS 140-3 sets that floor for HMAC keys; measured against the toolchain, 13
  bytes panics and 14 does not. The length is read from the seed's enclave
  with `Size()`, so measuring it never opens the key.

These checks have to happen at construction. `crypto/hmac` does not return an
error for SHA-1 or for a short key under `fips140=only` — it **panics**.
Accepting either configuration would put that panic behind `Generate`,
`Authenticate` and `ValidateCounter`, so an ordinary authentication attempt,
which is attacker-reachable traffic, would crash the process instead of failing
a login. The derivation re-checks immediately before keying HMAC as well, so
no path can reach the panic.

The key-length rule has an operational consequence worth planning for: an
application holding seeds enrolled from the 80-bit `JBSWY3DPEHPK3PXP` example
(or any provisioning tool that emitted short seeds) must **re-enroll those
users** before FIPS can be activated. Failing at construction is what surfaces
that at startup rather than at a login attempt. Seeds this package issues are
unaffected — `GenerateProtectedSecret` emits 160 bits.

A FIPS deployment must therefore set `Algorithm` explicitly to SHA-256 or
SHA-512, enroll users with it — re-enrolling anyone enrolled under SHA-1 — and
accept that authenticator apps which only speak SHA-1 will not interoperate.

The FIPS job runs the entire OTP suite with no tag. Tests whose digest is
incidental pick it from the same probe — SHA-1 normally, SHA-256 when FIPS is
activated — so each covers the same code path in both modes; the RFC 4226 and
RFC 6238 SHA-1 vectors, and an omitted algorithm, assert the typed refusal
instead. `TestFIPSActivation`
also re-executes the test binary under `GODEBUG=fips140=only`, so every
ordinary test run exercises the real runtime refusal, not just the FIPS job.

## Not exemptions — fixed in place

Two problems the `fips140=only` gate surfaced were real defects, and were fixed
rather than exempted.

- **`pkg/otp` HOTP validation ignored the configured algorithm.** Both
  validation entry points — `Authenticate` and `ValidateCounter` — called
  `github.com/pquerna/otp`'s `hotp.Validate`, which hardcodes 6 digits and SHA-1
  regardless of how the authenticator was built, while `Generate` honoured the
  configuration. A SHA-256 or 7/8-digit HOTP secret could therefore never
  validate a code it had just generated. The dependency has since been removed
  ([#46]); HOTP and TOTP are derived in-repo from the configured options.
- **The OTP test fixture used an 80-bit secret.** `JBSWY3DPEHPK3PXP` is the
  widely copied Google Authenticator doc example; it base32-decodes to 10
  bytes, below the 112-bit floor FIPS 140-3 sets for HMAC keys. Every fixture
  the FIPS job runs now uses the RFC 4226 Appendix D reference seed (20 bytes /
  160 bits), which is also what `GenerateProtectedSecret` emits. The algorithm
  was never the problem, only the key length of the fixture.

  The example's length is still used deliberately elsewhere, as a subject
  rather than a convenience: `pkg/otp/fips_test.go` checks that a seed of that
  length is *rejected* when FIPS is activated, and accepted otherwise, because
  an ordinary deployment has no key-length floor and must go on working for
  callers who enrolled against it.

## What is *not* an acceptable response to a red FIPS job

Setting `GODEBUG` back to `fips140=on`, adding a tag that skips the job, or
narrowing the test scope so a failing package is simply not covered. A gate
that cannot fail on the thing it exists to catch is decoration. If a failure
cannot be fixed or honestly exempted, it gets escalated, not silenced.

[#46]: https://github.com/jeremyhahn/go-auth/issues/46
