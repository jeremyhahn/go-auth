# OTP Authentication Package

The `otp` package provides TOTP (Time-based One-Time Password) and HOTP (HMAC-based One-Time Password) authentication following RFC 6238 and RFC 4226 respectively.

## Features

- **TOTP Support**: Time-based codes that change every 30 seconds (configurable)
- **HOTP Support**: Counter-based codes for hardware tokens
- **Multiple Hash Algorithms**: SHA1, SHA256, SHA512

> **FIPS 140-3 deployments must use SHA256 or SHA512.** `AlgorithmSHA1` — RFC
> 6238's default and the only digest some authenticator apps implement —
> cannot run under `GODEBUG=fips140=only`. There is no build tag: when a
> process runs in that mode, `Algorithm` must be set explicitly to SHA256 or
> SHA512 — `NewAuthenticator` rejects SHA1 *and an omitted `Algorithm`* with
> `ErrFIPSUnsupported`, rather than silently changing the digest existing
> enrollments are validated with. Seeds shorter than 112 bits are rejected there too, so users
> enrolled with an 80-bit seed need re-enrollment before FIPS is activated. The
> rest of the package is unaffected. See [FIPS 140-3 compliance](fips.md).
- **Flexible Digit Lengths**: 6, 7, or 8 digit codes
- **Clock Skew Tolerance**: Configurable time window for TOTP validation
- **Provisioning URIs**: Generate `otpauth://` URIs (Google Authenticator Key URI Format) for QR codes
- **Seeds in locked memory**: the shared key lives only in a go-enclave `*enclave.MemoryEnclave`
- **Context Support**: All operations support context cancellation
- **Thread-Safe**: Safe for concurrent use
- **No OTP dependency**: RFC 4226 / RFC 6238 are implemented in-repo over the standard library

## Installation

```bash
go get github.com/jeremyhahn/go-auth/pkg/otp
```

## Quick Start

### TOTP (Time-based OTP)

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-auth/pkg/otp"
)

func main() {
    // Generate a seed straight into locked memory
    seed, err := otp.GenerateProtectedSecret()
    if err != nil {
        log.Fatal(err)
    }

    // NewAuthenticator takes ownership of the seed; Close destroys it.
    auth, err := otp.NewAuthenticator(otp.Config{
        Type:        otp.TypeTOTP,
        Seed:        seed,
        Issuer:      "MyApp",
        AccountName: "user@example.com",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close()

    // Generate current code
    code, _ := auth.Generate()
    fmt.Printf("Current code: %s\n", code)

    // Validate code
    if err := auth.Authenticate(context.Background(), code); err != nil {
        log.Fatal(err)
    }
    fmt.Println("Authentication successful!")
}
```

### HOTP (Counter-based OTP)

```go
seed, err := otp.GenerateProtectedSecret()
if err != nil {
    log.Fatal(err)
}

auth, err := otp.NewAuthenticator(otp.Config{
    Type:        otp.TypeHOTP,
    Seed:        seed,
    Issuer:      "MyApp",
    AccountName: "user@example.com",
    Counter:     0,
})
if err != nil {
    log.Fatal(err)
}
defer auth.Close()

currentCounter := uint64(0)

// Generate code for current counter
code, _ := auth.Generate(currentCounter)

// Validate and get new counter
newCounter, err := auth.ValidateCounter(context.Background(), code, currentCounter)
if err != nil {
    log.Fatal(err)
}
currentCounter = newCounter // persist this
```

## Seeds and ownership

The seed — the shared HMAC key, RFC 4226's *K* — exists only inside a
`*enclave.MemoryEnclave` from [go-enclave](https://github.com/jeremyhahn/go-enclave):
locked, guard-paged, excluded from core dumps, and wiped on destroy. Codes are
derived from it inside the enclave's `WithBytes` borrow, for exactly as long as
one HMAC takes. There is no string form of the seed in the authenticator.

| You have | Build the seed with |
|---|---|
| Nothing — a new enrollment | `otp.GenerateProtectedSecret()` — 160 random bits written straight into locked pages |
| A stored base32 seed | `otp.DecodeSeed(stored)` — decoded straight into locked pages |
| Raw key bytes | `enclave.NewMemoryEnclave(b)` — takes ownership of and wipes `b` |

**Ownership.** `NewAuthenticator` takes ownership of `Config.Seed` on every
return path, the same contract `enclave.NewMemoryEnclave` has for its input: on
success `Close` destroys the seed, and on failure `NewAuthenticator` destroys it
before returning. Do not use or destroy a seed after handing it over. Two
authenticators over the same key need two enclaves (`DecodeSeed` the stored
value twice).

`Close` waits for in-flight calls to finish with the seed, wipes it, and is
idempotent. Afterwards every operation fails with an error matching
`enclave.ErrEnclaveDestroyed`.

A refusal to lock memory surfaces as `enclave.ErrLockedMemoryUnavailable` from
the seed constructors; there is no fallback to ordinary memory.

### Residue: where the seed becomes a string

Enrollment and storage genuinely need the base32 text, so two calls produce
it, each documented as a deliberate, unwipeable copy:

- `auth.ProvisioningURI()` — the `otpauth://` URI to render as a QR code.
- `otp.EncodeSecret(seed)` — the bare unpadded base32 seed, for persistence.

Both encode inside a locked scratch enclave and convert to a string only at
the end. Render or store the result and drop it; never log it.
`DecodeSeed`'s input is a string the caller already holds — that residue is the
caller's.

## Configuration

### Config Structure

```go
type Config struct {
    Type        Type                   // TypeTOTP or TypeHOTP (required)
    Seed        *enclave.MemoryEnclave // Shared key (required); ownership passes to NewAuthenticator
    Issuer      string                 // Issuing organization name
    AccountName string                 // Account identifier
    Digits      uint                   // 6, 7, or 8 (default: 6)
    Period      uint                   // TOTP: seconds per period (default: 30)
    Counter     uint64                 // HOTP: initial counter (default: 0)
    Algorithm   Algorithm              // SHA1, SHA256, or SHA512 (default: SHA1; must be set to SHA256/SHA512 under FIPS 140-only mode)
    Skew        uint                   // TOTP: time skew tolerance in periods (default: 1, max: 10)
}
```

### Configuration Examples

#### Minimal TOTP Configuration

```go
seed, err := otp.DecodeSeed(storedSeed)
if err != nil {
    return err
}
config := otp.Config{
    Type:        otp.TypeTOTP,
    Seed:        seed,
    Issuer:      "MyApp",
    AccountName: "user@example.com",
    // Uses defaults: 6 digits, SHA1, 30s period, skew=1
}
```

#### Custom TOTP Configuration

```go
config := otp.Config{
    Type:        otp.TypeTOTP,
    Seed:        seed,
    Issuer:      "MyApp",
    AccountName: "user@example.com",
    Digits:      8,                    // 8-digit codes
    Period:      60,                   // 60-second periods
    Algorithm:   otp.AlgorithmSHA256,  // SHA256
    Skew:        2,                    // Accept ±2 periods
}
```

## API Reference

### NewAuthenticator

```go
func NewAuthenticator(cfg Config) (*Authenticator, error)
```

Validates the configuration and takes ownership of `cfg.Seed` (see
[Seeds and ownership](#seeds-and-ownership)).

**Errors:**
- `ErrInvalidConfig`: Invalid configuration (nil or destroyed seed, bad type,
  digits, skew or algorithm)
- `ErrFIPSUnsupported` (also matches `ErrInvalidConfig`): SHA1, an omitted
  algorithm, or a seed under 112 bits, while the process runs under FIPS
  140-only mode

### Close

```go
func (a *Authenticator) Close() error
```

Destroys the seed. Idempotent. Returns go-enclave's teardown report (`nil`, or
`enclave.ErrReleasedWithoutWipe` when a sandbox denied the wipe's `mprotect`).

### Authenticate

```go
func (a *Authenticator) Authenticate(ctx context.Context, code string) error
```

Validates a code against the current time (TOTP, with skew) or the configured
counter (HOTP). Comparison is constant time, and a TOTP check evaluates every
step in the window whether or not one matches.

**Errors:**
- `ErrNilAuthenticator`: Called on nil authenticator
- `ErrInvalidCode`: Invalid code (also wraps `enclave.ErrEnclaveDestroyed` after `Close`)
- `context.Canceled` / `context.DeadlineExceeded`

### ValidateCounter (HOTP only)

```go
func (a *Authenticator) ValidateCounter(ctx context.Context, code string, counter uint64) (uint64, error)
```

Validates an HOTP code at `counter` and returns `counter + 1` to persist.

**Errors:** `ErrNilAuthenticator`, `ErrInvalidConfig` (TOTP authenticator),
`ErrInvalidCode`.

### Generate

```go
func (a *Authenticator) Generate(counter ...uint64) (string, error)
```

Generates the code for now (TOTP) or the given counter (HOTP).
`ErrCounterRequired` when an HOTP authenticator is given no counter.

### ProvisioningURI

```go
func (a *Authenticator) ProvisioningURI() (string, error)
```

Returns the `otpauth://` URI in the Google Authenticator Key URI Format. It
reports an error rather than a seed-less URI when the seed cannot be read.

```
otpauth://totp/MyApp:user@example.com?algorithm=SHA1&digits=6&issuer=MyApp&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
```

### GenerateProtectedSecret, DecodeSeed, EncodeSecret

```go
func GenerateProtectedSecret() (*enclave.MemoryEnclave, error)
func DecodeSeed(encoded string) (*enclave.MemoryEnclave, error)
func EncodeSecret(seed *enclave.MemoryEnclave) (string, error)
```

`DecodeSeed` accepts padded or unpadded, upper- or lower-case base32 and
rejects a trailing group too short to encode a whole byte (which Go's unpadded
decoder would otherwise drop silently). `EncodeSecret` borrows the seed and
leaves it alive.

## Error Handling

```go
var (
    ErrInvalidCode      = errors.New("otp: invalid code")
    ErrInvalidConfig    = errors.New("otp: invalid configuration")
    ErrExpiredCode      = errors.New("otp: code expired")
    ErrNilAuthenticator = errors.New("otp: authenticator is nil")
    ErrCounterRequired  = errors.New("otp: counter required for HOTP generation")
    ErrFIPSUnsupported  = errors.New("otp: unavailable under FIPS 140-only mode")
)
```

```go
err := auth.Authenticate(ctx, code)
switch {
case err == nil:
    // authenticated
case errors.Is(err, otp.ErrInvalidCode):
    fmt.Println("Invalid or expired code")
case errors.Is(err, context.Canceled):
    fmt.Println("Request cancelled")
default:
    fmt.Printf("Other error: %v\n", err)
}
```

## QR Code Generation

```go
import "github.com/skip2/go-qrcode"

uri, err := auth.ProvisioningURI()
if err != nil {
    return err // never render a seed-less enrollment
}
err = qrcode.WriteFile(uri, qrcode.Medium, 256, "qr.png")
```

## Security Considerations

### Seed Storage

- **Keep seeds in enclaves**: `GenerateProtectedSecret` / `DecodeSeed`; never hold the base32 text longer than the store or render that needs it
- **Never hardcode seeds**: Store them securely (database, secrets manager)
- **Use encrypted storage**: Encrypt seeds at rest
- **Rotate seeds**: Support re-enrollment for compromised accounts
- **Secure transmission**: Use TLS when transmitting provisioning URIs

### Clock Skew

- **Minimal skew**: Use `Skew: 1` (default) for balance between security and usability. `Skew` may not exceed 10: every extra step keeps a code valid for another period, and costs an HMAC per validation. Drift measured in minutes is a clock problem — run NTP
- **NTP synchronization**: Ensure server time is accurate
- **Monitor drift**: Alert on excessive time drift

### Algorithm Selection

- **SHA1 (default)**: Widely supported by authenticator apps; refused under FIPS 140-only mode
- **SHA256/SHA512**: Required under FIPS; may not work with all apps
- **Name the algorithm explicitly** in stored configuration: under FIPS 140-only mode an omitted algorithm is refused at construction
- **Test compatibility**: Verify with target authenticator apps

### Counter Management (HOTP)

- **Store counter securely**: Prevent counter reset attacks
- **Handle out-of-sync**: Implement counter resynchronization
- **Limit attempts**: Prevent brute-force attacks

## Best Practices

### TOTP

1. **Use standard period**: Stick with 30 seconds for compatibility
2. **Allow clock skew**: Use `Skew: 1` to handle clock drift
3. **Limit validation window**: Don't accept very old codes
4. **Rate limiting**: Prevent brute-force attacks
5. **Backup codes**: Provide recovery codes for lost devices

### HOTP

1. **Persist counter**: Store counter after successful validation
2. **Handle failures**: Don't increment counter on failed attempts
3. **Resynchronization**: Implement look-ahead window for out-of-sync counters
4. **Limit window**: Don't look too far ahead (prevent DoS)

### General

1. **Use HTTPS**: Always transmit codes over TLS
2. **One-time use**: Mark codes as used in TOTP (optional)
3. **Account lockout**: Implement after N failed attempts
4. **Audit logging**: Log authentication attempts — never seeds or URIs
5. **User education**: Provide clear setup instructions

## Integration Example

```go
func otpAuthHandler(w http.ResponseWriter, r *http.Request) {
    code := r.FormValue("code")

    // Load the user's stored seed and settings
    stored := getUserOTP(r.Context(), userID)
    seed, err := otp.DecodeSeed(stored.Seed)
    if err != nil {
        http.Error(w, "Invalid configuration", http.StatusInternalServerError)
        return
    }

    auth, err := otp.NewAuthenticator(otp.Config{
        Type:      otp.TypeTOTP,
        Seed:      seed, // owned by auth from here
        Algorithm: stored.Algorithm,
    })
    if err != nil {
        http.Error(w, "Invalid configuration", http.StatusInternalServerError)
        return
    }
    defer auth.Close()

    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()

    if err := auth.Authenticate(ctx, code); err != nil {
        http.Error(w, "Invalid code", http.StatusUnauthorized)
        return
    }
    w.WriteHeader(http.StatusOK)
}
```

## Testing

```bash
cd pkg/otp
make test
```

The suite includes the RFC 4226 Appendix D and RFC 6238 Appendix B vectors and
runs unchanged under `GOFIPS140=latest GODEBUG=fips140=only`.

## Examples

See the `examples/otp/` directory for complete examples:
- `totp_example.go`: TOTP authentication example
- `hotp_example.go`: HOTP authentication example

## References

- [RFC 6238: TOTP](https://www.rfc-editor.org/rfc/rfc6238)
- [RFC 4226: HOTP](https://www.rfc-editor.org/rfc/rfc4226)
- [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
- [go-enclave](https://github.com/jeremyhahn/go-enclave)

## License

See repository LICENSE file.
