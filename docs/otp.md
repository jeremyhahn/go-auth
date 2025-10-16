# OTP Authentication Package

The `otp` package provides TOTP (Time-based One-Time Password) and HOTP (HMAC-based One-Time Password) authentication following RFC 6238 and RFC 4226 respectively.

## Features

- **TOTP Support**: Time-based codes that change every 30 seconds (configurable)
- **HOTP Support**: Counter-based codes for hardware tokens
- **Multiple Hash Algorithms**: SHA1, SHA256, SHA512
- **Flexible Digit Lengths**: 6, 7, or 8 digit codes
- **Clock Skew Tolerance**: Configurable time window for TOTP validation
- **Provisioning URIs**: Generate `otpauth://` URIs for QR codes
- **Context Support**: All operations support context cancellation
- **Thread-Safe**: Safe for concurrent use
- **Zero Dependencies**: Only uses standard library and `github.com/pquerna/otp`

## Installation

```bash
go get github.com/jhahn/go-auth/pkg/otp
```

## Quick Start

### TOTP (Time-based OTP)

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/jhahn/go-auth/pkg/otp"
)

func main() {
    // Generate a secret
    secret, _ := otp.GenerateSecret()

    // Configure TOTP
    config := otp.Config{
        Type:        otp.TypeTOTP,
        Secret:      secret,
        Issuer:      "MyApp",
        AccountName: "user@example.com",
    }

    auth, err := otp.NewAuthenticator(config)
    if err != nil {
        log.Fatal(err)
    }

    // Generate current code
    code, _ := auth.Generate()
    fmt.Printf("Current code: %s\n", code)

    // Validate code
    ctx := context.Background()
    if err := auth.Authenticate(ctx, code); err != nil {
        log.Fatal(err)
    }
    fmt.Println("Authentication successful!")
}
```

### HOTP (Counter-based OTP)

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/jhahn/go-auth/pkg/otp"
)

func main() {
    secret, _ := otp.GenerateSecret()

    config := otp.Config{
        Type:        otp.TypeHOTP,
        Secret:      secret,
        Issuer:      "MyApp",
        AccountName: "user@example.com",
        Counter:     0,
    }

    auth, err := otp.NewAuthenticator(config)
    if err != nil {
        log.Fatal(err)
    }

    currentCounter := uint64(0)

    // Generate code for current counter
    code, _ := auth.Generate(currentCounter)

    // Validate and get new counter
    ctx := context.Background()
    newCounter, err := auth.ValidateCounter(ctx, code, currentCounter)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Authentication successful! New counter: %d\n", newCounter)
    currentCounter = newCounter
}
```

## Configuration

### Config Structure

```go
type Config struct {
    Type        Type      // TypeTOTP or TypeHOTP (required)
    Secret      string    // Base32-encoded secret (required)
    Issuer      string    // Issuing organization name
    AccountName string    // Account identifier
    Digits      uint      // 6, 7, or 8 (default: 6)
    Period      uint      // TOTP: seconds per period (default: 30)
    Counter     uint64    // HOTP: initial counter (default: 0)
    Algorithm   Algorithm // SHA1, SHA256, or SHA512 (default: SHA1)
    Skew        uint      // TOTP: time skew tolerance in periods (default: 1)
}
```

### Configuration Examples

#### Minimal TOTP Configuration

```go
config := otp.Config{
    Type:        otp.TypeTOTP,
    Secret:      "JBSWY3DPEHPK3PXP",
    Issuer:      "MyApp",
    AccountName: "user@example.com",
    // Uses defaults: 6 digits, SHA1, 30s period, skew=1
}
```

#### Custom TOTP Configuration

```go
config := otp.Config{
    Type:        otp.TypeTOTP,
    Secret:      "JBSWY3DPEHPK3PXP",
    Issuer:      "MyApp",
    AccountName: "user@example.com",
    Digits:      8,                    // 8-digit codes
    Period:      60,                   // 60-second periods
    Algorithm:   otp.AlgorithmSHA256,  // SHA256
    Skew:        2,                    // Accept ±2 periods
}
```

#### HOTP Configuration

```go
config := otp.Config{
    Type:        otp.TypeHOTP,
    Secret:      "JBSWY3DPEHPK3PXP",
    Issuer:      "MyApp",
    AccountName: "user@example.com",
    Counter:     0,                    // Initial counter
    Digits:      6,
    Algorithm:   otp.AlgorithmSHA1,
}
```

## API Reference

### NewAuthenticator

Creates a new OTP authenticator with the given configuration.

```go
func NewAuthenticator(cfg Config) (*Authenticator, error)
```

**Returns:**
- `*Authenticator`: The authenticator instance
- `error`: Configuration validation error

**Errors:**
- `ErrInvalidConfig`: Invalid configuration

### Authenticate

Validates an OTP code against the current time (TOTP) or configured counter (HOTP).

```go
func (a *Authenticator) Authenticate(ctx context.Context, code string) error
```

**Parameters:**
- `ctx`: Context for cancellation
- `code`: The OTP code to validate

**Returns:**
- `error`: `nil` if valid, `ErrInvalidCode` if invalid

**Errors:**
- `ErrNilAuthenticator`: Called on nil authenticator
- `ErrInvalidCode`: Invalid or expired code
- `context.Canceled`: Context was cancelled
- `context.DeadlineExceeded`: Context deadline exceeded

### ValidateCounter (HOTP only)

Validates an HOTP code and returns the new counter value.

```go
func (a *Authenticator) ValidateCounter(ctx context.Context, code string, counter uint64) (uint64, error)
```

**Parameters:**
- `ctx`: Context for cancellation
- `code`: The OTP code to validate
- `counter`: Current counter value

**Returns:**
- `uint64`: New counter value (counter + 1)
- `error`: Validation error

**Errors:**
- `ErrNilAuthenticator`: Called on nil authenticator
- `ErrInvalidConfig`: Called on TOTP authenticator
- `ErrInvalidCode`: Invalid code for given counter

### Generate

Generates an OTP code for the current time (TOTP) or specified counter (HOTP).

```go
func (a *Authenticator) Generate(counter ...uint64) (string, error)
```

**Parameters:**
- `counter`: Required for HOTP, ignored for TOTP

**Returns:**
- `string`: Generated OTP code
- `error`: Generation error

### GetProvisioningURI

Returns the `otpauth://` URI for QR code generation.

```go
func (a *Authenticator) GetProvisioningURI() string
```

**Returns:**
- `string`: Provisioning URI (empty for nil authenticator)

**Example URI:**
```
otpauth://totp/MyApp:user@example.com?algorithm=SHA1&digits=6&issuer=MyApp&period=30&secret=JBSWY3DPEHPK3PXP
```

### GenerateSecret

Generates a cryptographically random secret key.

```go
func GenerateSecret() (string, error)
```

**Returns:**
- `string`: Base32-encoded secret (20 bytes)
- `error`: Generation error

## Error Handling

The package defines the following error types:

```go
var (
    ErrInvalidCode      = errors.New("otp: invalid code")
    ErrInvalidConfig    = errors.New("otp: invalid configuration")
    ErrExpiredCode      = errors.New("otp: code expired")
    ErrNilAuthenticator = errors.New("otp: authenticator is nil")
)
```

### Error Checking

```go
err := auth.Authenticate(ctx, code)
if err != nil {
    if errors.Is(err, otp.ErrInvalidCode) {
        fmt.Println("Invalid or expired code")
    } else if errors.Is(err, context.Canceled) {
        fmt.Println("Request cancelled")
    } else {
        fmt.Printf("Other error: %v\n", err)
    }
}
```

## QR Code Generation

To generate QR codes for mobile authenticator apps:

```go
import "github.com/skip2/go-qrcode"

// Get provisioning URI
uri := auth.GetProvisioningURI()

// Generate QR code
err := qrcode.WriteFile(uri, qrcode.Medium, 256, "qr.png")
```

## Security Considerations

### Secret Storage

- **Never hardcode secrets**: Store them securely (database, secrets manager)
- **Use encrypted storage**: Encrypt secrets at rest
- **Rotate secrets**: Support secret rotation for compromised accounts
- **Secure transmission**: Use TLS when transmitting secrets

### Clock Skew

- **Minimal skew**: Use `Skew: 1` (default) for balance between security and usability
- **NTP synchronization**: Ensure server time is accurate
- **Monitor drift**: Alert on excessive time drift

### Algorithm Selection

- **SHA1 (default)**: Widely supported by authenticator apps
- **SHA256/SHA512**: More secure but may not work with all apps
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
4. **Audit logging**: Log authentication attempts
5. **User education**: Provide clear setup instructions

## Integration Examples

### With HTTP Server

```go
func otpAuthHandler(w http.ResponseWriter, r *http.Request) {
    code := r.FormValue("code")

    // Get user's OTP configuration from database
    config := getUserOTPConfig(r.Context(), userID)

    auth, err := otp.NewAuthenticator(config)
    if err != nil {
        http.Error(w, "Invalid configuration", http.StatusInternalServerError)
        return
    }

    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()

    if err := auth.Authenticate(ctx, code); err != nil {
        http.Error(w, "Invalid code", http.StatusUnauthorized)
        return
    }

    // Authentication successful
    w.WriteHeader(http.StatusOK)
}
```

### Two-Factor Authentication

```go
func twoFactorAuth(username, password, otpCode string) error {
    // Step 1: Validate username/password
    user, err := validateCredentials(username, password)
    if err != nil {
        return err
    }

    // Step 2: Validate OTP
    if user.OTPEnabled {
        auth, err := otp.NewAuthenticator(user.OTPConfig)
        if err != nil {
            return err
        }

        if err := auth.Authenticate(context.Background(), otpCode); err != nil {
            return fmt.Errorf("invalid OTP code: %w", err)
        }
    }

    return nil
}
```

## Testing

The package includes comprehensive tests with 95%+ coverage.

Run tests:
```bash
cd pkg/otp
make test
```

Run with coverage:
```bash
cd pkg/otp
make coverage
```

## Examples

See the `examples/otp/` directory for complete examples:
- `totp_example.go`: TOTP authentication example
- `hotp_example.go`: HOTP authentication example

## References

- [RFC 6238: TOTP](https://tools.ietf.org/html/rfc6238)
- [RFC 4226: HOTP](https://tools.ietf.org/html/rfc4226)
- [Google Authenticator](https://github.com/google/google-authenticator)
- [otpauth URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)

## License

See repository LICENSE file.
