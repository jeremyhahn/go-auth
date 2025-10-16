# PKCS#11 Authentication Package

The `pkcs11` package provides authentication using hardware security modules (HSMs), smart cards, and other cryptographic tokens via the PKCS#11 (Cryptoki) standard interface.

## Overview

PKCS#11 (Public-Key Cryptography Standards #11) defines a platform-independent API for cryptographic tokens. This package enables authentication by validating PINs against hardware tokens such as:

- Hardware Security Modules (HSMs) - SafeNet, Thales, Utimaco
- Smart Cards - PIV, CAC, YubiKey PIV
- USB Cryptographic Tokens - YubiKey, Nitrokey
- Software HSMs - SoftHSM (for testing)

Authentication verifies that the user can unlock the token with the correct PIN, proving possession of the hardware device.

## Architecture

The module uses an interface-based design for testability:

```
┌─────────────────┐
│  Authenticator  │
└────────┬────────┘
         │
         ▼
  ┌──────────────┐      ┌─────────────────┐
  │    Config    │      │ SessionProvider │
  └──────────────┘      └────────┬────────┘
                                 │
                                 ▼
                          ┌─────────────┐
                          │   Session   │
                          └─────────────┘
```

### Components

- **Config**: PKCS#11 module path and token identification
- **SessionProvider**: Interface for creating PKCS#11 sessions (enables testing)
- **Session**: Interface for token login operations
- **Authenticator**: Main authentication orchestrator

## Features

- PKCS#11 token authentication
- Support for multiple token types (HSMs, smart cards, USB tokens)
- Flexible token selection (by label or slot)
- Interface-based design for testing
- Context-aware operation
- Thread-safe concurrent usage
- Automatic session cleanup

## Quick Start

### Basic Authentication

```go
package main

import (
    "context"
    "log"

    "github.com/jhahn/go-auth/pkg/pkcs11"
)

func main() {
    // Configure PKCS#11
    cfg := pkcs11.Config{
        ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
        TokenLabel: "MyToken",
    }

    // Create authenticator (with real provider)
    // Note: requires building with PKCS#11 support
    auth, err := pkcs11.NewAuthenticator(cfg, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Authenticate with PIN
    ctx := context.Background()
    err = auth.Authenticate(ctx, "1234")
    if err == pkcs11.ErrInvalidPIN {
        log.Println("Invalid PIN")
        return
    }
    if err != nil {
        log.Printf("Error: %v", err)
        return
    }

    log.Println("Authentication successful")
}
```

### Select by Slot ID

```go
// Use specific slot instead of token label
cfg := pkcs11.Config{
    ModulePath: "/usr/lib/pkcs11/opensc-pkcs11.so",
    Slot:       "0",
}

auth, err := pkcs11.NewAuthenticator(cfg, nil)
```

### Custom Session Provider

For testing or custom token implementations:

```go
// Implement custom provider
type MyProvider struct{}

func (p *MyProvider) Open(ctx context.Context, cfg pkcs11.Config) (pkcs11.Session, error) {
    // Custom session creation logic
    return &MySession{}, nil
}

// Use custom provider
provider := &MyProvider{}
auth, err := pkcs11.NewAuthenticator(cfg, provider)
```

## Configuration

### Config Structure

```go
type Config struct {
    ModulePath string  // Path to PKCS#11 module library
    TokenLabel string  // Token label for identification
    Slot       string  // Slot ID (alternative to TokenLabel)
}
```

### Module Paths

Common PKCS#11 module locations:

**SoftHSM (testing):**
```go
ModulePath: "/usr/lib/softhsm/libsofthsm2.so"  // Linux
ModulePath: "/usr/local/lib/softhsm/libsofthsm2.so"  // macOS
```

**OpenSC (smart cards):**
```go
ModulePath: "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"  // Linux
ModulePath: "/Library/OpenSC/lib/opensc-pkcs11.so"  // macOS
```

**YubiKey:**
```go
ModulePath: "/usr/local/lib/libykcs11.so"  // Linux/macOS
ModulePath: "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll"  // Windows
```

**Hardware HSM vendors:**
```go
ModulePath: "/opt/safenet/lunaclient/lib/libCryptoki2_64.so"  // SafeNet Luna
ModulePath: "/opt/nfast/toolkits/pkcs11/libcknfast.so"  // Thales nShield
```

### Token Selection

**By Label:**
```go
cfg := pkcs11.Config{
    ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
    TokenLabel: "MyToken",  // Token's label
}
```

**By Slot:**
```go
cfg := pkcs11.Config{
    ModulePath: "/usr/lib/opensc-pkcs11.so",
    Slot:       "0",  // Slot ID as string
}
```

Either `TokenLabel` or `Slot` must be specified (not both).

## Authentication Flow

1. **Validate configuration** - Check module path and token identifier
2. **Open PKCS#11 session** - Connect to token via provider
3. **Login to token** - Validate PIN
4. **Logout from token** - Clean up session (even on error)

## Error Handling

```go
err := auth.Authenticate(ctx, "1234")

switch {
case err == nil:
    // Success
    log.Println("Token unlocked")

case errors.Is(err, pkcs11.ErrInvalidPIN):
    // Wrong PIN
    log.Println("Invalid PIN - attempt will be counted")
    // Note: Multiple failures may lock the token

case errors.Is(err, context.Canceled):
    // Context cancelled
    log.Println("Operation cancelled")

case errors.Is(err, context.DeadlineExceeded):
    // Timeout
    log.Println("Operation timed out")

default:
    // Other errors (token not found, module error, etc.)
    log.Printf("Error: %v", err)
}
```

### Configuration Errors

```go
// Empty module path
cfg := pkcs11.Config{TokenLabel: "token"}
auth, err := pkcs11.NewAuthenticator(cfg, nil)
// Error: "pkcs11: module path must not be empty"

// Missing token identifier
cfg := pkcs11.Config{ModulePath: "/path/to/module.so"}
auth, err := pkcs11.NewAuthenticator(cfg, nil)
// Error: "pkcs11: either token label or slot must be specified"

// Empty PIN
err := auth.Authenticate(ctx, "")
// Error: "pkcs11: pin must not be empty"
```

### Provider Errors

```go
// No system provider available (not built with PKCS#11)
auth, err := pkcs11.NewAuthenticator(cfg, nil)
// Error: "pkcs11: system provider unavailable; build with PKCS#11 support"
```

## Build Requirements

### With PKCS#11 Support

Requires PKCS#11 libraries and build tags:

```bash
# Install PKCS#11 development libraries
# Debian/Ubuntu:
sudo apt-get install libpcsclite-dev

# RHEL/CentOS/Fedora:
sudo dnf install pcsc-lite-devel

# Build with PKCS#11 support
go build -tags pkcs11
```

### Without PKCS#11 Support (Testing)

For testing with mock providers:

```bash
# Build without PKCS#11
go build
```

## Testing

### Mock Session Provider

```go
type MockProvider struct {
    session *MockSession
    err     error
}

func (m *MockProvider) Open(ctx context.Context, cfg pkcs11.Config) (pkcs11.Session, error) {
    if m.err != nil {
        return nil, m.err
    }
    return m.session, nil
}

type MockSession struct {
    loginErr  error
    logoutErr error
}

func (m *MockSession) Login(ctx context.Context, pin string) error {
    return m.loginErr
}

func (m *MockSession) Logout(ctx context.Context) error {
    return m.logoutErr
}

// Use in tests
func TestAuthentication(t *testing.T) {
    mockSession := &MockSession{}
    mockProvider := &MockProvider{session: mockSession}

    cfg := pkcs11.Config{
        ModulePath: "/path/to/module.so",
        TokenLabel: "test",
    }

    auth, err := pkcs11.NewAuthenticator(cfg, mockProvider)
    if err != nil {
        t.Fatal(err)
    }

    err = auth.Authenticate(context.Background(), "1234")
    // ... assertions
}
```

### System Provider

Set a default system provider for production use:

```go
// In production initialization code
realProvider := NewRealPKCS11Provider()
pkcs11.SetSystemSessionProvider(realProvider)

// Later, create authenticators without explicit provider
auth, err := pkcs11.NewAuthenticator(cfg, nil)
```

## Context Management

### With Timeout

```go
import "time"

ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

err := auth.Authenticate(ctx, "1234")
if err == context.DeadlineExceeded {
    log.Println("Token authentication timed out")
}
```

### With Cancellation

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

go func() {
    <-sigChan
    cancel() // Cancel on signal
}()

err := auth.Authenticate(ctx, "1234")
```

## Integration with go-auth API

```go
import (
    "github.com/jhahn/go-auth/pkg/api"
    "github.com/jhahn/go-auth/pkg/pkcs11"
)

cfg := pkcs11.Config{
    ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
    TokenLabel: "AuthToken",
}

pkcs11Auth, _ := pkcs11.NewAuthenticator(cfg, nil)

service, _ := api.NewService(api.Config{
    Backends: []api.Backend{
        {Name: api.BackendPKCS11, Handler: api.PKCS11(pkcs11Auth)},
    },
})

// Authenticate (PIN passed as password)
err := service.Login(ctx, api.LoginRequest{
    Backend:  api.BackendPKCS11,
    Password: "1234",  // Token PIN
})
```

## Hardware Token Examples

### SoftHSM (Testing)

```bash
# Initialize SoftHSM
softhsm2-util --init-token --slot 0 --label "TestToken" --pin 1234 --so-pin 5678

# Use in Go
cfg := pkcs11.Config{
    ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
    TokenLabel: "TestToken",
}
```

### YubiKey PIV

```bash
# YubiKey PIV uses PIN for authentication
cfg := pkcs11.Config{
    ModulePath: "/usr/local/lib/libykcs11.so",
    Slot:       "0",  // YubiKey slot
}

# Default YubiKey PIV PIN is 123456
err := auth.Authenticate(ctx, "123456")
```

### Smart Card (OpenSC)

```go
// Smart card with OpenSC
cfg := pkcs11.Config{
    ModulePath: "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    Slot:       "0",  // First reader slot
}

// User PIN (typically 4-8 digits)
err := auth.Authenticate(ctx, "1234")
```

### Hardware HSM

```go
// SafeNet Luna HSM
cfg := pkcs11.Config{
    ModulePath: "/usr/safenet/lunaclient/lib/libCryptoki2_64.so",
    TokenLabel: "partition1",
}

// HSM partition password
err := auth.Authenticate(ctx, "partition-password")
```

## Security Considerations

### PIN Security

1. **PIN strength** - Enforce minimum length and complexity
2. **PIN storage** - Never store PINs in plaintext
3. **PIN transmission** - Use secure channels
4. **Failed attempts** - Monitor and implement rate limiting
5. **Token lockout** - Most tokens lock after 3-5 failed attempts

### Token Lockout

Tokens typically lock after failed PIN attempts:
- **Smart cards**: Usually 3 attempts
- **HSMs**: Configurable (3-10 attempts)
- **YubiKey PIV**: 3 attempts before PIN blocked

Unlock requires:
- PUK (PIN Unlock Key) for smart cards
- SO-PIN (Security Officer PIN) for HSMs
- Administrator intervention

### Best Practices

1. **Limit login attempts** - Implement application-level rate limiting
2. **Monitor authentication** - Log all attempts
3. **Secure module files** - Protect PKCS#11 library files
4. **Token physical security** - Secure token storage
5. **Regular audits** - Review token usage logs
6. **Backup strategies** - Have recovery procedures for locked tokens

### Two-Factor Authentication

PKCS#11 tokens provide strong two-factor authentication:
- **Something you have**: The physical token
- **Something you know**: The PIN

Combined with username/password provides three-factor authentication.

## Performance

### Benchmark Results

Typical authentication latency:
- Software HSM (SoftHSM): 50-200ms
- Smart card: 100-500ms
- USB token: 50-300ms
- Hardware HSM (network): 100-1000ms

Performance factors:
- Token type and generation
- USB interface speed
- Network latency (for networked HSMs)
- PKCS#11 module implementation

### Optimization

- **Session reuse** - Minimize session creation overhead
- **Connection pooling** - For networked HSMs
- **Parallel authentication** - Token operations are often serialized
- **Token selection** - Use fastest available tokens

## Troubleshooting

### Module Not Found

```
Error: cannot load PKCS#11 module
```

Causes:
- Incorrect module path
- Missing PKCS#11 library
- Incorrect architecture (32-bit vs 64-bit)

Solutions:
1. Verify module exists: `ls -l /path/to/module.so`
2. Check architecture: `file /path/to/module.so`
3. Install required packages
4. Use correct path for your OS

### Token Not Found

```
Error: token not found
```

Causes:
- Token not inserted
- Incorrect token label
- Incorrect slot number
- Token not initialized

Solutions:
1. List tokens: `pkcs11-tool --module /path/to/module.so --list-tokens`
2. Verify token label matches configuration
3. Check token is properly inserted/connected
4. Initialize token if needed

### Invalid PIN

```
Error: pkcs11: invalid PIN
```

Causes:
- Wrong PIN entered
- Token locked from previous failed attempts
- PIN not initialized

Solutions:
1. Verify correct PIN
2. Check token lock status
3. Unlock with PUK/SO-PIN if locked
4. Reinitialize token if necessary (WARNING: destroys keys)

### Token Locked

```
Error: CKR_PIN_LOCKED
```

Token is locked due to excessive failed attempts.

Solutions:
1. Smart card: Use PUK to unlock
   ```bash
   pkcs11-tool --module /path/to/module.so --login --login-type so --pin <PUK> --change-pin
   ```

2. SoftHSM: Use SO-PIN
   ```bash
   pkcs11-tool --module /path/to/module.so --login --login-type so --pin <SO-PIN> --init-pin --new-pin <NEW-PIN>
   ```

3. Hardware HSM: Contact administrator

### Session Errors

```
Error: CKR_SESSION_HANDLE_INVALID
```

Causes:
- Token removed during operation
- Session timeout
- Module error

Solutions:
1. Ensure token remains connected
2. Recreate authenticator
3. Check token and module logs

## Advanced Usage

### Multi-Token Support

Handle multiple tokens in one application:

```go
tokens := []pkcs11.Config{
    {ModulePath: "/usr/lib/softhsm/libsofthsm2.so", TokenLabel: "Token1"},
    {ModulePath: "/usr/lib/softhsm/libsofthsm2.so", TokenLabel: "Token2"},
}

for _, cfg := range tokens {
    auth, err := pkcs11.NewAuthenticator(cfg, nil)
    if err != nil {
        log.Printf("Token %s unavailable: %v", cfg.TokenLabel, err)
        continue
    }

    err = auth.Authenticate(ctx, pin)
    if err == nil {
        log.Printf("Authenticated with %s", cfg.TokenLabel)
        break
    }
}
```

### Token Discovery

List available tokens:

```bash
# Using pkcs11-tool
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-slots
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-tokens
```

### Concurrent Authentication

Authenticators are thread-safe:

```go
auth, _ := pkcs11.NewAuthenticator(cfg, nil)

// Safe to use from multiple goroutines
var wg sync.WaitGroup
for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(pin string) {
        defer wg.Done()
        err := auth.Authenticate(ctx, pin)
        // ... handle result
    }("1234")
}
wg.Wait()
```

Note: Some PKCS#11 modules may serialize operations internally.

## Integration Tests

Run integration tests with SoftHSM:

```bash
# Install SoftHSM
sudo apt-get install softhsm2

# Initialize test token
softhsm2-util --init-token --slot 0 --label "TestToken" --pin 1234 --so-pin 5678

# Export configuration
export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export PKCS11_TOKEN_LABEL=TestToken
export PKCS11_PIN=1234

# Run integration tests
cd test/integration/auth
go test -v -run TestSoftHSM
```

Integration tests validate:
- Token connection
- PIN validation
- Invalid PIN handling
- Session cleanup
- Error conditions

## References

- [PKCS#11 v2.40 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
- [SoftHSM Documentation](https://www.opendnssec.org/softhsm/)
- [OpenSC PKCS#11](https://github.com/OpenSC/OpenSC/wiki)
- [YubiKey PIV](https://developers.yubico.com/PIV/)
- [PKCS#11 Tools](https://github.com/OpenSC/libp11)
