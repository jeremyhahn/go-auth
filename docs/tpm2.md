# TPM 2.0 Authentication Module

> **Status: NORMATIVE** · Scope: go-auth · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.

The `tpm2` package provides hardware-based authentication using TPM 2.0 devices. It implements platform integrity verification by unsealing secrets that are sealed to specific Platform Configuration Register (PCR) values.

## Overview

TPM 2.0 authentication provides cryptographic assurance that a system is in a known, trusted state before releasing secrets. This is achieved through:

1. **Sealing**: During provisioning, secrets are sealed to specific PCR values representing trusted platform state
2. **Unsealing**: During authentication, the TPM validates current PCR values match the sealed policy
3. **Verification**: If validation succeeds, the secret is unsealed; otherwise authentication fails

## Architecture

The module follows the established pattern from other auth modules (pkcs11, yubikey):

```
┌─────────────────┐
│  Authenticator  │
└────────┬────────┘
         │
         ▼
    ┌─────────┐      ┌──────────────┐
    │ Config  │      │ TPMProvider  │
    └─────────┘      └──────┬───────┘
                            │
                            ▼
                     ┌──────────────┐
                     │  TPMSession  │
                     └──────────────┘
```

### Components

- **Config**: Configuration for TPM device and sealed object
- **TPMProvider**: Interface for creating TPM sessions (enables testing)
- **TPMSession**: Interface for TPM operations (unseal, close)
- **Authenticator**: Main authentication orchestrator

## Configuration

```go
type Config struct {
    DevicePath    string  // Path to TPM device
    SealedHandle  Handle  // Handle to sealed object
    PCRSelection  []int   // PCR registers to verify
    HashAlgorithm string  // Hash algorithm (default: SHA256)
}
```

### Device Paths

- `/dev/tpm0` - Character device (exclusive access required)
- `/dev/tpmrm0` - Resource manager (recommended for concurrent access)
- Simulator devices for testing

### PCR Selection

Choose PCRs that measure critical platform components:

- **PCR 0-7**: BIOS/UEFI and boot components
- **PCR 8-15**: Operating system and applications
- **PCR 16-23**: Debug and testing

Common selections:
- Boot integrity: `[]int{0, 1, 7}` (firmware, config, secure boot)
- Full platform: `[]int{0, 1, 2, 3, 4, 5, 6, 7}` (complete boot chain)
- OS state: `[]int{8, 9}` (boot loader, OS kernel)

### Hash Algorithms

Supported algorithms:
- `SHA1` - Legacy support (not recommended)
- `SHA256` - Default, widely supported
- `SHA384` - Enhanced security
- `SHA512` - Maximum security

## Usage

### Basic Authentication

```go
package main

import (
    "context"
    "errors"
    "log"

    enclave "github.com/jeremyhahn/go-enclave"

    "github.com/jeremyhahn/go-auth/pkg/tpm2"
)

func main() {
    // Configure TPM authenticator
    cfg := tpm2.Config{
        DevicePath:   "/dev/tpmrm0",
        SealedHandle: 0x81000000,
        PCRSelection: []int{0, 1, 7},
    }

    // Create authenticator with a provider. The package ships none; the
    // host application supplies one (see Real Provider Implementation).
    provider := NewRealTPMProvider() // Implementation not shown
    auth, err := tpm2.NewAuthenticator(cfg, provider)
    if err != nil {
        log.Fatal(err)
    }

    // The authorization value travels in go-enclave locked memory. Build it
    // with enclave.NewMemoryEnclave from the bytes you read (that wipes
    // them); NewMemoryEnclave([]byte(s)) is for values that only exist as
    // strings.
    password, err := enclave.NewMemoryEnclave([]byte("password123"))
    if err != nil {
        log.Fatal(err) // enclave.ErrLockedMemoryUnavailable: fail closed
    }
    defer password.Destroy() // Authenticate only borrows it

    // Authenticate
    ctx := context.Background()
    err = auth.Authenticate(ctx, password)
    if errors.Is(err, tpm2.ErrPCRMismatch) {
        log.Fatal("Platform integrity check failed")
    } else if errors.Is(err, tpm2.ErrInvalidPassword) {
        log.Fatal("Invalid password")
    } else if err != nil {
        log.Fatal(err)
    }

    log.Println("Authentication successful")
}
```

In the snippets below, `password` is a `*enclave.MemoryEnclave` the caller
owns (see [Credentials](credentials.md)). `Authenticate` borrows it, and
destroys the unsealed data the session returns before it returns, on every
path.

### Error Handling

```go
err := auth.Authenticate(ctx, password)

switch {
case errors.Is(err, tpm2.ErrTPMUnavailable):
    // TPM device not accessible
    log.Println("TPM hardware not available")

case errors.Is(err, tpm2.ErrPCRMismatch):
    // PCR values don't match sealed policy
    log.Println("Platform state changed - integrity check failed")
    // May indicate firmware update, configuration change, or compromise

case errors.Is(err, tpm2.ErrInvalidPassword):
    // Password/authorization failed
    log.Println("Authentication failed - invalid credentials")

case errors.Is(err, context.Canceled):
    // Context cancelled
    log.Println("Operation cancelled")

case errors.Is(err, context.DeadlineExceeded):
    // Context timeout
    log.Println("Operation timed out")

default:
    log.Printf("Unexpected error: %v", err)
}
```

### Using System Provider

```go
// Set default provider once at application startup
provider := NewRealTPMProvider()
tpm2.SetSystemTPMProvider(provider)

// Create authenticators without explicit provider
auth, err := tpm2.NewAuthenticator(cfg, nil)
// With no provider installed: "tpm2: system provider unavailable; configure a TPM provider"
```

### Configuration Errors

`NewAuthenticator` validates the configuration before it looks at the provider:

- `tpm2: device path must not be empty`
- `tpm2: sealed handle must be specified` (a zero `SealedHandle`)
- `tpm2: at least one PCR must be selected`
- `tpm2: PCR <n> is invalid; must be between 0 and 23`
- `tpm2: unsupported hash algorithm: <name>`

`Authenticate` returns `tpm2.ErrEmptyPassword` for a nil or destroyed password
enclave and `tpm2.ErrNilAuthenticator` on a nil authenticator.

### Context Management

```go
// With timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
err := auth.Authenticate(ctx, password)

// With cancellation
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

go func() {
    // Cancel on signal
    <-sigChan
    cancel()
}()

err := auth.Authenticate(ctx, password)
```

## Testing

The module uses interface-based design for testability:

```go
type MockProvider struct {
    unsealErr error
    unsealData []byte
}

func (m *MockProvider) Open(ctx context.Context, cfg Config) (TPMSession, error) {
    return &MockSession{
        unsealErr: m.unsealErr,
        unsealData: m.unsealData,
    }, nil
}

type MockSession struct {
    unsealErr error
    unsealData []byte
}

// Unseal borrows password and returns the unsealed data in an enclave the
// caller (the authenticator) owns and destroys.
func (m *MockSession) Unseal(ctx context.Context, handle Handle, password *enclave.MemoryEnclave) (*enclave.MemoryEnclave, error) {
    if m.unsealErr != nil {
        return nil, m.unsealErr
    }
    return enclave.NewMemoryEnclaveCopy(m.unsealData)
}

func (m *MockSession) Close(ctx context.Context) error {
    return nil
}

// Use in tests
func TestMyCode(t *testing.T) {
    mockProvider := &MockProvider{
        unsealData: []byte("test-secret"),
    }

    cfg := tpm2.Config{
        DevicePath:   "/dev/tpm0",
        SealedHandle: 0x81000000,
        PCRSelection: []int{0},
    }

    auth, err := tpm2.NewAuthenticator(cfg, mockProvider)
    // ... test authentication
}
```

## Implementation Notes

### Real Provider Implementation

A real TPM provider uses `github.com/google/go-tpm/tpm2` and its `transport`
package; `tpm2auth` below is this package, imported as
`tpm2auth "github.com/jeremyhahn/go-auth/pkg/tpm2"`. The sketch is not
compiled; the integration test
`test/integration/tpm2/tpm2_integration_test.go` holds a complete provider:

```go
type RealTPMProvider struct{}

func (p *RealTPMProvider) Open(ctx context.Context, cfg tpm2auth.Config) (tpm2auth.TPMSession, error) {
    // Open TPM device
    tpm, err := transport.OpenTPM(cfg.DevicePath)
    if err != nil {
        return nil, tpm2auth.ErrTPMUnavailable
    }

    return &RealTPMSession{
        transport: tpm,
        handle: cfg.SealedHandle,
        // ... configure PCR policy
    }, nil
}

type RealTPMSession struct {
    transport transport.TPMCloser
    handle tpm2auth.Handle
}

func (s *RealTPMSession) Unseal(ctx context.Context, handle tpm2auth.Handle, password *enclave.MemoryEnclave) (*enclave.MemoryEnclave, error) {
    // Borrow the authorization value only for the command:
    //   password.WithBytes(func(auth []byte) error {
    //       rsp, err = tpm2.Unseal{ItemHandle: tpm2.AuthHandle{..., Auth: tpm2.PasswordAuth(auth)}}.Execute(s.transport)
    //       ...
    //   })
    // The unseal operation automatically validates PCR policy
    // Return tpm2auth.ErrPCRMismatch if PCR policy validation fails
    // Return tpm2auth.ErrInvalidPassword if password is wrong
    //
    // Move the response straight into locked memory: NewMemoryEnclave wipes
    // go-tpm's response buffer, so the plaintext never stays on the heap.
    //   return enclave.NewMemoryEnclave(rsp.OutData.Buffer)
}

func (s *RealTPMSession) Close(ctx context.Context) error {
    return s.transport.Close()
}
```

### Sealing Data (Provisioning)

Data must be sealed during provisioning:

```bash
# Example using tpm2-tools
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2_pcrread sha256:0,1,7 -o pcr.dat
tpm2_createpolicy --policy-pcr -l sha256:0,1,7 -f pcr.dat -L policy.dat
tpm2_create -C primary.ctx -g sha256 -G keyedhash -r sealed.priv -u sealed.pub \
    -L policy.dat -i secret.txt
tpm2_load -C primary.ctx -r sealed.priv -u sealed.pub -c sealed.ctx
tpm2_evictcontrol -C o -c sealed.ctx 0x81000000
```

## Security Considerations

### PCR Selection

- Choose PCRs measuring critical components (firmware, boot loader, OS)
- Avoid PCRs that change frequently (reduces operational complexity)
- Consider PCRs that detect configuration changes (secure boot, boot order)

### Updates and Resealing

PCR values change with firmware/software updates:

1. Perform trusted update
2. Record new PCR values
3. Reseal secrets to new PCR values
4. Deploy updated sealed objects

### Concurrent Access

- Use `/dev/tpmrm0` (resource manager) for concurrent access
- Each authentication opens a new session
- Sessions are properly closed (defer pattern)

### Password/Authorization

- The authorization value is a `*enclave.MemoryEnclave`, borrowed by
  `Authenticate` and lent to the session's `Unseal`; it is never a string
- The unsealed data comes back in an enclave and is destroyed before
  `Authenticate` returns, including when the session returns it alongside an
  error
- Passwords protect sealed objects from unauthorized unsealing
- Use strong passwords/authorization values
- Consider enhanced authorization (HMAC sessions, policy sessions)

### Handle Security

- Protect persistent handles (0x81xxxxxx) from unauthorized access
- Use TPM owner authorization to control handle creation
- Consider using transient handles for ephemeral operations

## Performance

### Optimization

- Reuse authenticator instances (thread-safe for concurrent use)
- Use resource manager (`/dev/tpmrm0`) to avoid session conflicts
- Pre-validate configuration at startup
- Consider caching unsealed secrets (balance security vs performance)

## Troubleshooting

### TPM Unavailable

```
Error: tpm2: device unavailable
```

Causes:
- TPM device doesn't exist (`ls /dev/tpm*`)
- Insufficient permissions (`sudo` or add user to `tss` group)
- TPM disabled in BIOS
- Another process has exclusive access

### PCR Mismatch

```
Error: tpm2: pcr policy validation failed
```

Causes:
- Firmware updated (PCR 0-7 changed)
- Boot configuration changed (PCR 1, 7)
- OS updated (PCR 8-9)
- System state differs from when sealed

Resolution:
- Verify change is legitimate
- Reseal data to new PCR values

### Invalid Password

```
Error: tpm2: invalid authorization
```

Causes:
- Wrong password provided
- Sealed object created with different authorization

## Integration Tests

The integration tests (build tag `integration`, in `test/integration/tpm2`)
need a TPM or simulator. `make tpm2-integration-test` builds and runs them in
Docker:

```bash
make tpm2-integration-test
```

## References

- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [go-tpm Library](https://github.com/google/go-tpm)
- [tpm2-tools](https://github.com/tpm2-software/tpm2-tools)
- [PCR Allocation](https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf)
