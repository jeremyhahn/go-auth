# TACACS+ Authentication Package

> **Status: NORMATIVE** · Scope: go-auth · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.

The `tacacs` package provides Terminal Access Controller Access-Control System Plus (TACACS+) authentication for network device access control and centralized AAA (Authentication, Authorization, and Accounting).

## Overview

TACACS+ is a Cisco-developed protocol that provides centralized authentication, authorization, and accounting services. This package implements the authentication component, supporting:

- ASCII login authentication
- Interactive challenge-response flows
- Configurable privilege levels
- Encrypted communication (all packet data encrypted)
- Context-aware operation with timeout support

> **Not available in FIPS 140-3 deployments.** TACACS+ obfuscates every packet
> body with an MD5 keystream (RFC 8907 §4.5), the only body encoding the
> protocol defines, so this backend cannot run under `GODEBUG=fips140=only`.
> The backend is in every build; when FIPS is activated, `NewAuthenticator`
> returns `tacacs.ErrFIPSUnsupported` instead of constructing it (and destroys
> the shared secret it was handed). Check for it with `errors.Is`.
> See [FIPS 140-3 compliance](fips.md).

TACACS+ is commonly used for:
- Network device administration (routers, switches, firewalls)
- Privileged access management
- Centralized credential management
- Audit logging of administrative access

## Features

- Full TACACS+ authentication protocol support
- Interactive session handling (prompts for username/password)
- Configurable privilege levels
- Encrypted packet communication
- Timeout configuration for operations
- Thread-safe concurrent usage
- Context-aware with cancellation support

## Quick Start

Credentials are go-enclave `*enclave.MemoryEnclave` values, never strings
(see [Credentials](credentials.md)). In the snippets after the first,
`sharedSecret` is an enclave handed to `NewAuthenticator`, which **takes
ownership** of it — every authenticator needs its own — and `password` is one
the caller owns and `Authenticate` borrows.

### Basic Authentication

```go
package main

import (
    "context"
    "errors"
    "log"

    enclave "github.com/jeremyhahn/go-enclave"

    "github.com/jeremyhahn/go-auth/pkg/tacacs"
)

func main() {
    // Credentials travel in go-enclave locked memory. Build them with
    // enclave.NewMemoryEnclave from bytes you read (that wipes them);
    // NewMemoryEnclave([]byte(s)) is for values that only exist as strings.
    sharedSecret, err := enclave.NewMemoryEnclave([]byte("shared-secret"))
    if err != nil {
        log.Fatal(err) // enclave.ErrLockedMemoryUnavailable: fail closed
    }

    // NewAuthenticator takes ownership of sharedSecret: it destroys it on
    // error, and auth.Close destroys it otherwise.
    auth, err := tacacs.NewAuthenticator("tacacs.example.com:49", sharedSecret)
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close()

    password, err := enclave.NewMemoryEnclave([]byte("password"))
    if err != nil {
        log.Fatal(err)
    }
    defer password.Destroy() // Authenticate only borrows it

    // Authenticate user
    ctx := context.Background()
    err = auth.Authenticate(ctx, "username", password)
    if errors.Is(err, tacacs.ErrAuthenticationFailed) {
        log.Println("Authentication failed - invalid credentials")
        return
    }
    if err != nil {
        log.Printf("Error: %v", err)
        return
    }

    log.Println("Authentication successful")
}
```

### With Privilege Level

```go
// Configure privilege level (default: 1)
auth, err := tacacs.NewAuthenticator(
    "tacacs.example.com:49",
    sharedSecret,
    tacacs.WithPrivLevel(15), // Highest privilege (admin)
)
if err != nil {
    log.Fatal(err)
}

err = auth.Authenticate(ctx, "admin", password)
```

### With Timeout

```go
import "time"

// Set read/write timeout
auth, err := tacacs.NewAuthenticator(
    "tacacs.example.com:49",
    sharedSecret,
    tacacs.WithTimeout(10 * time.Second),
)
if err != nil {
    log.Fatal(err)
}

err = auth.Authenticate(ctx, "username", password)
```

## Configuration

### NewAuthenticator Parameters

```go
func NewAuthenticator(addr string, sharedSecret *enclave.MemoryEnclave, opts ...Option) (*Authenticator, error)
func (a *Authenticator) Authenticate(ctx context.Context, username string, password *enclave.MemoryEnclave) error
func (a *Authenticator) Close() error
```

**Required Parameters:**
- `addr` - TACACS+ server address with port (e.g., "192.168.1.1:49")
- `sharedSecret` - Shared secret for packet obfuscation, in locked memory.
  `NewAuthenticator` takes ownership on every return path; `Close` destroys it.

**Standard Port:**
- `49` - TACACS+ (TCP)

### Available Options

#### WithPrivLevel

Set the privilege level for authentication requests:

```go
auth, err := tacacs.NewAuthenticator(
    "tacacs.example.com:49",
    sharedSecret,
    tacacs.WithPrivLevel(15), // uint8, sent as-is; the server interprets it
)
```

**Common Privilege Levels:**
- `0` - Zero privilege (limited access)
- `1` - User mode (default)
- `15` - Privileged mode (full admin access)

Levels 2-14 are available for custom privilege configurations.

#### WithTimeout

Set read/write timeout for TACACS+ operations:

```go
import "time"

auth, err := tacacs.NewAuthenticator(
    "tacacs.example.com:49",
    sharedSecret,
    tacacs.WithTimeout(5 * time.Second),
)
```

The timeout is set as the connection's read and write timeout, so it applies to:
- Reading authentication responses
- Writing authentication requests

To bound the whole call, connection establishment included, pass a `context`
with a deadline to `Authenticate`, or supply a dialer with `WithDialContext`.

## Authentication Flow

### Standard Flow

1. **Client** sends AuthenStart with username
2. **Server** responds with status (PASS, FAIL, or prompt)
3. **Client** sends password if prompted
4. **Server** responds with final status

### Interactive Flow

TACACS+ supports interactive prompts:

```
Client → AuthenStart(username)
Server → GetUser (prompt for username)
Client → Continue(username)
Server → GetPass (prompt for password)
Client → Continue(password)
Server → Pass/Fail
```

The package handles all interactive flows automatically.

### Reply Status Codes

The server can respond with various status codes:
- **PASS** - Authentication successful
- **FAIL** - Authentication failed
- **ERROR** - Server error; returned as `tacacs: <server message>`
- **GETUSER** - Server requests username
- **GETPASS** - Server requests password
- **GETDATA** - Answered with the password, as GETPASS
- **RESTART** - Server requests restart; the client continues with an empty message

Any other status fails with `tacacs: unsupported reply status`.

## Error Handling

```go
err := auth.Authenticate(ctx, "username", password)

switch {
case err == nil:
    // Success
    log.Println("Authenticated")

case errors.Is(err, tacacs.ErrAuthenticationFailed):
    // TACACS+ server rejected credentials
    log.Println("Invalid username or password")

case errors.Is(err, context.Canceled):
    // Context cancelled
    log.Println("Operation cancelled")

case errors.Is(err, context.DeadlineExceeded):
    // Context timeout
    log.Println("Authentication timed out")

default:
    // Network error or server error
    log.Printf("Error: %v", err)
}
```

### Common Errors

```go
// Empty address: tacacs.ErrEmptyAddress (sharedSecret is destroyed)
auth, err := tacacs.NewAuthenticator("", sharedSecret)
// Error: "tacacs: address must not be empty"

// Missing secret: tacacs.ErrMissingSharedSecret
auth, err := tacacs.NewAuthenticator("server:49", nil)
// Error: "tacacs: secret must not be empty"

// Empty username: tacacs.ErrMissingUsername
err := auth.Authenticate(ctx, "", password)
// Error: "tacacs: username must not be empty"

// Missing password: tacacs.ErrMissingPassword
// (a destroyed enclave also matches enclave.ErrEnclaveDestroyed)
err := auth.Authenticate(ctx, "user", nil)
// Error: "tacacs: password must not be empty"

// After Close: tacacs.ErrClosed
```

### FIPS activation

`NewAuthenticator` returns `tacacs.ErrFIPSUnsupported` — ahead of any argument
check, after destroying the shared secret it was handed — when the process runs
under `GODEBUG=fips140=only`. RFC 8907 §4.5 obfuscates every packet body with
an MD5 keystream, so no configuration or option makes this backend usable
there. `Authenticate` returns the same error before building a packet.

```go
auth, err := tacacs.NewAuthenticator("server:49", sharedSecret)
if errors.Is(err, tacacs.ErrFIPSUnsupported) {
    // FIPS is activated in this deployment. Use a different backend;
    // there is no TACACS+ configuration that satisfies FIPS 140-3.
}
```

The refusal is deliberate and final: without it the process would start and
then panic inside `crypto/md5` on the first authentication. See
[fips.md](fips.md) for the full rationale and how activation is detected.

## Context Management

### With Timeout

```go
import "time"

ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

err := auth.Authenticate(ctx, "username", password)
if errors.Is(err, context.DeadlineExceeded) {
    log.Println("TACACS+ server did not respond in time")
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

err := auth.Authenticate(ctx, "username", password)
```

## Integration with go-auth API

```go
import (
    "github.com/jeremyhahn/go-auth/pkg/api"
    "github.com/jeremyhahn/go-auth/pkg/tacacs"
)

tacacsAuth, _ := tacacs.NewAuthenticator(
    "tacacs.example.com:49",
    sharedSecret,
)

service, _ := api.NewService(api.Config{
    Backends: []api.Backend{
        {Name: api.BackendTACACS, Handler: api.TACACS(tacacsAuth)},
    },
})

// Login takes ownership of the request's enclaves and destroys them when
// the attempt completes.
err := service.Login(ctx, api.LoginRequest{
    Backend:  api.BackendTACACS,
    Username: "user",
    Password: password, // *enclave.MemoryEnclave
})
```

## Credentials in Locked Memory

The shared secret and the user's password are go-enclave
`*enclave.MemoryEnclave` values — see [Credentials](credentials.md).

- The **shared secret** belongs to the authenticator. `NewAuthenticator` takes
  ownership on every return path (including `ErrFIPSUnsupported`), each
  `Authenticate` lends it to `tacplus` for the length of the exchange, and
  `Close` destroys it; `Authenticate` then fails with `tacacs.ErrClosed`.
- The **password** is borrowed by `Authenticate` and never destroyed there.

```go
raw, err := os.ReadFile("/run/secrets/tacacs-secret")
if err != nil {
    log.Fatal(err)
}
sharedSecret, err := enclave.NewMemoryEnclave(bytes.TrimSpace(raw)) // wipes raw's bytes
if err != nil {
    log.Fatal(err)
}

auth, err := tacacs.NewAuthenticator("tacacs.example.com:49", sharedSecret,
    tacacs.WithPrivLevel(15))
if err != nil {
    log.Fatal(err) // sharedSecret has already been destroyed
}
defer auth.Close()
```

`tacplus` is handed the locked pages themselves (`ConnConfig.Secret`), with no
copy, for the length of one `Authenticate`. That is safe, and lets `Close`
release the key, because `tacplus` v0.0.3 reads the secret only inside
`SendAuthenStart` and `Continue`, on the calling goroutine: its connection
goroutines move ciphertext and never decrypt, and the handler it spawns for a
packet that matches no session fails its sequence-number checks before
reaching the cipher. Earlier releases kept a locked copy with no release point
on the assumption that those goroutines decrypted; they do not. A `tacplus`
upgrade must re-verify this.

What `tacplus` does copy — the key into a heap buffer for every packet, and the
password, which `Continue` accepts only as a `string` — is residue **R3** in the
[credential residue register](security/credential-residues.md). go-auth lends
`Continue` a string whose bytes are zeroed when it returns.

## Security Considerations

### Packet Encryption

TACACS+ encrypts the entire packet body (unlike RADIUS which only encrypts passwords):
- All authentication data is encrypted
- Uses MD5-based obfuscation with shared secret
- Protection against eavesdropping

### Shared Secret Security

1. **Use strong secrets** - 32+ random characters
2. **Unique per client** - Don't reuse across devices
3. **Secure storage** - Secret managers or files read into `[]byte`
4. **Regular rotation** - Change secrets periodically
5. **Secure transmission** - Never send secrets over unencrypted channels

```go
// Read the secret into bytes, never a string; NewMemoryEnclave wipes them.
raw, err := os.ReadFile(os.Getenv("TACACS_SECRET_FILE"))
if err != nil {
    log.Fatal("TACACS+ secret not readable: ", err)
}
sharedSecret, err := enclave.NewMemoryEnclave(bytes.TrimSpace(raw))
if err != nil {
    log.Fatal(err)
}

auth, err := tacacs.NewAuthenticator("server:49", sharedSecret)
```

### Transport Security

TACACS+ uses TCP (unlike RADIUS UDP):
- **Advantages**: Reliable delivery, connection-oriented
- **Considerations**: No built-in TLS/SSL support

For additional security:
- Use VPN or IPsec for transport encryption
- Restrict access with firewall rules (TCP/49)
- Use network segmentation for TACACS+ traffic
- Consider SSH tunneling for untrusted networks

### Best Practices

1. **Implement timeouts** - Prevent indefinite hangs
2. **Use privilege levels** - Enforce least privilege
3. **Audit logging** - Log all authentication attempts
4. **Connection limits** - Prevent resource exhaustion
5. **Secure secrets** - Use key management systems
6. **Monitor failures** - Alert on authentication failures
7. **Regular updates** - Keep TACACS+ server patched

## Advanced Usage

### Multiple TACACS+ Servers

Implement failover with multiple servers:

```go
servers := []string{
    "tacacs1.example.com:49",
    "tacacs2.example.com:49",
    "tacacs3.example.com:49",
}

var lastErr error

for _, server := range servers {
    // Each authenticator owns its own copy of the shared secret.
    sharedSecret, err := loadSharedSecret() // returns a fresh *enclave.MemoryEnclave
    if err != nil {
        return err
    }
    auth, err := tacacs.NewAuthenticator(
        server,
        sharedSecret,
        tacacs.WithTimeout(3*time.Second),
    )
    if err != nil {
        lastErr = err
        continue
    }

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    err = auth.Authenticate(ctx, "username", password)
    cancel()

    if err == nil {
        log.Printf("Authenticated via %s", server)
        return nil
    }

    log.Printf("Server %s failed: %v", server, err)
    lastErr = err
}

return fmt.Errorf("all TACACS+ servers failed: %w", lastErr)
```

### Custom Dial Context

Inject custom dialer for testing or advanced networking:

```go
customDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
    // Custom dial logic (proxy, socket options, etc.)
    dialer := &net.Dialer{
        Timeout:   5 * time.Second,
        KeepAlive: 30 * time.Second,
    }
    return dialer.DialContext(ctx, network, addr)
}

auth, err := tacacs.NewAuthenticator(
    "tacacs.example.com:49",
    sharedSecret,
    tacacs.WithDialContext(customDialer),
)
```

### Privilege Level Escalation

Authenticate at different privilege levels:

```go
// User-level authentication. Each authenticator owns its own shared-secret
// enclave, so the two get separate copies.
userAuth, _ := tacacs.NewAuthenticator(
    "tacacs.example.com:49",
    sharedSecret,
    tacacs.WithPrivLevel(1),
)

// Admin-level authentication
adminAuth, _ := tacacs.NewAuthenticator(
    "tacacs.example.com:49",
    adminSharedSecret,
    tacacs.WithPrivLevel(15),
)

// First authenticate as user
if err := userAuth.Authenticate(ctx, "username", userPassword); err != nil {
    return err
}

// Then authenticate for admin privileges
if err := adminAuth.Authenticate(ctx, "username", enablePassword); err != nil {
    return err
}
```

## Performance

Performance factors:
- Network latency to TACACS+ server
- Server processing time
- Number of interactive prompts
- Configured timeouts

### Optimization

- **Connection reuse** - Authenticator is stateless, create once
- **Timeout tuning** - Balance responsiveness vs reliability
- **Server placement** - Minimize network latency
- **Connection pooling** - At application level if needed

## Troubleshooting

### Connection Refused

```
Error: connection refused
```

Causes:
- TACACS+ server not running
- Firewall blocking TCP port 49
- Incorrect server address
- Server not listening on expected port

Solutions:
1. Verify server is running: `telnet tacacs.example.com 49`
2. Check firewall rules: `iptables -L -n | grep 49`
3. Verify server configuration
4. Check network connectivity: `ping tacacs.example.com`

### Authentication Failed

```
Error: tacacs: authentication failed
```

Causes:
- Invalid username or password
- User not authorized on TACACS+ server
- Account locked or expired
- Incorrect shared secret
- Privilege level mismatch

Solutions:
1. Verify credentials with TACACS+ admin
2. Check TACACS+ server logs
3. Test with known-good credentials
4. Verify shared secret matches server
5. Check user privilege level configuration

### Timeout Errors

```
Error: context deadline exceeded
```

Causes:
- TACACS+ server slow or overloaded
- Network congestion
- Timeout set too low
- Server not responding

Solutions:
1. Increase timeout:
```go
tacacs.WithTimeout(30 * time.Second)
```
2. Check server performance
3. Verify network connectivity
4. Monitor server logs for errors

### Session Nil Error

```
Error: tacacs: session unexpectedly nil
```

Causes:
- Server protocol error
- Malformed server response
- Network interruption during session

Solutions:
1. Check TACACS+ server logs
2. Verify server software version
3. Test with official TACACS+ client
4. Check for network issues

## Testing

### Mock Implementation

```go
type MockDialer struct {
    conn net.Conn
    err  error
}

func (m *MockDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
    return m.conn, m.err
}

// Use in tests
func TestAuthentication(t *testing.T) {
    // Create mock connection
    server, client := net.Pipe()
    defer server.Close()
    defer client.Close()

    mockDialer := &MockDialer{conn: client}

    auth, err := tacacs.NewAuthenticator(
        "test:49",
        sharedSecret,
        tacacs.WithDialContext(mockDialer.DialContext),
    )
    if err != nil {
        t.Fatal(err)
    }

    // Simulate server responses in goroutine
    go func() {
        // Read and respond to TACACS+ packets
        // ...
    }()

    err = auth.Authenticate(context.Background(), "user", password)
    // ... assertions
}
```

## Integration Tests

The integration tests (build tag `integration`) start an in-process `tacplus`
server on `127.0.0.1` and need no environment variables. `make
tacacs-integration-test` builds and runs them in Docker:

```bash
make tacacs-integration-test
```

Integration tests validate:
- Successful authentication
- Failed authentication
- Interactive prompts
- Timeout handling
- Context cancellation
- Error conditions

## TACACS+ Server Configuration

### Cisco IOS Example

```
# Define TACACS+ client
aaa new-model
tacacs-server host 192.168.1.100 key shared-secret

# Configure authentication
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
```

### Free TACACS+ (tac_plus) Example

```
# /etc/tacacs/tac_plus.conf
key = shared-secret

user = testuser {
    login = cleartext testpass
    service = shell {
        priv-lvl = 15
    }
}

group = admins {
    default service = permit
    service = shell {
        priv-lvl = 15
    }
}
```

## Comparison with RADIUS

| Feature | TACACS+ | RADIUS |
|---------|---------|---------|
| Transport | TCP (port 49) | UDP (port 1812) |
| Encryption | Full packet body | Password only |
| AAA Separation | Separate AAA functions | Combined AAA |
| Packet Size | Variable | Up to 4096 bytes |
| Primary Use | Network device admin | Network access, VPN, WiFi |
| Vendor | Cisco (open standard) | IETF standard |

**When to use TACACS+:**
- Network device administration
- Privilege level control needed
- Full packet encryption required
- Reliable delivery important (TCP)

**When to use RADIUS:**
- Network access control (WiFi, VPN)
- Accounting/billing required
- Standard AAA across vendors
- High-volume authentication

## References

- [RFC 8907 - TACACS+](https://www.rfc-editor.org/rfc/rfc8907)
- [Cisco TACACS+ Configuration Guide](https://www.cisco.com/c/en/us/support/docs/security-vpn/terminal-access-controller-access-control-system-tacacs-/13847-45.html)
- [tac_plus - Free TACACS+ Server](http://www.shrubbery.net/tac_plus/)
- [TACACS+ Protocol Specification](https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-tacacs)
