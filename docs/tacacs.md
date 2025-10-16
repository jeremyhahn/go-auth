# TACACS+ Authentication Package

The `tacacs` package provides Terminal Access Controller Access-Control System Plus (TACACS+) authentication for network device access control and centralized AAA (Authentication, Authorization, and Accounting).

## Overview

TACACS+ is a Cisco-developed protocol that provides centralized authentication, authorization, and accounting services. This package implements the authentication component, supporting:

- ASCII login authentication
- Interactive challenge-response flows
- Configurable privilege levels
- Encrypted communication (all packet data encrypted)
- Context-aware operation with timeout support

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

### Basic Authentication

```go
package main

import (
    "context"
    "log"

    "github.com/jhahn/go-auth/pkg/tacacs"
)

func main() {
    // Create TACACS+ authenticator
    auth, err := tacacs.NewAuthenticator(
        "tacacs.example.com:49",
        "shared-secret",
    )
    if err != nil {
        log.Fatal(err)
    }

    // Authenticate user
    ctx := context.Background()
    err = auth.Authenticate(ctx, "username", "password")
    if err == tacacs.ErrAuthenticationFailed {
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
    "shared-secret",
    tacacs.WithPrivLevel(15), // Highest privilege (admin)
)
if err != nil {
    log.Fatal(err)
}

err = auth.Authenticate(ctx, "admin", "password")
```

### With Timeout

```go
import "time"

// Set read/write timeout
auth, err := tacacs.NewAuthenticator(
    "tacacs.example.com:49",
    "shared-secret",
    tacacs.WithTimeout(10 * time.Second),
)
if err != nil {
    log.Fatal(err)
}

err = auth.Authenticate(ctx, "username", "password")
```

## Configuration

### NewAuthenticator Parameters

```go
func NewAuthenticator(addr, secret string, opts ...Option) (*Authenticator, error)
```

**Required Parameters:**
- `addr` - TACACS+ server address with port (e.g., "192.168.1.1:49")
- `secret` - Shared secret for packet encryption

**Standard Port:**
- `49` - TACACS+ (TCP)

### Available Options

#### WithPrivLevel

Set the privilege level for authentication requests:

```go
auth, err := tacacs.NewAuthenticator(
    "tacacs.example.com:49",
    "secret",
    tacacs.WithPrivLevel(15), // Privilege level 0-15
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
    "secret",
    tacacs.WithTimeout(5 * time.Second),
)
```

Timeout applies to:
- Initial connection establishment
- Reading authentication responses
- Writing authentication requests

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
- **ERROR** - Server error
- **GETUSER** - Server requests username
- **GETPASS** - Server requests password
- **GETDATA** - Server requests additional data
- **RESTART** - Server requests restart of authentication

## Error Handling

```go
err := auth.Authenticate(ctx, "username", "password")

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
// Empty address
auth, err := tacacs.NewAuthenticator("", "secret")
// Error: "tacacs: address must not be empty"

// Empty secret
auth, err := tacacs.NewAuthenticator("server:49", "")
// Error: "tacacs: secret must not be empty"

// Empty username
err := auth.Authenticate(ctx, "", "password")
// Error: "tacacs: username must not be empty"

// Empty password
err := auth.Authenticate(ctx, "user", "")
// Error: "tacacs: password must not be empty"
```

## Context Management

### With Timeout

```go
import "time"

ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

err := auth.Authenticate(ctx, "username", "password")
if err == context.DeadlineExceeded {
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

err := auth.Authenticate(ctx, "username", "password")
```

## Integration with go-auth API

```go
import (
    "github.com/jhahn/go-auth/pkg/api"
    "github.com/jhahn/go-auth/pkg/tacacs"
)

tacacsAuth, _ := tacacs.NewAuthenticator(
    "tacacs.example.com:49",
    "shared-secret",
)

service, _ := api.NewService(api.Config{
    Backends: []api.Backend{
        {Name: api.BackendTACACS, Handler: api.TACACS(tacacsAuth)},
    },
})

err := service.Login(ctx, api.LoginRequest{
    Backend:  api.BackendTACACS,
    Username: "user",
    Password: "pass",
})
```

## Security Considerations

### Packet Encryption

TACACS+ encrypts the entire packet body (unlike RADIUS which only encrypts passwords):
- All authentication data is encrypted
- Uses MD5-based obfuscation with shared secret
- Protection against eavesdropping
- Replay attack protection via session IDs

### Shared Secret Security

1. **Use strong secrets** - 32+ random characters
2. **Unique per client** - Don't reuse across devices
3. **Secure storage** - Environment variables or secret managers
4. **Regular rotation** - Change secrets periodically
5. **Secure transmission** - Never send secrets over unencrypted channels

```go
// Load secret from environment
secret := os.Getenv("TACACS_SECRET")
if secret == "" {
    log.Fatal("TACACS_SECRET not set")
}

auth, err := tacacs.NewAuthenticator("server:49", secret)
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
    auth, err := tacacs.NewAuthenticator(
        server,
        "shared-secret",
        tacacs.WithTimeout(3*time.Second),
    )
    if err != nil {
        lastErr = err
        continue
    }

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    err = auth.Authenticate(ctx, "username", "password")
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
    "secret",
    tacacs.WithDialContext(customDialer),
)
```

### Privilege Level Escalation

Authenticate at different privilege levels:

```go
// User-level authentication
userAuth, _ := tacacs.NewAuthenticator(
    "tacacs.example.com:49",
    "secret",
    tacacs.WithPrivLevel(1),
)

// Admin-level authentication
adminAuth, _ := tacacs.NewAuthenticator(
    "tacacs.example.com:49",
    "secret",
    tacacs.WithPrivLevel(15),
)

// First authenticate as user
if err := userAuth.Authenticate(ctx, "username", "userpass"); err != nil {
    return err
}

// Then authenticate for admin privileges
if err := adminAuth.Authenticate(ctx, "username", "enablepass"); err != nil {
    return err
}
```

## Performance

### Benchmark Results

Typical authentication latency:
- Local network: 10-30ms
- WAN: 50-200ms
- With timeout failures: 3-10s (depending on timeout)

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
        "secret",
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

    err = auth.Authenticate(context.Background(), "user", "pass")
    // ... assertions
}
```

## Integration Tests

Run integration tests with a TACACS+ server:

```bash
# Export test configuration
export TACACS_SERVER=tacacs.example.com:49
export TACACS_SECRET=testing123
export TACACS_USERNAME=testuser
export TACACS_PASSWORD=testpass

# Run integration tests
cd test/integration/tacacs
go test -v
```

Integration tests validate:
- Successful authentication
- Failed authentication
- Interactive prompts
- Timeout handling
- Context cancellation
- Error conditions

## TACACS+ Server Configuration

### Cisco ACS Example

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
| Packet Size | Variable | Fixed (4096 bytes) |
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
