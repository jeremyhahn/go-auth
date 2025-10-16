# RADIUS Authentication Package

The `radius` package provides Remote Authentication Dial-In User Service (RADIUS) authentication with support for PAP, EAP-TLS, and RadSec (RADIUS-over-TLS).

## Overview

RADIUS is a networking protocol that provides centralized authentication, authorization, and accounting (AAA) management. This package implements the authentication component, supporting:

- **PAP (Password Authentication Protocol)** - Traditional username/password authentication
- **EAP-TLS (Extensible Authentication Protocol - TLS)** - Certificate-based authentication
- **RadSec** - RADIUS over TLS for encrypted transport
- **Standard RADIUS** - UDP-based transport (RFC 2865)

## Features

- Multiple authentication methods (PAP, EAP-TLS)
- RadSec support for encrypted communication
- Configurable retry logic and timeouts
- Packet validation and authenticator verification
- Fragment handling for EAP-TLS
- Thread-safe concurrent operation
- Context-aware with proper cancellation

## Quick Start

### PAP Authentication

Traditional username/password authentication:

```go
package main

import (
    "context"
    "log"

    "github.com/jhahn/go-auth/pkg/radius"
)

func main() {
    // Create RADIUS authenticator
    auth, err := radius.NewAuthenticator(
        "radius.example.com:1812",
        "shared-secret",
    )
    if err != nil {
        log.Fatal(err)
    }

    // Authenticate user
    ctx := context.Background()
    err = auth.Authenticate(ctx, "username", "password")
    if err == radius.ErrRejected {
        log.Println("Access denied")
        return
    }
    if err != nil {
        log.Printf("Error: %v", err)
        return
    }

    log.Println("Authentication successful")
}
```

### RadSec (RADIUS over TLS)

Encrypted RADIUS communication using TLS:

```go
import (
    "crypto/tls"
    "crypto/x509"
    "os"
)

// Load CA certificate
caCert, err := os.ReadFile("ca.pem")
if err != nil {
    log.Fatal(err)
}

caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

tlsConfig := &tls.Config{
    RootCAs:    caCertPool,
    MinVersion: tls.VersionTLS12,
}

// Create RadSec authenticator
auth, err := radius.NewAuthenticator(
    "radsec.example.com:2083",
    "shared-secret",
    radius.WithTLSConfig(tlsConfig),
)
if err != nil {
    log.Fatal(err)
}

err = auth.Authenticate(ctx, "username", "password")
```

### EAP-TLS Authentication

Certificate-based authentication using EAP-TLS:

```go
import (
    "crypto/tls"
    "crypto/x509"
)

// Load client certificate
cert, err := tls.LoadX509KeyPair("client-cert.pem", "client-key.pem")
if err != nil {
    log.Fatal(err)
}

// Load CA certificate
caCert, err := os.ReadFile("ca.pem")
if err != nil {
    log.Fatal(err)
}

caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

// Configure EAP-TLS
eapTLSConfig := &radius.EAPTLSConfig{
    TLSConfig: &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
        MinVersion:   tls.VersionTLS12,
    },
    Identity:      "user@example.com",
    OuterIdentity: "anonymous",
    FragmentSize:  1010,
}

// Create authenticator with EAP-TLS
auth, err := radius.NewAuthenticator(
    "radius.example.com:1812",
    "shared-secret",
    radius.WithEAPTLS(eapTLSConfig),
)
if err != nil {
    log.Fatal(err)
}

// Authenticate (password parameter ignored for EAP-TLS)
err = auth.Authenticate(ctx, "user@example.com", "")
```

## Configuration Options

### NewAuthenticator Parameters

```go
func NewAuthenticator(address, secret string, opts ...Option) (*Authenticator, error)
```

**Required Parameters:**
- `address` - RADIUS server address with port (e.g., "192.168.1.1:1812")
- `secret` - Shared secret for RADIUS packet encryption

**Standard Ports:**
- `1812` - Authentication (UDP)
- `1813` - Accounting (UDP)
- `2083` - RadSec (TCP/TLS)

### Available Options

#### WithNetwork

Override the network protocol (default: "udp"):

```go
auth, err := radius.NewAuthenticator(
    "radius.example.com:1812",
    "secret",
    radius.WithNetwork("udp4"), // Force IPv4
)
```

#### WithTLSConfig

Enable RadSec with TLS configuration:

```go
tlsConfig := &tls.Config{
    RootCAs:            caCertPool,
    Certificates:       []tls.Certificate{cert},
    MinVersion:         tls.VersionTLS12,
    InsecureSkipVerify: false, // Always verify in production
}

auth, err := radius.NewAuthenticator(
    "radsec.example.com:2083",
    "secret",
    radius.WithTLSConfig(tlsConfig),
)
```

#### WithRetry

Configure retry interval for Access-Request packets:

```go
import "time"

auth, err := radius.NewAuthenticator(
    "radius.example.com:1812",
    "secret",
    radius.WithRetry(3 * time.Second),
)
```

#### WithMaxPacketErrors

Limit tolerance for malformed responses:

```go
auth, err := radius.NewAuthenticator(
    "radius.example.com:1812",
    "secret",
    radius.WithMaxPacketErrors(3),
)
```

#### WithDialTimeout

Set connection timeout:

```go
auth, err := radius.NewAuthenticator(
    "radius.example.com:1812",
    "secret",
    radius.WithDialTimeout(5 * time.Second),
)
```

#### WithInsecureSkipVerify

Disable response authenticator verification (testing only):

```go
auth, err := radius.NewAuthenticator(
    "radius.example.com:1812",
    "secret",
    radius.WithInsecureSkipVerify(true), // DO NOT use in production
)
```

#### WithEAPTLS

Enable EAP-TLS authentication:

```go
eapConfig := &radius.EAPTLSConfig{
    TLSConfig:     tlsConfig,
    Identity:      "user@realm",
    OuterIdentity: "anonymous",
    FragmentSize:  1010,
}

auth, err := radius.NewAuthenticator(
    "radius.example.com:1812",
    "secret",
    radius.WithEAPTLS(eapConfig),
)
```

## EAP-TLS Configuration

### EAPTLSConfig Structure

```go
type EAPTLSConfig struct {
    TLSConfig     *tls.Config  // TLS configuration (required)
    Identity      string       // Inner identity (default: username)
    OuterIdentity string       // Outer identity (default: Identity)
    FragmentSize  int          // Fragment size (default: 1010, max: 4096)
}
```

### Identity Configuration

- **Identity** - Inner identity sent after TLS tunnel establishment
- **OuterIdentity** - Outer identity sent before TLS tunnel (privacy)

Common pattern for privacy:
```go
Identity:      "user@example.com",      // Real identity
OuterIdentity: "anonymous@example.com", // Privacy-preserving
```

### Fragment Size

EAP-TLS fragments large TLS messages to fit in RADIUS packets:
- Default: 1010 bytes (safe for most networks)
- Maximum: 4096 bytes
- Larger fragments = fewer round trips but potential MTU issues

```go
FragmentSize: 1400, // Adjust based on network MTU
```

## Error Handling

### Common Errors

```go
err := auth.Authenticate(ctx, "username", "password")

switch {
case err == nil:
    // Authentication successful
    log.Println("Access granted")

case errors.Is(err, radius.ErrRejected):
    // RADIUS server rejected credentials
    log.Println("Access denied - invalid credentials")

case errors.Is(err, context.Canceled):
    // Context cancelled
    log.Println("Operation cancelled")

case errors.Is(err, context.DeadlineExceeded):
    // Timeout
    log.Println("Authentication timed out")

default:
    // Network error, malformed packet, or other issue
    log.Printf("Error: %v", err)
}
```

### Validation Errors

Configuration errors are returned from `NewAuthenticator`:

```go
auth, err := radius.NewAuthenticator("", "secret")
if err != nil {
    // Error: "radius: address must not be empty"
}

auth, err := radius.NewAuthenticator("server:1812", "")
if err != nil {
    // Error: "radius: secret must not be empty"
}
```

## Integration with go-auth API

```go
import (
    "github.com/jhahn/go-auth/pkg/api"
    "github.com/jhahn/go-auth/pkg/radius"
)

radiusAuth, _ := radius.NewAuthenticator(
    "radius.example.com:1812",
    "shared-secret",
)

service, _ := api.NewService(api.Config{
    Backends: []api.Backend{
        {Name: api.BackendRADIUS, Handler: api.RADIUS(radiusAuth)},
    },
})

err := service.Login(ctx, api.LoginRequest{
    Backend:  api.BackendRADIUS,
    Username: "user",
    Password: "pass",
})
```

## Advanced Usage

### Context with Timeout

```go
import "time"

ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

err := auth.Authenticate(ctx, "username", "password")
if err == context.DeadlineExceeded {
    log.Println("RADIUS server did not respond in time")
}
```

### Multiple RADIUS Servers

```go
servers := []string{
    "radius1.example.com:1812",
    "radius2.example.com:1812",
}

var auth *radius.Authenticator
var err error

for _, server := range servers {
    auth, err = radius.NewAuthenticator(server, "secret")
    if err != nil {
        continue
    }

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    err = auth.Authenticate(ctx, "username", "password")
    cancel()

    if err == nil {
        break // Success
    }

    log.Printf("Server %s failed: %v", server, err)
}
```

### RadSec with Mutual TLS

```go
// Load client certificate
cert, err := tls.LoadX509KeyPair("client.pem", "client-key.pem")
if err != nil {
    log.Fatal(err)
}

// Load CA certificates
caCert, err := os.ReadFile("ca.pem")
if err != nil {
    log.Fatal(err)
}

caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert}, // Client certificate
    RootCAs:      caCertPool,              // CA for server verification
    MinVersion:   tls.VersionTLS12,
}

auth, err := radius.NewAuthenticator(
    "radsec.example.com:2083",
    "shared-secret",
    radius.WithTLSConfig(tlsConfig),
)
```

## Security Considerations

### Shared Secret Security

1. **Use strong secrets** - 32+ random characters
2. **Unique per client** - Don't reuse across systems
3. **Secure storage** - Environment variables or secret managers
4. **Regular rotation** - Change secrets periodically

```go
// Load secret from environment
secret := os.Getenv("RADIUS_SECRET")
if secret == "" {
    log.Fatal("RADIUS_SECRET not set")
}
```

### Transport Security

**Standard RADIUS (UDP):**
- Passwords are MD5 hashed (weak by modern standards)
- Susceptible to replay attacks
- Use only on trusted networks

**RadSec (TLS):**
- Full encryption of all RADIUS traffic
- Mutual authentication with certificates
- Recommended for untrusted networks

### EAP-TLS Security

1. **Certificate validation** - Always verify server certificates
2. **Strong cipher suites** - Use TLS 1.2+ with modern ciphers
3. **Certificate expiration** - Monitor and renew before expiry
4. **Private key protection** - Secure storage and access control
5. **Outer identity privacy** - Use anonymous outer identity

### Best Practices

1. **Use RadSec** - For communication over untrusted networks
2. **Enable TLS verification** - Never skip certificate validation in production
3. **Implement timeouts** - Prevent indefinite hangs
4. **Rate limiting** - Implement at application level
5. **Audit logging** - Log all authentication attempts
6. **Error handling** - Don't leak information in error messages

## Performance

### Benchmark Results

Typical authentication latency:
- PAP (local network): 5-20ms
- PAP (WAN): 50-200ms
- RadSec: +10-30ms (TLS overhead)
- EAP-TLS: 100-300ms (certificate exchange)

### Optimization

- **Connection pooling** - Not applicable (stateless protocol)
- **Retry configuration** - Balance responsiveness vs resilience
- **Network selection** - Use UDP for speed, TCP/TLS for security
- **Fragment size** - Larger fragments for EAP-TLS reduce round trips

## Troubleshooting

### No Response from Server

```
Error: i/o timeout
```

Causes:
- RADIUS server down or unreachable
- Firewall blocking UDP 1812 or TCP 2083
- Incorrect server address
- Network connectivity issues

Solutions:
1. Verify server is running: `nc -u radius.example.com 1812`
2. Check firewall rules
3. Test with `radtest` tool
4. Verify DNS resolution
5. Increase timeout: `radius.WithDialTimeout(10*time.Second)`

### Access Rejected

```
Error: radius: access rejected
```

Causes:
- Invalid username or password
- User not authorized on RADIUS server
- Account expired or locked
- Incorrect shared secret (PAP)

Solutions:
1. Verify credentials
2. Check RADIUS server logs
3. Test with known-good credentials
4. Verify shared secret matches server configuration

### TLS Errors

```
Error: x509: certificate signed by unknown authority
```

Causes:
- CA certificate not in trust store
- Self-signed certificate without CA
- Expired or invalid certificate

Solutions:
```go
// Add CA to trust store
caCert, _ := os.ReadFile("ca.pem")
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

tlsConfig.RootCAs = caCertPool
```

### EAP-TLS Handshake Failures

```
Error: radius: EAP-TLS handshake failed
```

Causes:
- Client certificate not trusted by server
- Certificate expired
- Cipher suite mismatch
- Fragment size too large

Solutions:
1. Verify client certificate is valid
2. Check server RADIUS logs
3. Reduce fragment size: `FragmentSize: 900`
4. Verify certificate chain

## Integration Tests

Run integration tests with a RADIUS server:

```bash
# Export test configuration
export RADIUS_SERVER=radius.example.com:1812
export RADIUS_SECRET=testing123
export RADIUS_USERNAME=testuser
export RADIUS_PASSWORD=testpass

# Run integration tests
cd test/integration/radius
go test -v
```

Integration tests validate:
- PAP authentication
- EAP-TLS authentication
- RadSec transport
- Error handling
- Context cancellation

## References

- [RFC 2865 - RADIUS](https://www.rfc-editor.org/rfc/rfc2865)
- [RFC 2866 - RADIUS Accounting](https://www.rfc-editor.org/rfc/rfc2866)
- [RFC 3748 - EAP](https://www.rfc-editor.org/rfc/rfc3748)
- [RFC 5216 - EAP-TLS](https://www.rfc-editor.org/rfc/rfc5216)
- [RFC 6614 - RadSec](https://www.rfc-editor.org/rfc/rfc6614)
- [FreeRADIUS Documentation](https://freeradius.org/documentation/)
