# LDAP Authentication Package

The `ldap` package provides Lightweight Directory Access Protocol (LDAP) authentication for validating credentials against directory services like Active Directory, OpenLDAP, and other LDAP-compliant systems.

## Overview

LDAP authentication validates credentials by attempting to bind to an LDAP directory with user-provided credentials. This package supports:

- **Direct Bind** - Bind directly with user DN and password
- **Service Account Bind** - Initial bind with service account, then user bind
- **LDAP** - Standard LDAP over plaintext (port 389)
- **LDAPS** - LDAP over TLS (port 636)
- **StartTLS** - Upgrade LDAP connection to TLS
- Configurable timeouts and TLS settings

Common use cases:
- Active Directory authentication
- OpenLDAP integration
- Enterprise directory integration
- Single sign-on (SSO) backends

## Features

- Standard LDAP and LDAPS support
- StartTLS for LDAP connections
- Service account authentication
- Configurable user DN templates
- Custom TLS configuration
- Timeout support
- Context-aware operation
- Thread-safe concurrent usage

## Quick Start

### Basic LDAP Authentication

```go
package main

import (
    "context"
    "log"

    "github.com/jhahn/go-auth/pkg/ldap"
)

func main() {
    // Create LDAP authenticator
    auth, err := ldap.NewAuthenticator(
        "ldap://ldap.example.com:389",
        ldap.WithUserDNTemplate("uid=%s,ou=users,dc=example,dc=com"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Authenticate user
    ctx := context.Background()
    err = auth.Authenticate(ctx, "jdoe", "password")
    if err != nil {
        log.Printf("Authentication failed: %v", err)
        return
    }

    log.Println("Authentication successful")
}
```

### LDAPS (LDAP over TLS)

```go
// Create LDAPS authenticator (automatic TLS)
auth, err := ldap.NewAuthenticator(
    "ldaps://ldap.example.com:636",
    ldap.WithUserDNTemplate("cn=%s,ou=users,dc=example,dc=com"),
)
if err != nil {
    log.Fatal(err)
}

err = auth.Authenticate(ctx, "username", "password")
```

### LDAP with StartTLS

```go
// Create LDAP authenticator with StartTLS
auth, err := ldap.NewAuthenticator(
    "ldap://ldap.example.com:389",
    ldap.WithUserDNTemplate("uid=%s,ou=people,dc=example,dc=com"),
    ldap.WithStartTLS(),
)
if err != nil {
    log.Fatal(err)
}

err = auth.Authenticate(ctx, "username", "password")
```

### With Service Account

Use a service account for initial bind (required for user lookup):

```go
auth, err := ldap.NewAuthenticator(
    "ldap://ldap.example.com:389",
    ldap.WithUserDNTemplate("cn=%s,ou=users,dc=example,dc=com"),
    ldap.WithServiceAccount(
        "cn=service,dc=example,dc=com",
        "service-password",
    ),
)
if err != nil {
    log.Fatal(err)
}

err = auth.Authenticate(ctx, "username", "password")
```

## Configuration

### NewAuthenticator Parameters

```go
func NewAuthenticator(url string, opts ...Option) (*Authenticator, error)
```

**Required Parameter:**
- `url` - LDAP server URL (ldap:// or ldaps://)

**URL Format:**
- `ldap://hostname:port` - Standard LDAP (default port 389)
- `ldaps://hostname:port` - LDAP over TLS (default port 636)

### Available Options

#### WithUserDNTemplate (Required)

Template for constructing user Distinguished Names (DNs):

```go
auth, err := ldap.NewAuthenticator(
    "ldap://ldap.example.com",
    ldap.WithUserDNTemplate("uid=%s,ou=people,dc=example,dc=com"),
)
```

The template must contain exactly one `%s` which is replaced with the username.

**Common Templates:**

Active Directory:
```go
ldap.WithUserDNTemplate("cn=%s,cn=users,dc=example,dc=com")
```

OpenLDAP with uid:
```go
ldap.WithUserDNTemplate("uid=%s,ou=people,dc=example,dc=com")
```

Custom OU structure:
```go
ldap.WithUserDNTemplate("cn=%s,ou=employees,ou=users,dc=company,dc=com")
```

#### WithServiceAccount

Configure service account for initial bind:

```go
auth, err := ldap.NewAuthenticator(
    "ldap://ldap.example.com",
    ldap.WithUserDNTemplate("cn=%s,ou=users,dc=example,dc=com"),
    ldap.WithServiceAccount(
        "cn=readonly,dc=example,dc=com",  // Service account DN
        "service-password",                // Service account password
    ),
)
```

Use service accounts when:
- Anonymous binds are disabled
- User lookup is required before authentication
- Additional directory access is needed

#### WithStartTLS

Enable StartTLS to upgrade plaintext LDAP to TLS:

```go
auth, err := ldap.NewAuthenticator(
    "ldap://ldap.example.com:389",
    ldap.WithUserDNTemplate("uid=%s,ou=users,dc=example,dc=com"),
    ldap.WithStartTLS(),
)
```

StartTLS vs LDAPS:
- **StartTLS**: Starts plaintext, upgrades to TLS (port 389)
- **LDAPS**: TLS from connection start (port 636)

#### WithTLSConfig

Provide custom TLS configuration:

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
    ServerName: "ldap.example.com",
}

auth, err := ldap.NewAuthenticator(
    "ldaps://ldap.example.com:636",
    ldap.WithUserDNTemplate("cn=%s,ou=users,dc=example,dc=com"),
    ldap.WithTLSConfig(tlsConfig),
)
```

#### WithTimeout

Set dial and read timeout:

```go
import "time"

auth, err := ldap.NewAuthenticator(
    "ldap://ldap.example.com",
    ldap.WithUserDNTemplate("uid=%s,ou=users,dc=example,dc=com"),
    ldap.WithTimeout(10 * time.Second),
)
```

Timeout applies to:
- Connection establishment
- LDAP bind operations
- Network read/write operations

## Authentication Flow

### Direct Bind Flow

1. Connect to LDAP server
2. Optionally perform StartTLS
3. Construct user DN from template
4. Bind with user DN and password
5. Return success or failure

### Service Account Flow

1. Connect to LDAP server
2. Optionally perform StartTLS
3. Bind with service account credentials
4. Construct user DN from template
5. Bind with user DN and password
6. Return success or failure

## Error Handling

```go
err := auth.Authenticate(ctx, "username", "password")

switch {
case err == nil:
    // Success
    log.Println("Authenticated")

case errors.Is(err, ldap.ErrMissingTemplate):
    // User DN template not configured
    log.Println("Configuration error: missing template")

case errors.Is(err, context.Canceled):
    // Context cancelled
    log.Println("Operation cancelled")

case errors.Is(err, context.DeadlineExceeded):
    // Timeout
    log.Println("LDAP operation timed out")

case strings.Contains(err.Error(), "bind failed"):
    // Invalid credentials
    log.Println("Invalid username or password")

case strings.Contains(err.Error(), "dial failed"):
    // Connection error
    log.Println("Cannot connect to LDAP server")

default:
    // Other errors
    log.Printf("Error: %v", err)
}
```

### Common Errors

```go
// Missing URL
auth, err := ldap.NewAuthenticator("")
// Error: "ldap: url must not be empty"

// Missing template
auth, err := ldap.NewAuthenticator("ldap://server")
err = auth.Authenticate(ctx, "user", "pass")
// Error: "ldap: user DN template must be configured"

// Empty credentials
err := auth.Authenticate(ctx, "", "password")
// Error: "ldap: username and password must not be empty"

err := auth.Authenticate(ctx, "user", "")
// Error: "ldap: username and password must not be empty"
```

## Active Directory Integration

### Basic AD Authentication

```go
auth, err := ldap.NewAuthenticator(
    "ldap://dc.example.com:389",
    ldap.WithUserDNTemplate("cn=%s,cn=users,dc=example,dc=com"),
    ldap.WithStartTLS(),
)
if err != nil {
    log.Fatal(err)
}

err = auth.Authenticate(ctx, "jdoe", "password")
```

### AD with Service Account

```go
auth, err := ldap.NewAuthenticator(
    "ldaps://dc.example.com:636",
    ldap.WithUserDNTemplate("cn=%s,cn=users,dc=example,dc=com"),
    ldap.WithServiceAccount(
        "cn=service,cn=users,dc=example,dc=com",
        "service-pass",
    ),
)
```

### AD Global Catalog

```go
// Use Global Catalog port for multi-domain forests
auth, err := ldap.NewAuthenticator(
    "ldap://gc.example.com:3268",
    ldap.WithUserDNTemplate("cn=%s,cn=users,dc=example,dc=com"),
)
```

## OpenLDAP Integration

### Basic OpenLDAP

```go
auth, err := ldap.NewAuthenticator(
    "ldap://openldap.example.com:389",
    ldap.WithUserDNTemplate("uid=%s,ou=people,dc=example,dc=com"),
    ldap.WithStartTLS(),
)
```

### OpenLDAP with Organizational Units

```go
// Multiple OUs in hierarchy
auth, err := ldap.NewAuthenticator(
    "ldap://openldap.example.com",
    ldap.WithUserDNTemplate("uid=%s,ou=employees,ou=people,dc=company,dc=com"),
)
```

## Integration with go-auth API

```go
import (
    "github.com/jhahn/go-auth/pkg/api"
    "github.com/jhahn/go-auth/pkg/ldap"
)

ldapAuth, _ := ldap.NewAuthenticator(
    "ldap://ldap.example.com",
    ldap.WithUserDNTemplate("uid=%s,ou=users,dc=example,dc=com"),
)

service, _ := api.NewService(api.Config{
    Backends: []api.Backend{
        {Name: api.BackendLDAP, Handler: api.LDAP(ldapAuth)},
    },
})

err := service.Login(ctx, api.LoginRequest{
    Backend:  api.BackendLDAP,
    Username: "user",
    Password: "pass",
})
```

## Advanced Usage

### Custom TLS with Client Certificates

```go
import (
    "crypto/tls"
    "crypto/x509"
)

// Load client certificate
cert, err := tls.LoadX509KeyPair("client.pem", "client-key.pem")
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

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    RootCAs:      caCertPool,
    MinVersion:   tls.VersionTLS12,
}

auth, err := ldap.NewAuthenticator(
    "ldaps://ldap.example.com:636",
    ldap.WithUserDNTemplate("cn=%s,ou=users,dc=example,dc=com"),
    ldap.WithTLSConfig(tlsConfig),
)
```

### Multiple LDAP Servers (Failover)

```go
servers := []string{
    "ldap://ldap1.example.com:389",
    "ldap://ldap2.example.com:389",
    "ldap://ldap3.example.com:389",
}

template := "uid=%s,ou=users,dc=example,dc=com"

var lastErr error

for _, server := range servers {
    auth, err := ldap.NewAuthenticator(
        server,
        ldap.WithUserDNTemplate(template),
        ldap.WithTimeout(5*time.Second),
    )
    if err != nil {
        lastErr = err
        continue
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    err = auth.Authenticate(ctx, "username", "password")
    cancel()

    if err == nil {
        log.Printf("Authenticated via %s", server)
        return nil
    }

    log.Printf("Server %s failed: %v", server, err)
    lastErr = err
}

return fmt.Errorf("all LDAP servers failed: %w", lastErr)
```

### Context with Timeout

```go
import "time"

ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

err := auth.Authenticate(ctx, "username", "password")
if err == context.DeadlineExceeded {
    log.Println("LDAP authentication timed out")
}
```

## Security Considerations

### Transport Security

1. **Always use TLS in production**
   - Prefer LDAPS (ldaps://) over StartTLS
   - Never transmit passwords over plaintext LDAP

2. **Verify server certificates**
   - Don't skip TLS verification
   - Use proper CA certificates

3. **Use strong TLS configuration**
   ```go
   tlsConfig := &tls.Config{
       MinVersion: tls.VersionTLS12,
       CipherSuites: []uint16{
           tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
           tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
       },
   }
   ```

### Credential Security

1. **Service account credentials**
   - Use read-only service accounts
   - Store credentials securely (environment variables, secret managers)
   - Rotate credentials regularly
   - Limit service account permissions

2. **User credentials**
   - Never log passwords
   - Clear password variables after use
   - Use secure memory if handling sensitive operations

3. **DN template security**
   - Validate username input (prevent LDAP injection)
   - Escape special characters in usernames
   - Use allowlist for valid username characters

### Best Practices

1. **Connection security**
   - Use LDAPS (636) instead of StartTLS when possible
   - Implement connection timeouts
   - Use connection pooling at application level

2. **Error handling**
   - Don't leak information in error messages
   - Log authentication attempts for auditing
   - Implement rate limiting for failed attempts

3. **Configuration**
   - Store LDAP URLs in configuration, not code
   - Use environment variables for secrets
   - Validate configuration at startup

## Performance

### Benchmark Results

Typical authentication latency:
- Local network: 10-50ms
- WAN: 50-200ms
- With TLS: +10-30ms overhead
- Active Directory: 20-100ms
- OpenLDAP: 10-50ms

Performance factors:
- Network latency to LDAP server
- Server processing time
- TLS handshake overhead
- Service account bind (if used)

### Optimization

- **Connection pooling** - Implement at application level
- **Timeout tuning** - Balance responsiveness vs reliability
- **Server placement** - Minimize network latency
- **LDAP replicas** - Use read replicas for better performance
- **Caching** - Cache successful authentications (with short TTL)

## Troubleshooting

### Connection Errors

```
Error: ldap: dial failed: connection refused
```

Causes:
- LDAP server not running
- Firewall blocking ports (389/636)
- Incorrect server address
- Network connectivity issues

Solutions:
1. Verify server is running: `ldapsearch -H ldap://server -x`
2. Check port access: `telnet server 389`
3. Verify firewall rules
4. Test DNS resolution

### Bind Failures

```
Error: ldap: user bind failed
```

Causes:
- Invalid username or password
- Incorrect DN template
- Account locked or expired
- Insufficient permissions

Solutions:
1. Verify DN template is correct
2. Test with ldapsearch:
   ```bash
   ldapsearch -H ldap://server -D "uid=user,ou=users,dc=example,dc=com" -W
   ```
3. Check LDAP server logs
4. Verify account status

### TLS Errors

```
Error: ldap: starttls failed: x509: certificate signed by unknown authority
```

Causes:
- CA certificate not trusted
- Self-signed certificate
- Certificate expired
- Hostname mismatch

Solutions:
```go
// Add CA certificate
caCert, _ := os.ReadFile("ca.pem")
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

tlsConfig := &tls.Config{
    RootCAs:    caCertPool,
    ServerName: "ldap.example.com",
}

auth, _ := ldap.NewAuthenticator(
    "ldaps://ldap.example.com",
    ldap.WithUserDNTemplate("cn=%s,ou=users,dc=example,dc=com"),
    ldap.WithTLSConfig(tlsConfig),
)
```

### Template Errors

```
Error: ldap: user DN template must be configured
```

Solution:
```go
// Always specify user DN template
auth, err := ldap.NewAuthenticator(
    "ldap://server",
    ldap.WithUserDNTemplate("uid=%s,ou=users,dc=example,dc=com"),
)
```

## Testing

### Mock Implementation

```go
type MockConn struct {
    bindErr     error
    startTLSErr error
}

func (m *MockConn) Bind(username, password string) error {
    return m.bindErr
}

func (m *MockConn) StartTLS(config *tls.Config) error {
    return m.startTLSErr
}

func (m *MockConn) Close() error {
    return nil
}

// Use in tests
func TestAuthentication(t *testing.T) {
    mockConn := &MockConn{}

    dialFunc := func(ctx context.Context) (ldap.LdapConn, error) {
        return mockConn, nil
    }

    auth, err := ldap.NewAuthenticator(
        "ldap://test",
        ldap.WithUserDNTemplate("cn=%s,dc=test"),
        ldap.WithDialContext(dialFunc),
    )
    if err != nil {
        t.Fatal(err)
    }

    err = auth.Authenticate(context.Background(), "user", "pass")
    // ... assertions
}
```

## Integration Tests

Run integration tests with an LDAP server:

```bash
# Export test configuration
export LDAP_URL=ldap://ldap.example.com:389
export LDAP_USER_DN_TEMPLATE="uid=%s,ou=users,dc=example,dc=com"
export LDAP_USERNAME=testuser
export LDAP_PASSWORD=testpass

# Run integration tests
cd test/integration/ldap
go test -v
```

Integration tests validate:
- LDAP connection
- LDAPS connection
- StartTLS upgrade
- Service account binding
- User authentication
- Error handling

## References

- [RFC 4511 - LDAP: The Protocol](https://www.rfc-editor.org/rfc/rfc4511)
- [RFC 4513 - LDAP: Authentication Methods](https://www.rfc-editor.org/rfc/rfc4513)
- [RFC 4514 - LDAP: String Representation of DNs](https://www.rfc-editor.org/rfc/rfc4514)
- [Active Directory LDAP](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/active-directory-ldap)
- [OpenLDAP Documentation](https://www.openldap.org/doc/)
