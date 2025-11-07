# PAM (Pluggable Authentication Modules) Package

The `pam` package provides authentication against the system's Pluggable Authentication Modules stack, enabling integration with standard Linux/Unix authentication mechanisms.

## Overview

PAM authentication validates credentials using the host operating system's configured authentication stack. This enables applications to leverage existing PAM configurations for authentication, including local users, LDAP, Kerberos, and other PAM-supported authentication backends.

## Architecture

The module uses an interface-based design for testability and flexibility:

```
┌─────────────────┐
│  Authenticator  │
└────────┬────────┘
         │
         ▼
  ┌──────────────┐      ┌────────────┐
  │    Service   │      │   Opener   │
  └──────────────┘      └──────┬─────┘
                               │
                               ▼
                        ┌──────────────┐
                        │   Session    │
                        └──────────────┘
```

### Components

- **Authenticator**: Main authentication orchestrator
- **SessionOpener**: Interface for creating PAM sessions (enables testing)
- **Session**: Interface representing an active PAM transaction
- **Service**: PAM service configuration name (e.g., "login", "sshd", "sudo")

## Configuration

PAM authentication requires a service name that corresponds to a configuration file in `/etc/pam.d/`:

```go
type Authenticator struct {
    service       string
    sessionOpener SessionOpener
}
```

### Service Names

Common PAM service names:
- `login` - Standard system login
- `sshd` - SSH daemon authentication
- `sudo` - Sudo privilege elevation
- `su` - User switching
- `passwd` - Password changes
- Custom service names defined in `/etc/pam.d/`

## Usage

### Basic Authentication

```go
package main

import (
    "context"
    "log"

    "github.com/jeremyhahn/go-auth/pkg/pam"
)

func main() {
    // Create authenticator using "login" PAM service
    auth, err := pam.NewAuthenticator("login", nil)
    if err != nil {
        log.Fatal(err)
    }

    // Authenticate user
    ctx := context.Background()
    err = auth.Authenticate(ctx, "username", "password")
    if err != nil {
        log.Printf("Authentication failed: %v", err)
        return
    }

    log.Println("Authentication successful")
}
```

### Custom Service Configuration

```go
// Use a custom PAM service (requires /etc/pam.d/myapp)
auth, err := pam.NewAuthenticator("myapp", nil)
if err != nil {
    log.Fatal(err)
}

err = auth.Authenticate(ctx, "user", "pass")
```

### Context Management

```go
import "time"

// With timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

err := auth.Authenticate(ctx, "username", "password")
if err == context.DeadlineExceeded {
    log.Println("Authentication timed out")
}

// With cancellation
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

go func() {
    <-sigChan
    cancel() // Cancel authentication on signal
}()

err = auth.Authenticate(ctx, "username", "password")
```

## Testing

The module uses interface-based design for easy testing without requiring actual PAM libraries:

```go
type MockSessionOpener struct {
    session *MockSession
    err     error
}

func (m *MockSessionOpener) Open(ctx context.Context, service, username string) (pam.Session, error) {
    if m.err != nil {
        return nil, m.err
    }
    return m.session, nil
}

type MockSession struct {
    authErr  error
    closeErr error
}

func (m *MockSession) Authenticate(ctx context.Context, password string) error {
    return m.authErr
}

func (m *MockSession) Close() error {
    return m.closeErr
}

// Use in tests
func TestMyCode(t *testing.T) {
    mockOpener := &MockSessionOpener{
        session: &MockSession{},
    }

    auth, err := pam.NewAuthenticator("test", mockOpener)
    if err != nil {
        t.Fatal(err)
    }

    err = auth.Authenticate(context.Background(), "user", "pass")
    // ... assertions
}
```

## Build Requirements

### CGO Build (Production)

PAM integration requires CGO and PAM development libraries:

```bash
# Install PAM development libraries
# Debian/Ubuntu:
sudo apt-get install libpam0g-dev

# RHEL/CentOS/Fedora:
sudo dnf install pam-devel

# Build with CGO
CGO_ENABLED=1 go build -tags pam
```

### Stub Build (Testing)

For testing without PAM libraries, use the default build (without CGO):

```bash
# Build without PAM support (mock only)
CGO_ENABLED=0 go build
```

Without CGO, creating an authenticator with `nil` opener will fail with:
```
pam: system session opener unavailable; requires cgo build with PAM support
```

## PAM Configuration

PAM service files are located in `/etc/pam.d/`. Example configuration:

### /etc/pam.d/myapp

```
# Authentication
auth       required     pam_unix.so
auth       required     pam_succeed_if.so quiet uid >= 1000

# Account validation
account    required     pam_unix.so
account    required     pam_permit.so

# Password management
password   required     pam_unix.so sha512 shadow

# Session setup
session    required     pam_unix.so
session    optional     pam_systemd.so
```

### Common PAM Modules

- **pam_unix.so** - Traditional Unix authentication (local users)
- **pam_ldap.so** - LDAP authentication
- **pam_krb5.so** - Kerberos authentication
- **pam_sss.so** - System Security Services Daemon (SSSD)
- **pam_google_authenticator.so** - Two-factor authentication
- **pam_succeed_if.so** - Conditional authentication rules

## Error Handling

```go
err := auth.Authenticate(ctx, "username", "password")

switch {
case err == nil:
    // Success
    log.Println("Authenticated")

case errors.Is(err, context.Canceled):
    // Context cancelled
    log.Println("Operation cancelled")

case errors.Is(err, context.DeadlineExceeded):
    // Timeout
    log.Println("Authentication timed out")

default:
    // PAM-specific errors (invalid credentials, account locked, etc.)
    log.Printf("PAM error: %v", err)
}
```

Common PAM errors include:
- Invalid username or password
- Account expired or locked
- Password expired (needs change)
- Insufficient permissions
- PAM configuration error

## Integration with go-auth API

Use PAM with the api package:

```go
import (
    "github.com/jeremyhahn/go-auth/pkg/api"
    "github.com/jeremyhahn/go-auth/pkg/pam"
)

pamAuth, _ := pam.NewAuthenticator("login", nil)

service, _ := api.NewService(api.Config{
    Backends: []api.Backend{
        {Name: api.BackendPAM, Handler: api.PAM(pamAuth)},
    },
})

err := service.Login(ctx, api.LoginRequest{
    Backend:  api.BackendPAM,
    Username: "user",
    Password: "pass",
})
```

## Security Considerations

### Privilege Requirements

PAM authentication typically requires:
- Read access to `/etc/pam.d/` configuration
- Ability to execute PAM modules (may require elevated privileges)
- Access to user database (varies by PAM configuration)

Some PAM configurations require root privileges or specific group membership.

### Service Configuration Security

1. **Limit authentication methods** - Only enable necessary PAM modules
2. **Enforce account policies** - Use `pam_succeed_if.so` for restrictions
3. **Enable logging** - Use `pam_unix.so` with audit flags
4. **Rate limiting** - Consider `pam_faildelay.so` and `pam_faillock.so`
5. **Two-factor authentication** - Layer additional PAM modules when needed

### Input Validation

The module validates:
- Service name must not be empty
- Username must not be empty
- Password must not be empty

Always use parameterized PAM configurations to prevent injection attacks.

## Performance

### Benchmark Results

Typical authentication latency:
- Local user (pam_unix): 5-20ms
- LDAP backend: 50-200ms
- Kerberos backend: 20-100ms

Performance depends heavily on the underlying PAM configuration and backend systems.

### Optimization

- **Cache credentials** - At application level when appropriate
- **Use service accounts** - For non-interactive authentication
- **Configure timeouts** - Use context deadlines to prevent hangs
- **Connection pooling** - For LDAP/Kerberos backends (configured in PAM)

## Troubleshooting

### PAM Unavailable Error

```
Error: pam: system session opener unavailable
```

Causes:
- Built without CGO support
- PAM development libraries not installed
- Incorrect build tags

Solution:
```bash
CGO_ENABLED=1 go build -tags pam
```

### Authentication Failures

```
Error: authentication error
```

Check:
1. Verify PAM service configuration exists: `ls /etc/pam.d/myapp`
2. Test with `pamtester`: `pamtester myapp username authenticate`
3. Check system logs: `journalctl -xe | grep pam`
4. Verify file permissions on `/etc/pam.d/` and service file
5. Ensure application has required privileges

### Permission Denied

```
Error: permission denied
```

Some PAM modules require elevated privileges:
- Run application as root (not recommended)
- Use sudo with specific capabilities
- Configure PAM to use modules that don't require root
- Adjust file permissions on authentication databases

## Integration Tests

Integration tests require a working PAM installation:

```bash
# Run integration tests (requires PAM libraries)
cd test/integration/pam
CGO_ENABLED=1 go test -v
```

Tests validate:
- Authenticator creation
- Successful authentication
- Failed authentication
- Context cancellation
- Session cleanup

## Best Practices

1. **Use appropriate service names** - Match your application's purpose
2. **Handle errors gracefully** - PAM errors can be user-facing
3. **Implement timeouts** - Prevent hangs on slow backends
4. **Log authentication attempts** - For security auditing
5. **Don't leak information** - Generic error messages for failed auth
6. **Test with mock opener** - Unit tests shouldn't require PAM
7. **Document PAM requirements** - For deployment and operations

## References

- [Linux-PAM Documentation](http://www.linux-pam.org/)
- [PAM Configuration Guide](http://www.linux-pam.org/Linux-PAM-html/sag-configuration.html)
- [PAM Module Reference](http://www.linux-pam.org/Linux-PAM-html/sag-module-reference.html)
- [PAM Application Developer's Guide](http://www.linux-pam.org/Linux-PAM-html/adg-introduction.html)
