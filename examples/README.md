# go-auth Examples

This directory contains comprehensive examples for all authentication modules in the go-auth library.

## Overview

Each example demonstrates real-world usage patterns for different authentication backends. Examples are organized by module and include:

- Configuration setup
- Authentication flows
- Error handling
- Context usage
- Best practices

## Available Examples

| Module | Example | Description | Prerequisites |
|--------|---------|-------------|---------------|
| **API** | `api/multi_backend_example.go` | Multi-backend integration with fallback | None |
| **OAuth** | `oauth/token_validation_example.go` | JWT token validation with JWKS | OAuth provider credentials |
| | `oauth/client_credentials_example.go` | Machine-to-machine authentication | OAuth client ID/secret |
| | `oauth/pkce_example.go` | Authorization code flow with PKCE | OAuth client configuration |
| **OTP** | `otp/totp_example.go` | Time-based one-time passwords | None |
| | `otp/hotp_example.go` | Counter-based one-time passwords | None |
| **PAM** | `pam/basic_example.go` | System authentication via PAM | PAM libraries, CGO enabled |
| **LDAP** | `ldap/basic_example.go` | LDAP bind authentication | LDAP server |
| **RADIUS** | `radius/pap_example.go` | PAP authentication | RADIUS server |
| | `radius/eap_tls_example.go` | EAP-TLS with certificates | RADIUS server, client certs |
| **TACACS+** | `tacacs/basic_example.go` | TACACS+ authentication | TACACS+ server |
| **PKCS#11** | `pkcs11/basic_example.go` | Smart card/HSM authentication | PKCS#11 library, token |
| **YubiKey** | `yubikey/basic_example.go` | YubiKey OTP validation | YubiCloud API credentials |
| **TPM 2.0** | `tpm2/basic_example.go` | TPM unsealing with PCR validation | TPM 2.0 device |

## Running Examples

### Basic Usage

Each example is a standalone Go program that can be run directly:

```bash
cd examples/<module>
go run <example>.go
```

For example:

```bash
cd examples/otp
go run totp_example.go
```

### Module-Specific Prerequisites

#### PAM
- **Requirements**: PAM development libraries, CGO enabled
- **Install**: `apt-get install libpam0g-dev` (Debian/Ubuntu)
- **Build**: `CGO_ENABLED=1 go run pam/basic_example.go`

#### LDAP
- **Requirements**: LDAP server accessible
- **Configuration**: Update server URL and DN template in example
- **Testing**: Use OpenLDAP or Active Directory

#### RADIUS
- **Requirements**: RADIUS server (FreeRADIUS recommended)
- **Configuration**: Update server address and shared secret
- **EAP-TLS**: Requires client certificates

#### TACACS+
- **Requirements**: TACACS+ server
- **Configuration**: Update server address and shared secret
- **Port**: Default is 49

#### PKCS#11
- **Requirements**: PKCS#11 library (SoftHSM, OpenSC, or hardware token)
- **Setup**:
  ```bash
  # Install SoftHSM for testing
  apt-get install softhsm2
  softhsm2-util --init-token --slot 0 --label MyToken
  ```
- **Configuration**: Update module path in example

#### YubiKey
- **Requirements**: YubiKey hardware, YubiCloud API credentials
- **Setup**:
  1. Get API key: https://upgrade.yubico.com/getapikey/
  2. Update ClientID and APIKey in example
  3. Generate OTP by pressing YubiKey button

#### TPM 2.0
- **Requirements**: TPM 2.0 device or emulator
- **Install tools**: `apt-get install tpm2-tools`
- **Software TPM**: `apt-get install swtpm swtpm-tools`
- **Setup**: Create sealed object with tpm2_create before running

#### OAuth
- **Token Validation**: Requires OAuth provider configuration (Google, Auth0, etc.)
- **Client Credentials**: Requires service account credentials
- **PKCE**: Requires OAuth client with redirect URI configured

## Example Structure

All examples follow a consistent pattern:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/jeremyhahn/go-auth/pkg/<module>"
)

func main() {
    // 1. Create authenticator with configuration
    auth, err := <module>.NewAuthenticator(config)
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close() // if applicable

    // 2. Create context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // 3. Perform authentication
    err = auth.Authenticate(ctx, credentials...)
    if err != nil {
        log.Printf("Authentication failed: %v", err)
        return
    }

    fmt.Println("✓ Authentication successful!")
}
```

## Configuration Best Practices

### Security
- **Never hardcode credentials** in production code
- Use environment variables or secure configuration management
- Enable TLS/encryption for network authentication (LDAP, RADIUS)
- Validate certificates in production (disable `InsecureSkipVerify`)

### Timeouts
- Always use `context.WithTimeout()` for authentication operations
- Set appropriate timeouts based on network conditions
- Consider retry logic for network-based authentication

### Error Handling
- Check for specific error types (e.g., `ErrInvalidPIN`, `ErrRejected`)
- Log authentication failures for security monitoring
- Provide helpful error messages for debugging

## Testing

### Unit Testing
Most modules support dependency injection for testing:

```go
// Example: PAM with mock session opener
auth, err := pam.NewAuthenticator("login", mockOpener)

// Example: TPM with mock provider
auth, err := tpm2.NewAuthenticator(cfg, mockProvider)
```

### Integration Testing
See `test/integration/` directory for comprehensive integration tests.

## API Integration

The `api/multi_backend_example.go` demonstrates how to combine multiple authentication backends:

```go
service, err := api.NewService(api.Config{
    Backends: []api.Backend{
        {Name: api.BackendOAuth, Handler: api.OAuth(oauthAuth)},
        {Name: api.BackendOTP, Handler: api.OTP(otpAuth)},
        {Name: api.BackendLDAP, Handler: api.LDAP(ldapAuth)},
    },
})
```

This allows:
- **Multiple authentication methods** in one application
- **Fallback authentication** (tries backends in order)
- **Targeted backend selection** via request parameters

## Common Issues

### PAM: "system session opener unavailable"
- **Cause**: Binary not built with CGO
- **Solution**: Build with `CGO_ENABLED=1`

### LDAP: "user DN template must be configured"
- **Cause**: Missing DN template in configuration
- **Solution**: Use `WithUserDNTemplate("uid=%s,ou=users,dc=example,dc=com")`

### RADIUS: Connection timeout
- **Cause**: Firewall or incorrect server address
- **Solution**: Verify server reachability and port (typically 1812)

### PKCS#11: "module path must not be empty"
- **Cause**: Missing PKCS#11 library path
- **Solution**: Find library path with `find /usr -name "*.so" | grep -i pkcs11`

### TPM: "device unavailable"
- **Cause**: No TPM device or insufficient permissions
- **Solution**: Check `/dev/tpm*` exists and you have access rights

## Further Reading

- **Documentation**: See `docs/` directory for detailed module documentation
- **Integration Tests**: See `test/integration/` for working test examples
- **API Reference**: Run `go doc github.com/jeremyhahn/go-auth/pkg/<module>`

## Contributing

When adding new examples:

1. Follow the established pattern (50-150 lines)
2. Include clear comments explaining each step
3. Show error handling best practices
4. Add prerequisites and setup instructions
5. Update this README with the new example

## License

Examples are provided under the same license as the go-auth library.
