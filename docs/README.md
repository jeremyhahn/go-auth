# go-auth Documentation

Comprehensive authentication library for Go with support for multiple authentication methods and hardware tokens.

## Overview

`go-auth` provides a unified interface for various authentication mechanisms, from traditional username/password systems to modern hardware-based authentication. The library is designed with modularity, testability, and security in mind.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                      API Layer                           │
│            (Unified Authentication Service)              │
└───────────────────────┬──────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        │                               │
        ▼                               ▼
┌───────────────┐              ┌───────────────┐
│   Software    │              │   Hardware    │
│ Authenticators│              │ Authenticators│
└───────┬───────┘              └───────┬───────┘
        │                               │
   ┌────┴────┐                     ┌────┴────┐
   │         │                     │         │
   ▼         ▼                     ▼         ▼
 PAM      OAuth               PKCS11    YubiKey
 LDAP     TACACS+             TPM2
 RADIUS   OTP
```

## Authentication Modules

### Software-Based Authentication

#### [PAM (Pluggable Authentication Modules)](pam.md)
- System-level authentication
- Integration with Linux/Unix auth stack
- Support for LDAP, Kerberos, local users
- **Use cases**: System authentication, SSH, sudo integration

#### [LDAP (Lightweight Directory Access Protocol)](ldap.md)
- Directory service authentication
- Active Directory and OpenLDAP support
- LDAPS and StartTLS support
- **Use cases**: Enterprise directory integration, SSO backends

#### [RADIUS (Remote Authentication Dial-In User Service)](radius.md)
- Network authentication protocol
- PAP and EAP-TLS support
- RadSec (RADIUS-over-TLS)
- **Use cases**: Network access, VPN, WiFi authentication

#### [TACACS+ (Terminal Access Controller Access-Control System Plus)](tacacs.md)
- Network device authentication
- Full packet encryption
- Privilege level support
- **Use cases**: Network device management, privileged access

#### [OAuth 2.0 / OpenID Connect](oauth.md)
- Modern web authentication
- Multiple OAuth flows (client credentials, password, authorization code)
- JWT validation and token introspection
- Pre-configured providers (Google, Microsoft, GitHub, etc.)
- **Use cases**: API authentication, web SSO, microservices

#### [OTP (One-Time Password - TOTP/HOTP)](otp.md)
- Time-based and counter-based OTP
- RFC 6238 (TOTP) and RFC 4226 (HOTP) compliant
- Compatible with authenticator apps (Google Authenticator, Authy, etc.)
- QR code provisioning support
- **Use cases**: Two-factor authentication, MFA, passwordless login

### Hardware-Based Authentication

#### [PKCS#11 (Cryptographic Token Interface)](pkcs11.md)
- Hardware security modules (HSMs)
- Smart cards and USB tokens
- PIN-based authentication
- **Use cases**: High-security environments, certificate-based auth

#### [YubiKey OTP](yubikey.md)
- YubiKey hardware token authentication
- One-time password validation
- Yubico cloud or self-hosted validation
- **Use cases**: Two-factor authentication, MFA

#### [TPM 2.0 (Trusted Platform Module)](tpm2.md)
- Hardware-based platform integrity
- PCR-based attestation
- Secret unsealing
- **Use cases**: Platform attestation, secure boot verification

## Quick Start

### Installation

```bash
go get github.com/jhahn/go-auth
```

### Basic Usage

```go
package main

import (
    "context"
    "log"

    "github.com/jhahn/go-auth/pkg/api"
    "github.com/jhahn/go-auth/pkg/ldap"
    "github.com/jhahn/go-auth/pkg/oauth"
    "github.com/jhahn/go-auth/pkg/otp"
)

func main() {
    ctx := context.Background()

    // Configure LDAP authentication
    ldapAuth, _ := ldap.NewAuthenticator(
        "ldap://ldap.example.com",
        ldap.WithUserDNTemplate("uid=%s,ou=users,dc=example,dc=com"),
    )

    // Configure OAuth authentication
    oauthAuth, _ := oauth.NewAuthenticator(&oauth.Config{
        Provider: oauth.Google(),
        Flow:     oauth.FlowTokenValidation,
        ClientID: "your-client-id",
        Validation: oauth.TokenValidationConfig{
            Method:  oauth.ValidationJWT,
            JWKSURL: "https://www.googleapis.com/oauth2/v3/certs",
        },
    })

    // Configure OTP authentication
    otpAuth, _ := otp.NewAuthenticator(otp.Config{
        Type:        otp.TypeTOTP,
        Secret:      "JBSWY3DPEHPK3PXP",
        Issuer:      "MyApp",
        AccountName: "user@example.com",
    })

    // Create unified authentication service
    service, _ := api.NewService(api.Config{
        Backends: []api.Backend{
            {Name: api.BackendLDAP, Handler: api.LDAP(ldapAuth)},
            {Name: api.BackendOAuth, Handler: api.OAuth(oauthAuth)},
            {Name: api.BackendOTP, Handler: api.OTP(otpAuth)},
        },
    })

    // Authenticate using LDAP
    err := service.Login(ctx, api.LoginRequest{
        Backend:  api.BackendLDAP,
        Username: "jdoe",
        Password: "password",
    })
    if err != nil {
        log.Printf("LDAP authentication failed: %v", err)
    }

    // Authenticate using OAuth token
    err = service.Login(ctx, api.LoginRequest{
        Backend:  api.BackendOAuth,
        Password: "oauth-access-token",
    })
    if err != nil {
        log.Printf("OAuth authentication failed: %v", err)
    }

    // Authenticate using OTP
    err = service.Login(ctx, api.LoginRequest{
        Backend:  api.BackendOTP,
        Password: "123456",
    })
    if err != nil {
        log.Printf("OTP authentication failed: %v", err)
    }
}
```

## Module Comparison

| Module | Type | Protocol | Transport | Primary Use Case |
|--------|------|----------|-----------|------------------|
| [PAM](pam.md) | Software | System | Local | System authentication |
| [LDAP](ldap.md) | Software | LDAP | TCP/TLS | Directory services |
| [RADIUS](radius.md) | Software | RADIUS | UDP/TCP+TLS | Network access |
| [TACACS+](tacacs.md) | Software | TACACS+ | TCP | Network devices |
| [OAuth](oauth.md) | Software | HTTP/HTTPS | HTTPS | Web/API auth |
| [OTP](otp.md) | Software | TOTP/HOTP | Local | 2FA, MFA |
| [PKCS#11](pkcs11.md) | Hardware | PKCS#11 | Local/Network | HSMs, Smart cards |
| [YubiKey](yubikey.md) | Hardware | HTTPS | HTTPS | Hardware tokens |
| [TPM2](tpm2.md) | Hardware | TPM | Local | Platform integrity |

## Common Patterns

### Error Handling

All modules follow consistent error handling:

```go
err := authenticator.Authenticate(ctx, credentials...)

switch {
case err == nil:
    // Success
case errors.Is(err, context.Canceled):
    // Operation cancelled
case errors.Is(err, context.DeadlineExceeded):
    // Timeout
default:
    // Module-specific error
}
```

### Context Management

All modules support context for timeouts and cancellation:

```go
import "time"

// With timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

err := auth.Authenticate(ctx, username, password)

// With cancellation
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

go func() {
    <-sigChan
    cancel()
}()

err := auth.Authenticate(ctx, username, password)
```

### Testing

All modules provide interface-based designs for testing:

```go
// Mock implementations for testing
type MockValidator struct {
    result error
}

func (m *MockValidator) Validate(...) error {
    return m.result
}

// Use in tests
mockValidator := &MockValidator{result: nil}
auth, _ := NewAuthenticator(config, mockValidator)
```

## Security Best Practices

### General Recommendations

1. **Always use TLS/encryption in production**
   - LDAPS instead of LDAP
   - RadSec instead of RADIUS
   - HTTPS for OAuth

2. **Implement timeouts**
   - Use context with deadlines
   - Prevent indefinite hangs
   - Balance responsiveness vs reliability

3. **Validate inputs**
   - Sanitize usernames and passwords
   - Prevent injection attacks
   - Check configuration at startup

4. **Secure credential storage**
   - Use environment variables
   - Leverage secret managers
   - Never commit secrets to version control

5. **Audit logging**
   - Log all authentication attempts
   - Include timestamps and outcomes
   - Monitor for suspicious patterns

6. **Rate limiting**
   - Implement at application level
   - Prevent brute force attacks
   - Use exponential backoff

### Module-Specific Security

- **PAM**: Requires appropriate system permissions
- **LDAP**: Always use TLS, validate server certificates
- **RADIUS**: Use strong shared secrets, prefer RadSec
- **TACACS+**: Secure shared secrets, monitor failed attempts
- **OAuth**: Validate issuer and audience, use PKCE
- **OTP**: Secure secret storage, implement rate limiting, use backup codes
- **PKCS#11**: Protect PINs, monitor lockout attempts
- **YubiKey**: Bind YubiKeys to user accounts, prevent replay
- **TPM2**: Reseal after platform updates, monitor PCR changes

## Performance Considerations

### Latency Comparison

Typical authentication latency (local network):

| Module | Latency | Notes |
|--------|---------|-------|
| PAM | 5-20ms | Local system calls |
| LDAP | 10-50ms | Network + directory lookup |
| RADIUS | 5-20ms | UDP, minimal overhead |
| TACACS+ | 10-30ms | TCP, full encryption |
| OAuth | 50-200ms | HTTPS + validation |
| OTP | <1ms | Local computation |
| PKCS#11 | 50-200ms | Hardware operation |
| YubiKey | 100-500ms | Cloud validation |
| TPM2 | 10-30ms | Local hardware |

### Optimization Strategies

1. **Connection pooling** - Reuse connections where applicable
2. **Caching** - Cache validation results (with security considerations)
3. **Parallel authentication** - Try multiple backends concurrently
4. **Timeout tuning** - Balance speed vs reliability
5. **Local validators** - Self-host services when possible

## Build Requirements

### CGO Dependencies

Some modules require CGO:

```bash
# PAM
sudo apt-get install libpam0g-dev
CGO_ENABLED=1 go build -tags pam

# PKCS#11
sudo apt-get install libpcsclite-dev
CGO_ENABLED=1 go build -tags pkcs11
```

### Pure Go Modules

These modules work without CGO:
- LDAP
- RADIUS
- TACACS+
- OAuth
- OTP
- YubiKey (with custom validator)
- TPM2 (with go-tpm)

## Testing

### Unit Tests

Run unit tests for all modules:

```bash
go test ./pkg/...
```

### Integration Tests

Integration tests require actual services:

```bash
# Set up test services (see module docs)
docker-compose up -d

# Run integration tests
go test -tags integration ./test/integration/...
```

### Coverage

Check test coverage:

```bash
go test -cover ./pkg/...
```

Target coverage: 90%+ for all modules

## Examples

Example code for each module:

```bash
examples/
├── pam_example.go
├── ldap_example.go
├── radius_example.go
├── tacacs_example.go
├── oauth_example.go
├── otp_example.go
├── pkcs11_example.go
├── yubikey_example.go
└── tpm2_example.go
```

See individual module documentation for detailed examples.

## Troubleshooting

### Common Issues

1. **Connection timeouts**
   - Increase context deadline
   - Check network connectivity
   - Verify firewall rules

2. **Authentication failures**
   - Verify credentials
   - Check server logs
   - Test with known-good credentials

3. **Build errors**
   - Install required development libraries
   - Enable CGO for certain modules
   - Use correct build tags

4. **Certificate errors**
   - Add CA certificates to trust store
   - Verify certificate validity
   - Check hostname matching

### Debug Logging

Enable debug logging in each module (implementation varies):

```go
// Example for OAuth module
config.Debug = true
```

## Migration Guide

### From v1.x to v2.x

(Include migration instructions when applicable)

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

See [LICENSE](../LICENSE) for details.

## Support

- **Documentation**: This directory
- **Issues**: GitHub issue tracker
- **Examples**: `examples/` directory
- **Integration Tests**: `test/integration/` directory

## Module Documentation

- [PAM Authentication](pam.md) - System authentication
- [LDAP Authentication](ldap.md) - Directory services
- [RADIUS Authentication](radius.md) - Network access
- [TACACS+ Authentication](tacacs.md) - Network devices
- [OAuth 2.0 / OIDC](oauth.md) - Web and API authentication
- [OTP (TOTP/HOTP)](otp.md) - One-time passwords and 2FA
- [PKCS#11 Authentication](pkcs11.md) - Hardware security modules
- [YubiKey OTP](yubikey.md) - Hardware tokens
- [TPM 2.0 Authentication](tpm2.md) - Platform integrity

## Additional Resources

### Standards and Specifications

- [RFC 4511 - LDAP](https://www.rfc-editor.org/rfc/rfc4511)
- [RFC 2865 - RADIUS](https://www.rfc-editor.org/rfc/rfc2865)
- [RFC 8907 - TACACS+](https://www.rfc-editor.org/rfc/rfc8907)
- [RFC 6749 - OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7515 - JWT](https://www.rfc-editor.org/rfc/rfc7515)
- [RFC 6238 - TOTP](https://www.rfc-editor.org/rfc/rfc6238)
- [RFC 4226 - HOTP](https://www.rfc-editor.org/rfc/rfc4226)
- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/)
- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)

### Third-Party Libraries

- [go-ldap](https://github.com/go-ldap/ldap) - LDAP client
- [layeh/radius](https://github.com/layeh/radius) - RADIUS protocol
- [nwaples/tacplus](https://github.com/nwaples/tacplus) - TACACS+ client
- [pquerna/otp](https://github.com/pquerna/otp) - OTP library
- [google/go-tpm](https://github.com/google/go-tpm) - TPM 2.0 library
- [miekg/pkcs11](https://github.com/miekg/pkcs11) - PKCS#11 bindings

### Recommended Reading

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) - Digital Identity Guidelines
- [Linux PAM Documentation](http://www.linux-pam.org/)
- [Active Directory LDAP](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/active-directory-ldap)
