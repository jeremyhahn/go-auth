# Codebase Structure

```
go-auth/
├── pkg/
│   ├── api/          # Facade: Handler interface, Service, factory functions (PAM, RADIUS, etc.)
│   ├── pam/          # Linux PAM client
│   ├── radius/       # RADIUS client
│   ├── tacacs/       # TACACS+ client
│   ├── ldap/         # LDAP client
│   ├── pkcs11/       # PKCS#11 client
│   ├── yubikey/      # YubiKey client
│   ├── oauth/        # OAuth/OIDC 2.0 client
│   ├── otp/          # OTP (TOTP/HOTP) client
│   └── tpm2/         # TPM 2.0 client
├── examples/         # Usage examples
├── test/             # Test utilities/fixtures
├── Makefile          # Top-level build/test orchestration
├── go.mod / go.sum
└── README.md
```

## Key Types (pkg/api)
- `Handler` interface - core auth handler
- `Service` struct - multi-backend login service
- `BackendName` - enum for backend selection
- `Config`, `LoginRequest` - configuration and request types
- Factory functions: `PAM()`, `RADIUS()`, `TACACS()`, `LDAP()`, `OAuth()`, `OTP()`, `PKCS11()`, `YubiKey()`, `TPM2()`
