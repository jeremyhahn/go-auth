# go-auth

Client authentication libraries for Go providing a unified facade over multiple auth backends.

## Purpose
Provides pluggable authentication client libraries with a factory-pattern facade (`pkg/api`) for uniform access.

## Supported Backends
- LDAP
- OAuth/OIDC 2.0
- Linux PAM
- PKCS #11
- RADIUS
- TACACS+
- TPM 2.0
- YubiKey
- OTP

## Tech Stack
- Language: Go 1.25.5
- Module: `github.com/jeremyhahn/go-auth`
- Build: Makefile
- No external framework; pure library

## Architecture
- `pkg/api/` - Facade with factory pattern (`NewService`, `Login`, backend constructors)
- `pkg/{pam,radius,tacacs,ldap,pkcs11,yubikey,oauth,otp,tpm2}/` - Per-backend implementations
- Each backend module has its own Makefile for testing
- `examples/` - Usage examples
- `test/` - Test utilities/fixtures
