# Suggested Commands

## Testing
- `make test` - Run lint + all module unit tests
- `make integration-test` - Run all module integration tests
- `make <module>-test` - Test specific module (e.g., `make oauth-test`, `make tpm2-test`)
- `make <module>-integration-test` - Integration test specific module

## Linting
- `make lint` - Run `go vet` on all packages (excluding examples)

## Cleaning
- `make clean` - Clear Go caches

## Available module targets
pam, radius, tacacs, ldap, pkcs11, yubikey, oauth, otp, tpm2
