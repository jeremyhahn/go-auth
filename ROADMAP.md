# go-auth roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-08
> Changes are proposed by docs-only PR.

## Mission

Layer 0 library of external authentication backends: LDAP, PAM, TACACS+ and RADIUS.
Also provides OAuth2/OIDC, OTP, PKCS #11, TPM 2.0 and YubiKey clients behind one factory facade.
Every credential is held in go-enclave locked memory, never as a plaintext string.

## Current milestone

[Release candidate (M8)](../../milestone/8), target kind RC.
Projected 2026-10-15.

## Now

- [#41](../../issues/41) public release readiness confirmed — blocked: factory:escalated, awaiting owner answer
- [#64](../../issues/64) every doc carries a status banner and verified stamp — open

## Next

Nothing queued. New work arrives as issues.

## Later

Nothing accepted. New work arrives as issues.

## Dependencies

- Up: go-enclave v0.8.0-alpha
- Down: go-quicbaas (`pkg/otp`), go-recountly (`pkg/oauth`); go-trusted-platform indirectly

## Non-goals

- Credential memory protection; go-enclave owns it.
- Application authorization, sessions and identity storage; consumers own them.
- Ownership boundaries: [../handbook/software/docs/00-ownership-and-sdk-boundary.md](../handbook/software/docs/00-ownership-and-sdk-boundary.md)
