### Changed

- The Go toolchain moves to `1.27.1` in one pass: the module's `go`
  directive, `GO_VERSION` in `ci.yml` and `integration.yml`, and every
  integration image under `pkg/` (`FROM golang:1.27.1-bookworm`) ([#43]).
  Consumers now need Go 1.27.1, the portfolio toolchain.
- `pkg/secret`: go-enclave is raised from `v0.3.0-alpha` to `v0.6.1-alpha`
  ([#43]). The `MemoryEnclave` calls this package makes — `NewMemoryEnclave`,
  `NewMemoryEnclaveSized`, `WithBytes`, `Open`, `IsAlive`, `Size` and
  `Destroy` — have the same signatures and the same wipe-on-construct,
  wipe-and-unmap-on-destroy semantics, so `pkg/secret` needed no code change
  and its exported API and behaviour are unchanged. One tightening arrives
  with it: an enclave whose release failed after its material was wiped now
  reports itself destroyed, so `Open` on such a `Secret` returns
  `ErrDestroyed` rather than handing back zeroes.
- Every third-party module is brought to its latest release ([#43]):
  `golang.org/x/crypto` `v0.57.0`, `golang.org/x/sys` `v0.48.0`,
  `golang.org/x/oauth2` `v0.37.0`, `golang.org/x/time` `v0.16.0`,
  `github.com/go-ldap/ldap/v3` `v3.4.14`, `github.com/go-asn1-ber/asn1-ber`
  `v1.5.8`, `github.com/Azure/go-ntlmssp` `v0.1.1`,
  `github.com/MicahParks/keyfunc/v3` `v3.8.2`, `github.com/MicahParks/jwkset`
  `v0.11.3`, `github.com/google/go-tpm-tools` `v0.4.10` and
  `github.com/stretchr/testify` `v1.12.1`.

### Security

- The dependency moves clear three advisories govulncheck reported against
  this module ([#43]): GO-2026-5543, a panic on a malformed NTLM challenge in
  `github.com/Azure/go-ntlmssp`, whose package `pkg/ldap` imports through
  go-ldap (fixed in `v0.1.1`); and GO-2026-6354 and GO-2026-6355 in
  `golang.org/x/crypto` `v0.55.0` (fixed by `v0.57.0`). govulncheck found no
  call path to any of them from this module's code.

[#43]: https://github.com/jeremyhahn/go-auth/issues/43
