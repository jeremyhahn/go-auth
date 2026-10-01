# go-auth

My client authentication libraries for Golang.


## Libraries

- LDAP
- OAuth/OIDC 2.0
- Linux PAM
- PKCS #11
- RADIUS
- TACACS+
- TPM 2.0
- Yubikey


## Facade

The [api package](pkg/api/) contains a factory pattern for working with all of the clients through a uniform constructor.


## Credentials

Every credential — passwords, PINs, one-time passwords, shared secrets, API keys, OTP seeds, OAuth secrets and tokens — is a [go-enclave](https://github.com/jeremyhahn/go-enclave) `*enclave.MemoryEnclave`: locked, guard-paged, non-swappable, undumpable memory, read only inside the call that uses it. There is no plaintext-string credential path. See [Credentials](docs/credentials.md) for the ownership rules, and the [credential residue register](docs/security/credential-residues.md) for the finite, CI-gated places where a dependency still forces plaintext out of locked memory.


## Support

Please consider supporting this project for ongoing success and sustainability. I'm a passionate open source contributor making a professional living creating free, secure, scalable, robust, enterprise grade, distributed systems and cloud native solutions.

I'm also available for international consulting opportunities. Please let me know how I can assist you or your organization in achieving your desired security posture and technology goals.

https://github.com/sponsors/jeremyhahn

https://www.linkedin.com/in/jeremyhahn
