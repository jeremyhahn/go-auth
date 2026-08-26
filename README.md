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


## Protected memory

Keys, passwords, shared secrets and API keys are held in [protected memory](docs/secret.md) — a [go-enclave](https://github.com/jeremyhahn/go-enclave) `MemoryEnclave`: locked, guard-paged, non-swappable, undumpable memory — for their whole lifetime, and are read only inside the call that uses them. The entry points that take a credential as a Go string still work and are deprecated; see the [changelog](CHANGELOG.md).


## Support

Please consider supporting this project for ongoing success and sustainability. I'm a passionate open source contributor making a professional living creating free, secure, scalable, robust, enterprise grade, distributed systems and cloud native solutions.

I'm also available for international consulting opportunities. Please let me know how I can assist you or your organization in achieving your desired security posture and technology goals.

https://github.com/sponsors/jeremyhahn

https://www.linkedin.com/in/jeremyhahn
