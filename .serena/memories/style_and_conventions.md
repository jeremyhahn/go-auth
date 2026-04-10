# Style and Conventions

- Standard Go conventions (gofmt, go vet)
- Interface-driven design: `Handler` interface with per-backend implementations
- Factory pattern via top-level constructor functions (`PAM()`, `RADIUS()`, etc.)
- Each backend is a separate sub-package under `pkg/`
- Each backend has its own Makefile for independent test execution
- CGO_ENABLED=0 for linting (some backends may need CGO for actual compilation, e.g., PAM, PKCS#11)
- Error variables defined as package-level `var` (e.g., `ErrNoBackends`, `ErrBackendNotFound`)
