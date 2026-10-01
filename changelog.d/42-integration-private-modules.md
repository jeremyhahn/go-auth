### Fixed

- CI: the `Integration` workflow is green again ([#42]). Every integration
  image build failed at `RUN go mod download`: `go.mod` requires the private
  `github.com/jeremyhahn/go-enclave`, and `docker build` inherits none of the
  job's private-module configuration. The seven integration images now build
  through `scripts/docker-build-integration.sh`. The script stages `GOPRIVATE`
  and the `GIT_CONFIG_*` rewrite in a 0600 file outside the build context,
  hands it over as the optional BuildKit secret `gomodauth`, and removes it on
  every exit path. Each Dockerfile sources that secret for its single
  `go mod download` only, so the token reaches no layer, no image metadata and
  no command line. Without credentials, the build resolves from the public
  proxy. `test/ci` holds the Dockerfiles, Makefiles and script to this.

[#42]: https://github.com/jeremyhahn/go-auth/issues/42
