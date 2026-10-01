FROM golang:1.27.0-bookworm

WORKDIR /workspace
COPY go.mod go.sum ./
# go.mod requires the private github.com/jeremyhahn/go-enclave. Its credentials
# arrive as the optional BuildKit secret `gomodauth`, staged by
# scripts/docker-build-integration.sh (go-auth#42): mounted on tmpfs for this
# RUN only and sourced, never exported into a layer, ARG or ENV. Absent, the
# modules resolve from the public proxy.
RUN --mount=type=secret,id=gomodauth,required=false \
    set -eu; \
    if [ -s /run/secrets/gomodauth ]; then . /run/secrets/gomodauth; fi; \
    go mod download
COPY . .

ENV CGO_ENABLED=0
CMD ["go", "test", "-v", "-tags", "integration", "./test/integration/tacacs"]
