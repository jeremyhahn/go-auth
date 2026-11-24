FROM golang:1.27.2-bookworm

WORKDIR /workspace
COPY go.mod go.sum ./
# Private module credentials arrive as the optional BuildKit secret gomodauth, mounted on tmpfs for this RUN only.
RUN --mount=type=secret,id=gomodauth,required=false \
    set -eu; \
    if [ -s /run/secrets/gomodauth ]; then . /run/secrets/gomodauth; fi; \
    go mod download
COPY . .

ENV CGO_ENABLED=0
CMD ["go", "test", "-v", "-tags", "integration", "./test/integration/ldap"]
