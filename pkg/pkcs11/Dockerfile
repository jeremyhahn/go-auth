FROM golang:1.27.0-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        softhsm2 \
        libpam0g-dev \
    && rm -rf /var/lib/apt/lists/*

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

ENV SOFTHSM2_CONF=/tmp/softhsm2.conf
RUN mkdir -p /tmp/tokens && \
    echo "directories.tokendir = /tmp/tokens" > $SOFTHSM2_CONF && \
    softhsm2-util --init-token --free --label go-auth-token --so-pin 123456 --pin 654321

ENV CGO_ENABLED=1
ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so

CMD ["go", "test", "-tags", "integration pkcs11", "./test/integration/auth"]
