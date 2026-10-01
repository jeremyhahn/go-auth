FROM golang:1.27.0-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpam0g-dev \
        libpam-modules \
        libpam-modules-bin \
        libpam-runtime \
        passwd \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin pamuser \
    && echo 'pamuser:secretpw' | chpasswd \
    && useradd -m -s /usr/sbin/nologin expireduser \
    && echo 'expireduser:secretpw' | chpasswd \
    && chage -E 0 expireduser

RUN printf 'auth    required    pam_unix.so\naccount required    pam_unix.so\n' > /etc/pam.d/go-auth-test

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

ENV CGO_ENABLED=1
CMD ["go", "test", "-v", "-tags", "integration", "./test/integration/pam" ]
