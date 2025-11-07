FROM golang:1.25-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        softhsm2 \
        libpam0g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download
COPY . .

ENV SOFTHSM2_CONF=/tmp/softhsm2.conf
RUN mkdir -p /tmp/tokens && \
    echo "directories.tokendir = /tmp/tokens" > $SOFTHSM2_CONF && \
    softhsm2-util --init-token --free --label go-auth-token --so-pin 123456 --pin 654321

ENV CGO_ENABLED=1
ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so

CMD ["go", "test", "-tags", "integration pkcs11", "./test/integration/auth"]
