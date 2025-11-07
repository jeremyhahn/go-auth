FROM golang:1.25-bookworm

# Install dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        sqlite3 \
        netcat-openbsd \
        jq \
    && rm -rf /var/lib/apt/lists/*

# Install ORY Hydra using install script
RUN bash -c "bash <(curl https://raw.githubusercontent.com/ory/meta/master/install.sh) -b /usr/local/bin hydra v2.2.0"

# Setup workspace
WORKDIR /workspace

# Copy Go module files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Copy test setup script
COPY pkg/oauth/testdata/setup-hydra.sh /setup-hydra.sh
RUN chmod +x /setup-hydra.sh

# Environment variables for Hydra
ENV SECRETS_SYSTEM=youReallyNeedToChangeThis \
    DSN=memory \
    URLS_SELF_ISSUER=http://127.0.0.1:4444/ \
    URLS_CONSENT=http://127.0.0.1:3000/consent \
    URLS_LOGIN=http://127.0.0.1:3000/login \
    SERVE_PUBLIC_PORT=4444 \
    SERVE_ADMIN_PORT=4445 \
    SERVE_PUBLIC_CORS_ENABLED=true \
    SERVE_ADMIN_CORS_ENABLED=true \
    LOG_LEVEL=error \
    CGO_ENABLED=0

# Start Hydra, set up test clients, and run integration tests
CMD ["bash", "-c", "\
    hydra serve all --dev & HYDRA_PID=$!; \
    echo 'Waiting for Hydra to start...'; \
    for i in {1..30}; do \
        if curl -s http://127.0.0.1:4444/health/ready > /dev/null 2>&1; then \
            echo 'Hydra is ready'; \
            break; \
        fi; \
        if [ $i -eq 30 ]; then \
            echo 'Hydra failed to start'; \
            kill $HYDRA_PID 2>/dev/null || true; \
            exit 1; \
        fi; \
        sleep 1; \
    done; \
    /setup-hydra.sh; \
    SETUP_STATUS=$?; \
    if [ $SETUP_STATUS -ne 0 ]; then \
        echo 'Hydra setup failed'; \
        kill $HYDRA_PID 2>/dev/null || true; \
        exit $SETUP_STATUS; \
    fi; \
    source /tmp/oauth-test-env.sh; \
    /usr/local/go/bin/go test -v -tags integration ./test/integration/oauth; \
    TEST_STATUS=$?; \
    kill $HYDRA_PID 2>/dev/null || true; \
    exit $TEST_STATUS"]
