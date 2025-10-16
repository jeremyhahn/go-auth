FROM golang:1.25-bookworm

# Install swtpm (software TPM simulator) and dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        swtpm \
        swtpm-tools \
        tpm2-tools \
        socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy dependency files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Create directories for TPM state and scripts
RUN mkdir -p /tpm-state /tmp/tpm-scripts

# Create initialization script that sets up TPM and seals test data
RUN cat > /tmp/tpm-scripts/setup-tpm.sh <<'EOF'
#!/bin/bash
set -e

echo "==> Starting software TPM (swtpm) for initialization..."

# Start swtpm in socket mode
swtpm socket --tpmstate dir=/tpm-state \
    --tpm2 \
    --server type=unixio,path=/tmp/swtpm-sock \
    --ctrl type=unixio,path=/tmp/swtpm-sock.ctrl \
    --flags not-need-init,startup-clear \
    --log level=0 &

SWTPM_PID=$!
echo "swtpm started with PID: $SWTPM_PID"

# Set TCTI to use swtpm socket
export TPM2TOOLS_TCTI="swtpm:path=/tmp/swtpm-sock"

# Wait for swtpm to be ready - check for both data and control sockets
echo "==> Waiting for swtpm sockets to be ready..."
MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if [ -S "/tmp/swtpm-sock" ] && [ -S "/tmp/swtpm-sock.ctrl" ]; then
        echo "Both swtpm sockets are ready"
        break
    fi

    if [ $RETRY_COUNT -eq 0 ]; then
        echo -n "Waiting for sockets to appear"
    else
        echo -n "."
    fi

    sleep 0.2
    RETRY_COUNT=$((RETRY_COUNT + 1))
done
echo ""

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "ERROR: swtpm sockets failed to appear after ${MAX_RETRIES} retries"
    ls -la /tmp/swtpm-sock* 2>&1 || echo "No swtpm socket files found"
    kill $SWTPM_PID || true
    exit 1
fi

# Additional verification - try to connect to the TPM
echo "==> Verifying TPM connection..."
if ! tpm2_startup -c 2>/dev/null; then
    echo "WARNING: First startup attempt failed, retrying..."
    sleep 1
    tpm2_startup -c
fi

echo "==> Initializing TPM..."

echo "==> Creating primary key and persisting it..."
# Create primary key in transient memory
tpm2_createprimary -C o -g sha256 -G rsa -c /tmp/primary.ctx

# Immediately persist the primary key to a persistent handle
# This prevents it from being flushed and allows reuse across operations
tpm2_evictcontrol -C o -c /tmp/primary.ctx 0x81000000

# Flush the transient primary key context since we now have it persisted
tpm2_flushcontext -t

echo "  Primary key persisted to handle 0x81000000"

echo "==> Creating sealed objects for testing..."

# Handle 0x81000001: Sealed with correct password
echo "secret-data-123" | tpm2_create -C 0x81000000 \
    -g sha256 \
    -i- \
    -p "test-password-123" \
    -u /tmp/seal1.pub \
    -r /tmp/seal1.priv

tpm2_load -C 0x81000000 \
    -u /tmp/seal1.pub \
    -r /tmp/seal1.priv \
    -c /tmp/seal1.ctx

tpm2_evictcontrol -C o -c /tmp/seal1.ctx 0x81000001
tpm2_flushcontext -t
echo "  Created handle 0x81000001 with password 'test-password-123'"

# Handle 0x81000002: Sealed with different password
echo "secret-data-456" | tpm2_create -C 0x81000000 \
    -g sha256 \
    -i- \
    -p "different-password" \
    -u /tmp/seal2.pub \
    -r /tmp/seal2.priv

tpm2_load -C 0x81000000 \
    -u /tmp/seal2.pub \
    -r /tmp/seal2.priv \
    -c /tmp/seal2.ctx

tpm2_evictcontrol -C o -c /tmp/seal2.ctx 0x81000002
tpm2_flushcontext -t
echo "  Created handle 0x81000002 with password 'different-password'"

# Handle 0x81000003: Sealed with PCR policy
tpm2_pcrread sha256:7 -o /tmp/pcr7.dat
tpm2_createpolicy --policy-pcr -l sha256:7 -f /tmp/pcr7.dat -L /tmp/pcr.policy

echo "pcr-sealed-data" | tpm2_create -C 0x81000000 \
    -g sha256 \
    -i- \
    -p "test-password-123" \
    -L /tmp/pcr.policy \
    -u /tmp/seal3.pub \
    -r /tmp/seal3.priv

tpm2_load -C 0x81000000 \
    -u /tmp/seal3.pub \
    -r /tmp/seal3.priv \
    -c /tmp/seal3.ctx

tpm2_evictcontrol -C o -c /tmp/seal3.ctx 0x81000003
tpm2_flushcontext -t
echo "  Created handle 0x81000003 with PCR[7] policy"

# Handle 0x81000004: Sealed with SHA384
echo "sha384-data" | tpm2_create -C 0x81000000 \
    -g sha384 \
    -i- \
    -p "test-password-123" \
    -u /tmp/seal4.pub \
    -r /tmp/seal4.priv

tpm2_load -C 0x81000000 \
    -u /tmp/seal4.pub \
    -r /tmp/seal4.priv \
    -c /tmp/seal4.ctx

tpm2_evictcontrol -C o -c /tmp/seal4.ctx 0x81000004
tpm2_flushcontext -t
echo "  Created handle 0x81000004 with SHA384 hash"

echo "==> Verifying persistent handles were created..."
tpm2_getcap handles-persistent

echo "==> TPM initialization complete!"

# Stop swtpm and save state
kill $SWTPM_PID
wait $SWTPM_PID || true

echo "==> TPM state saved to /tpm-state"
EOF

RUN chmod +x /tmp/tpm-scripts/setup-tpm.sh

# Run the setup script to initialize TPM with test data
RUN /tmp/tpm-scripts/setup-tpm.sh

# Create helper script to reset TPM lockout counter
# This script is called by Go tests to reset lockout between tests
RUN cat > /usr/local/bin/tpm-reset-lockout <<'EOF'
#!/bin/bash
# Reset TPM dictionary attack lockout counter
# This is called by tests that intentionally cause auth failures
#
# IMPORTANT: Use swtpm TCTI to connect to the swtpm socket directly.
# The /dev/tpmrm0 is just a socat relay, and tpm2-tools work better
# when connecting directly to the actual swtpm socket.
export TPM2TOOLS_TCTI="swtpm:path=/tmp/swtpm-sock"
tpm2_dictionarylockout -c -p "" 2>/dev/null || \
    tpm2_dictionarylockout -c 2>/dev/null || \
    true  # Ignore errors - some TPMs don't support this
EOF

RUN chmod +x /usr/local/bin/tpm-reset-lockout

# Create runtime script that starts swtpm and exposes it as /dev/tpmrm0
RUN cat > /tmp/tpm-scripts/run-tests.sh <<'EOF'
#!/bin/bash
set -e

echo "==> Starting swtpm with device emulation..."

# Create /dev directory if it doesn't exist
mkdir -p /dev

# Start swtpm in socket mode (we'll create a device proxy)
# IMPORTANT: Removed 'startup-clear' flag to preserve persistent handles!
# The 'startup-clear' flag causes TPM2_Startup(CLEAR) which erases persistent handles.
# We only use 'not-need-init' to indicate the TPM state is already initialized.
swtpm socket --tpmstate dir=/tpm-state \
    --tpm2 \
    --server type=unixio,path=/tmp/swtpm-sock \
    --ctrl type=unixio,path=/tmp/swtpm-sock.ctrl \
    --flags not-need-init \
    --log level=0 &

SWTPM_PID=$!
echo "swtpm started with PID: $SWTPM_PID"

# Set TCTI for tpm2-tools commands
export TPM2TOOLS_TCTI="swtpm:path=/tmp/swtpm-sock"

# Wait for swtpm to be ready - check for both data and control sockets
echo "==> Waiting for swtpm sockets to be ready..."
MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if [ -S "/tmp/swtpm-sock" ] && [ -S "/tmp/swtpm-sock.ctrl" ]; then
        echo "Both swtpm sockets are ready"
        break
    fi

    if [ $RETRY_COUNT -eq 0 ]; then
        echo -n "Waiting for sockets to appear"
    else
        echo -n "."
    fi

    sleep 0.2
    RETRY_COUNT=$((RETRY_COUNT + 1))
done
echo ""

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "ERROR: swtpm sockets failed to appear after ${MAX_RETRIES} retries"
    ls -la /tmp/swtpm-sock* 2>&1 || echo "No swtpm socket files found"
    kill $SWTPM_PID || true
    exit 1
fi

# Initialize TPM with non-destructive startup
# Use -c (TPM2_Startup CLEAR) which initializes volatile state
# but preserves NV storage and persistent handles
echo "==> Initializing TPM with TPM2_Startup(CLEAR)..."
if ! tpm2_startup -c; then
    echo "ERROR: TPM2_Startup failed"
    kill $SWTPM_PID || true
    exit 1
fi
echo "TPM successfully initialized"

# Verify TPM is accessible and list persistent handles
echo "==> Verifying TPM persistent handles are loaded..."
if ! tpm2_getcap handles-persistent; then
    echo "ERROR: Failed to read persistent handles from TPM"
    kill $SWTPM_PID || true
    exit 1
fi

# CRITICAL FIX: Clear dictionary attack lockout counter before tests
# The TPM has dictionary attack protection that tracks failed auth attempts.
# After 3 failed attempts, the TPM enters lockout mode and rejects ALL auths
# (even correct ones) for 1000 seconds. The lockout state persists in NV storage.
#
# Our test suite intentionally causes auth failures to test error handling.
# These failures can trigger lockout, causing subsequent tests to fail.
#
# Solution: Reset the lockout counter to 0 before running tests.
echo "==> Resetting TPM dictionary attack lockout counter..."
tpm2_dictionarylockout -c -p "" 2>/dev/null || \
    tpm2_dictionarylockout -c || \
    echo "  WARNING: Could not reset lockout counter"

# Verify lockout was cleared
echo "==> Checking dictionary attack lockout status..."
tpm2_getcap properties-variable | grep -A4 "TPM2_PT_LOCKOUT" || echo "  Could not query lockout properties"

# Create a Unix domain socket relay that acts as /dev/tpmrm0
# We'll use socat to create a character device-like interface
rm -f /tmp/tpm-device.sock /dev/tpmrm0

# Create a relay from Unix socket to the swtpm socket
socat UNIX-LISTEN:/tmp/tpm-device.sock,fork,reuseaddr UNIX-CONNECT:/tmp/swtpm-sock &
SOCAT_PID=$!
echo "socat relay started with PID: $SOCAT_PID"

sleep 1

# Create symlink for /dev/tpmrm0 pointing to our socket
ln -sf /tmp/tpm-device.sock /dev/tpmrm0

echo "==> TPM device available at /dev/tpmrm0"

# Run tests with environment variable to enable lockout reset helper
echo "==> Running integration tests..."
cd /workspace
export TPM_LOCKOUT_RESET_SCRIPT="/usr/local/bin/tpm-reset-lockout"
go test -v -tags integration -timeout 60s ./test/integration/tpm2

TEST_EXIT_CODE=$?

# Cleanup
echo "==> Cleaning up..."
kill $SOCAT_PID || true
kill $SWTPM_PID || true
wait $SOCAT_PID || true
wait $SWTPM_PID || true

exit $TEST_EXIT_CODE
EOF

RUN chmod +x /tmp/tpm-scripts/run-tests.sh

# Enable CGO for go-tpm
ENV CGO_ENABLED=1

# Run integration tests
CMD ["/tmp/tpm-scripts/run-tests.sh"]
