#!/bin/bash
# Setup script to initialize the host TPM with test handles for integration testing
# This script must be run with appropriate TPM permissions (usually requires being in 'tss' group)

set -e

echo "==> Host TPM Test Setup Script"
echo "This script will create test sealed objects in your TPM at handles 0x81000001-0x81000004"
echo ""

# Check if TPM device exists
if [ ! -e "/dev/tpmrm0" ]; then
    echo "ERROR: TPM device /dev/tpmrm0 not found"
    exit 1
fi

# Check if we have tpm2-tools installed
if ! command -v tpm2_createprimary &> /dev/null; then
    echo "ERROR: tpm2-tools not installed. Please install: apt-get install tpm2-tools"
    exit 1
fi

# Warning prompt
echo "WARNING: This script will create persistent handles in your TPM."
echo "Existing handles 0x81000000-0x81000004 will be removed if they exist."
read -p "Continue? (yes/no): " -r
echo
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Aborted."
    exit 0
fi

echo "==> Cleaning up existing test handles (if any)..."
for handle in 0x81000000 0x81000001 0x81000002 0x81000003 0x81000004; do
    if tpm2_getcap handles-persistent | grep -q "$handle"; then
        echo "  Removing existing handle $handle"
        tpm2_evictcontrol -C o -c "$handle" 2>/dev/null || true
    fi
done

echo "==> Creating primary key and persisting it..."
tpm2_createprimary -C o -g sha256 -G rsa -c /tmp/primary.ctx
tpm2_evictcontrol -C o -c /tmp/primary.ctx 0x81000000
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

echo "==> Cleaning up temporary files..."
rm -f /tmp/primary.ctx /tmp/seal*.pub /tmp/seal*.priv /tmp/seal*.ctx /tmp/pcr7.dat /tmp/pcr.policy

echo ""
echo "==> Host TPM setup complete!"
echo "You can now run integration tests with: go test -v -tags integration ./test/integration/tpm2"
