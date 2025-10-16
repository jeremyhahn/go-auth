#!/bin/bash
# Cleanup script to remove test handles from the host TPM
# This removes handles 0x81000000-0x81000004 created by setup-host-tpm.sh

set -e

echo "==> Host TPM Test Cleanup Script"
echo "This script will remove test sealed objects from handles 0x81000000-0x81000004"
echo ""

# Check if TPM device exists
if [ ! -e "/dev/tpmrm0" ]; then
    echo "ERROR: TPM device /dev/tpmrm0 not found"
    exit 1
fi

# Check if we have tpm2-tools installed
if ! command -v tpm2_evictcontrol &> /dev/null; then
    echo "ERROR: tpm2-tools not installed. Please install: apt-get install tpm2-tools"
    exit 1
fi

echo "==> Removing test handles..."
for handle in 0x81000000 0x81000001 0x81000002 0x81000003 0x81000004; do
    if tpm2_getcap handles-persistent | grep -q "$handle"; then
        echo "  Removing handle $handle"
        tpm2_evictcontrol -C o -c "$handle" 2>/dev/null || echo "    Warning: Failed to remove $handle"
    else
        echo "  Handle $handle not found (skipping)"
    fi
done

echo ""
echo "==> Verifying handles were removed..."
tpm2_getcap handles-persistent

echo ""
echo "==> Cleanup complete!"
