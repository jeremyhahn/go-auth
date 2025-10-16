# TPM 2.0 Authentication Package

This package provides TPM 2.0 based authentication by unsealing data from persistent TPM handles. The unsealing operation automatically validates PCR policy, providing hardware-based platform integrity verification.

## Integration Testing

The integration tests require specific sealed objects to be present in the TPM at predefined handles. There are two ways to run the tests:

### Option 1: Docker-based Testing (Recommended)

Uses a software TPM simulator (swtpm) with pre-configured test data:

```bash
cd pkg/tpm2
make integration-test
```

This builds and runs a Docker container with:
- Software TPM (swtpm)
- Pre-sealed test objects at handles 0x81000001-0x81000004
- All required dependencies

### Option 2: Host TPM Testing

To run tests against your host's physical TPM:

1. **Setup test data** (one time):
   ```bash
   cd pkg/tpm2
   sudo ./setup-host-tpm.sh
   ```

   This creates test sealed objects at handles 0x81000000-0x81000004.

   **WARNING**: This modifies persistent TPM state. Review the script before running.

2. **Run tests**:
   ```bash
   go test -v -tags integration ./test/integration/tpm2
   ```

3. **Cleanup** (when done testing):
   ```bash
   cd pkg/tpm2
   sudo ./cleanup-host-tpm.sh
   ```

## Test Handles

The integration tests use these predefined handles:

- `0x81000000`: Primary key (parent for sealed objects)
- `0x81000001`: Sealed with password "test-password-123"
- `0x81000002`: Sealed with password "different-password"
- `0x81000003`: Sealed with PCR[7] policy + password
- `0x81000004`: Sealed with SHA384 hash algorithm

## Why Tests Failed Previously

**Root Cause**: Tests were running against the host TPM which had different handles (0x81010001, 0x81010016) instead of the expected test handles (0x81000001-0x81000004).

**Details**:
1. The Docker setup correctly creates handles 0x81000001-0x81000004 in the simulated TPM
2. When running tests with `-tags integration` on the host, they attempted to use `/dev/tpmrm0`
3. The host TPM didn't have the test handles, causing "invalid sealed object handle" errors
4. The error message was misleading - the TPM opened successfully, but the handles didn't exist

**Solution**:
- Use Docker for CI/automated testing (isolated, reproducible)
- Use `setup-host-tpm.sh` for local development testing against real hardware
- Both approaches now create the same test handles for consistency

## Troubleshooting

### "TPM device not available"
- Check if `/dev/tpmrm0` or `/dev/tpm0` exists
- Ensure your user is in the `tss` group: `sudo usermod -a -G tss $USER`
- Log out and back in for group changes to take effect

### "Failed to open TPM device"
- Verify permissions: `ls -la /dev/tpm*`
- Try with sudo: `sudo go test -v -tags integration ./test/integration/tpm2`

### "Invalid sealed object handle"
- Run `tpm2_getcap handles-persistent` to see what handles exist
- If handles don't match 0x81000001-0x81000004, run `setup-host-tpm.sh`
- For Docker tests, rebuild the image: `make integration-test`

### Docker tests fail with "swtpm sockets failed to appear"
- Try increasing timeout in Dockerfile (MAX_RETRIES)
- Check Docker has sufficient resources allocated
- Rebuild image: `docker build --no-cache -f Dockerfile ...`

## Security Considerations

**For Development/Testing Only**: The test handles use known passwords and are intended for integration testing only. Never use these handles or passwords in production.

**Production Usage**:
- Use unique, randomly generated passwords for sealing
- Implement proper key derivation (PBKDF2, Argon2)
- Consider using TPM 2.0's HMAC sessions for enhanced auth
- Seal to specific PCR values that reflect your platform's trusted state
- Use hardware TPM, not software simulation

## Dependencies

- Go 1.21+
- github.com/google/go-tpm v0.9+
- tpm2-tools (for host setup scripts)
- Docker (for containerized testing)
- swtpm (included in Docker image)

## References

- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [go-tpm Documentation](https://pkg.go.dev/github.com/google/go-tpm)
- [tpm2-tools Documentation](https://github.com/tpm2-software/tpm2-tools)
