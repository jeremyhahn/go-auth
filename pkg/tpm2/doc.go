// Package tpm2 provides authentication using TPM 2.0 devices for hardware-based
// platform integrity verification.
//
// The primary authentication mechanism is unsealing secrets that were previously
// sealed to specific Platform Configuration Register (PCR) values. This provides
// cryptographic assurance that the platform is in a known, trusted state before
// releasing secrets.
//
// # Authentication Flow
//
// 1. A secret (e.g., encryption key, password) is sealed to specific PCR values
// representing a trusted platform state during provisioning.
//
// 2. During authentication, the TPM validates that current PCR values match
// the sealed policy.
//
// 3. If validation succeeds, the TPM unseals the secret; otherwise authentication
// fails with ErrPCRMismatch.
//
// # Basic Usage
//
//	cfg := tpm2.Config{
//		DevicePath:   "/dev/tpmrm0",
//		SealedHandle: 0x81000000,  // Persistent handle with sealed data
//		PCRSelection: []int{0, 1, 7},  // Boot PCRs
//		HashAlgorithm: "SHA256",
//	}
//
//	// Use a real TPM provider (implementation not shown)
//	provider := NewRealTPMProvider()
//
//	auth, err := tpm2.NewAuthenticator(cfg, provider)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Authenticate by unsealing
//	err = auth.Authenticate(context.Background(), "password123")
//	if errors.Is(err, tpm2.ErrPCRMismatch) {
//		log.Fatal("Platform integrity check failed")
//	} else if errors.Is(err, tpm2.ErrInvalidPassword) {
//		log.Fatal("Invalid password")
//	} else if err != nil {
//		log.Fatal(err)
//	}
//
// # Platform Configuration Registers (PCRs)
//
// PCRs are hash extend registers in the TPM that measure platform state.
// Common PCR assignments on PC platforms:
//
//   - PCR 0: BIOS/UEFI firmware
//   - PCR 1: BIOS/UEFI configuration
//   - PCR 2: Option ROM code
//   - PCR 3: Option ROM configuration
//   - PCR 4-5: Boot loader
//   - PCR 6: Resume events
//   - PCR 7: Secure Boot state
//   - PCR 8-15: OS and application usage
//   - PCR 16-23: Debug and testing
//
// # TPM Device Paths
//
// Common TPM device paths:
//   - /dev/tpm0: Character device (requires exclusive access)
//   - /dev/tpmrm0: Resource manager device (recommended, allows concurrent access)
//   - Simulator devices for testing
//
// # Error Handling
//
// The package defines several sentinel errors for common failure modes:
//
//   - ErrTPMUnavailable: TPM device cannot be accessed
//   - ErrInvalidPassword: Password/authorization failed
//   - ErrPCRMismatch: Platform state doesn't match sealed policy
//   - ErrNilAuthenticator: Nil authenticator used
//   - ErrEmptyPassword: Empty password provided
//
// # Testing
//
// For testing, implement the TPMProvider interface with mock behavior:
//
//	type mockProvider struct{}
//
//	func (m *mockProvider) Open(ctx context.Context, cfg Config) (TPMSession, error) {
//		return &mockSession{}, nil
//	}
//
//	auth, err := tpm2.NewAuthenticator(cfg, &mockProvider{})
//
// # Security Considerations
//
// 1. Sealed data security depends on PCR selection. Choose PCRs that measure
// critical platform components.
//
// 2. PCR values change with firmware/software updates. Plan for resealing
// secrets after trusted updates.
//
// 3. Use /dev/tpmrm0 when available for better concurrent access support.
//
// 4. Protect sealed object handles - they contain sensitive policy information.
//
// 5. Consider using enhanced authorization (HMAC, policy sessions) for
// production deployments.
package tpm2
