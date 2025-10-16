package tpm2_test

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/jhahn/go-auth/pkg/tpm2"
)

// ExampleNewAuthenticator demonstrates basic usage of the TPM 2.0 authenticator.
func ExampleNewAuthenticator() {
	// Configure the TPM authenticator
	cfg := tpm2.Config{
		DevicePath:    "/dev/tpmrm0",  // Use resource manager for concurrent access
		SealedHandle:  0x81000000,     // Persistent handle with sealed data
		PCRSelection:  []int{0, 1, 7}, // Boot integrity PCRs
		HashAlgorithm: "SHA256",
	}

	// In production, use a real TPM provider implementation
	// For this example, we'll use nil (would require SetSystemTPMProvider)
	auth, err := tpm2.NewAuthenticator(cfg, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Authenticate by unsealing the secret
	ctx := context.Background()
	err = auth.Authenticate(ctx, "password123")
	if errors.Is(err, tpm2.ErrPCRMismatch) {
		fmt.Println("Platform integrity check failed")
	} else if errors.Is(err, tpm2.ErrInvalidPassword) {
		fmt.Println("Invalid password")
	} else if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Authentication successful")
}

// ExampleConfig_validate demonstrates configuration validation.
func ExampleConfig_validate() {
	cfg := tpm2.Config{
		DevicePath:   "/dev/tpm0",
		SealedHandle: 0x81000000,
		PCRSelection: []int{0, 1, 2, 3, 7},
	}

	// Note: validate is an unexported method, but this shows the concept
	// In practice, validation happens automatically in NewAuthenticator
	_, err := tpm2.NewAuthenticator(cfg, nil)
	if err != nil {
		fmt.Printf("Configuration error: %v\n", err)
	}
}

// ExampleAuthenticator_Authenticate_pcrMismatch demonstrates handling PCR policy violations.
func ExampleAuthenticator_Authenticate_pcrMismatch() {
	cfg := tpm2.Config{
		DevicePath:   "/dev/tpmrm0",
		SealedHandle: 0x81000000,
		PCRSelection: []int{0, 1, 7},
	}

	// Mock provider for demonstration
	mockProvider := &mockTPMProviderExample{
		shouldFailPCR: true,
	}

	auth, err := tpm2.NewAuthenticator(cfg, mockProvider)
	if err != nil {
		log.Fatal(err)
	}

	err = auth.Authenticate(context.Background(), "password")
	if errors.Is(err, tpm2.ErrPCRMismatch) {
		fmt.Println("PCR values do not match sealed policy")
		fmt.Println("This could indicate:")
		fmt.Println("- Firmware update changed PCR values")
		fmt.Println("- Boot configuration changed")
		fmt.Println("- System integrity compromised")
		// Output:
		// PCR values do not match sealed policy
		// This could indicate:
		// - Firmware update changed PCR values
		// - Boot configuration changed
		// - System integrity compromised
	}
}

// ExampleSetSystemTPMProvider demonstrates setting a default provider.
func ExampleSetSystemTPMProvider() {
	// Create a real TPM provider (implementation not shown)
	provider := &mockTPMProviderExample{}

	// Set as system default
	tpm2.SetSystemTPMProvider(provider)

	// Now authenticators can be created without explicit provider
	cfg := tpm2.Config{
		DevicePath:   "/dev/tpmrm0",
		SealedHandle: 0x81000000,
		PCRSelection: []int{0, 7},
	}

	auth, err := tpm2.NewAuthenticator(cfg, nil) // Uses system provider
	if err != nil {
		log.Fatal(err)
	}

	_ = auth // Use the authenticator
}

// Mock implementations for examples

type mockTPMProviderExample struct {
	shouldFailPCR bool
}

func (m *mockTPMProviderExample) Open(ctx context.Context, cfg tpm2.Config) (tpm2.TPMSession, error) {
	return &mockTPMSessionExample{shouldFailPCR: m.shouldFailPCR}, nil
}

type mockTPMSessionExample struct {
	shouldFailPCR bool
}

func (m *mockTPMSessionExample) Unseal(ctx context.Context, handle tpm2.Handle, password string) ([]byte, error) {
	if m.shouldFailPCR {
		return nil, tpm2.ErrPCRMismatch
	}
	return []byte("unsealed-secret"), nil
}

func (m *mockTPMSessionExample) Close(ctx context.Context) error {
	return nil
}
