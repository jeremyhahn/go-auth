// Package main demonstrates TPM 2.0 unseal with password and PCR validation; requires a TPM 2.0 device or simulator.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/tpm2"
)

func main() {
	fmt.Println("==> TPM 2.0 Authentication Example")
	fmt.Println()

	// Configure the TPM 2.0 authenticator to unseal data sealed to PCR values and a password.
	cfg := tpm2.Config{
		// TPM device; /dev/tpmrm0 (resource manager) is recommended over /dev/tpm0.
		DevicePath: "/dev/tpmrm0",

		// Handle where the sealed data is stored
		// This is typically a persistent handle created during seal operation
		// Persistent handles use range 0x81000000 - 0x81FFFFFF
		SealedHandle: 0x81000001,

		// PCRs that must match to unseal: 7 (secure boot state) and 14 (boot authority).
		PCRSelection: []int{7, 14},

		// Hash algorithm for PCR bank
		// "SHA256" is recommended for TPM 2.0
		HashAlgorithm: "SHA256",
	}

	// Create authenticator
	// Pass nil to use the system TPM provider
	auth, err := tpm2.NewAuthenticator(cfg, nil)
	if err != nil {
		log.Fatalf("Failed to create TPM authenticator: %v", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Password used when the data was sealed. It travels in go-enclave
	// locked memory; in production build it with enclave.NewMemoryEnclave
	// over a []byte the reader fills, which wipes that slice.
	password, err := enclave.NewMemoryEnclave([]byte("my-secret-password"))
	if err != nil {
		log.Fatalf("Failed to seal the password: %v", err)
	}
	// Authenticate borrows it; the caller destroys it.
	defer password.Destroy()

	fmt.Println("Attempting to unseal data from TPM...")
	fmt.Printf("Device: %s\n", cfg.DevicePath)
	fmt.Printf("Handle: 0x%X\n", cfg.SealedHandle)
	fmt.Printf("PCR Selection: %v\n", cfg.PCRSelection)
	fmt.Printf("Hash Algorithm: %s\n", cfg.HashAlgorithm)
	fmt.Println()

	// Unseal: fails if the password is wrong or the PCR values differ from the sealed policy.
	err = auth.Authenticate(ctx, password)
	if err != nil {
		switch err {
		case tpm2.ErrInvalidPassword:
			log.Printf("Invalid password")
		case tpm2.ErrPCRMismatch:
			log.Printf("PCR policy validation failed - platform state has changed")
		case tpm2.ErrTPMUnavailable:
			log.Printf("TPM device not available")
		default:
			log.Printf("Authentication failed: %v", err)
		}
		fmt.Println()
		fmt.Println("Note: This example requires:")
		fmt.Println("  1. A TPM 2.0 device (physical or swtpm emulator)")
		fmt.Println("  2. TPM device accessible at /dev/tpmrm0 or /dev/tpm0")
		fmt.Println("  3. Pre-sealed data at the specified handle")
		fmt.Println("  4. Correct password and matching PCR values")
		fmt.Println()
		fmt.Println("To set up TPM for testing:")
		fmt.Println("  1. Install tpm2-tools: apt-get install tpm2-tools")
		fmt.Println("  2. List available TPMs: ls -l /dev/tpm*")
		fmt.Println("  3. Create a primary key and seal data using tpm2_create")
		fmt.Println("  4. Make the handle persistent using tpm2_evictcontrol")
		fmt.Println()
		fmt.Println("For software TPM emulator:")
		fmt.Println("  1. Install swtpm: apt-get install swtpm swtpm-tools")
		fmt.Println("  2. Start emulator: swtpm socket --tpmstate dir=/tmp/tpm \\")
		fmt.Println("       --ctrl type=unixio,path=/tmp/tpm/ctrl.sock \\")
		fmt.Println("       --tpm2 --flags startup-clear")
		return
	}

	fmt.Println("✓ Authentication successful!")
	fmt.Println()
	fmt.Println("Data successfully unsealed from TPM.")
	fmt.Println("Platform integrity verified via PCR validation.")
	fmt.Println()
	fmt.Println("TPM 2.0 authentication benefits:")
	fmt.Println("  - Hardware-based credential storage")
	fmt.Println("  - Platform integrity verification (PCR)")
	fmt.Println("  - Protection against offline attacks")
	fmt.Println("  - Sealed data only accessible in trusted state")
	fmt.Println("  - Suitable for full-disk encryption, secure boot validation")
}
