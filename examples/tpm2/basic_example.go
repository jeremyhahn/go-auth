// Package main demonstrates TPM 2.0 authentication.
//
// This example shows how to:
// - Configure the TPM 2.0 authenticator
// - Unseal data with password validation
// - Verify platform integrity with PCR validation
// - Handle errors properly
//
// Usage:
//   go run basic_example.go
//
// Note: This example requires a TPM 2.0 device (physical or software emulator).
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jeremyhahn/go-auth/pkg/tpm2"
)

func main() {
	fmt.Println("==> TPM 2.0 Authentication Example")
	fmt.Println()

	// Configure TPM 2.0 authenticator
	// This example demonstrates unsealing data that was previously sealed
	// with specific PCR values and a password.
	cfg := tpm2.Config{
		// Path to the TPM device
		// Common paths:
		//   - /dev/tpm0 (direct TPM access, requires root)
		//   - /dev/tpmrm0 (TPM resource manager, recommended)
		DevicePath: "/dev/tpmrm0",

		// Handle where the sealed data is stored
		// This is typically a persistent handle created during seal operation
		// Persistent handles use range 0x81000000 - 0x81FFFFFF
		SealedHandle: 0x81000001,

		// PCR registers that must match for unsealing to succeed
		// PCR values provide platform integrity verification:
		//   0-7:   BIOS/Firmware measurements
		//   8-15:  Operating system and boot loader
		//   16-23: Application and runtime measurements
		// This example uses PCR 7 (secure boot state) and PCR 14 (boot authority)
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

	// Password used when the data was sealed
	password := "my-secret-password"

	fmt.Println("Attempting to unseal data from TPM...")
	fmt.Printf("Device: %s\n", cfg.DevicePath)
	fmt.Printf("Handle: 0x%X\n", cfg.SealedHandle)
	fmt.Printf("PCR Selection: %v\n", cfg.PCRSelection)
	fmt.Printf("Hash Algorithm: %s\n", cfg.HashAlgorithm)
	fmt.Println()

	// Perform authentication
	// This attempts to unseal data from the TPM
	// The TPM will automatically verify:
	//   1. The password is correct
	//   2. The current PCR values match the sealed policy
	//
	// If PCR values have changed (e.g., different boot state), unsealing fails
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
