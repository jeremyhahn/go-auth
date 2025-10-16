//go:build integration

package tpm2_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tpm2auth "github.com/jeremyhahn/go-auth/pkg/tpm2"
)

const (
	// TPM device path - can be either real device or Unix socket
	tpmDevicePath = "/dev/tpmrm0"

	// Test handles for sealed objects created during Docker image build
	validHandle     = tpm2auth.Handle(0x81000001) // Sealed with correct password
	invalidHandle   = tpm2auth.Handle(0x81000002) // Sealed with different password
	pcrPolicyHandle = tpm2auth.Handle(0x81000003) // Sealed with PCR policy
	sha384Handle    = tpm2auth.Handle(0x81000004) // Sealed with SHA384 hash

	// Test passwords
	correctPassword = "test-password-123"
	wrongPassword   = "wrong-password"

	// PCR configuration
	testPCR = 7 // PCR 7 is typically used for secure boot
)

// Global mutex to serialize all TPM access across all tests.
// TPM is a single physical resource that cannot handle concurrent operations.
var globalTPMMutex sync.Mutex

// Shared provider instance used by all tests to ensure proper serialization
var sharedProvider = &realTPMProvider{}

// tpmWithCloser wraps a transport.TPM and an io.Closer to implement transport.TPMCloser
type tpmWithCloser struct {
	transport.TPM
	closer io.Closer
}

func (t *tpmWithCloser) Close() error {
	if t.closer != nil {
		return t.closer.Close()
	}
	return nil
}

// realTPMProvider implements TPMProvider using the go-tpm library.
type realTPMProvider struct{}

func (p *realTPMProvider) Open(ctx context.Context, cfg tpm2auth.Config) (tpm2auth.TPMSession, error) {
	// Lock globally to prevent concurrent TPM access across all authenticators and tests
	globalTPMMutex.Lock()

	// Check if the device path is a Unix socket
	fileInfo, err := os.Stat(cfg.DevicePath)
	if err != nil {
		globalTPMMutex.Unlock()
		if os.IsNotExist(err) {
			return nil, tpm2auth.ErrTPMUnavailable
		}
		return nil, fmt.Errorf("failed to stat TPM device: %w", err)
	}

	var tpm transport.TPMCloser

	// If it's a Unix socket (used in Docker with socat), connect directly
	if fileInfo.Mode()&os.ModeSocket != 0 {
		conn, err := net.Dial("unix", cfg.DevicePath)
		if err != nil {
			globalTPMMutex.Unlock()
			return nil, fmt.Errorf("failed to connect to TPM socket: %w", err)
		}
		tpm = &tpmWithCloser{
			TPM:    transport.FromReadWriter(conn),
			closer: conn,
		}
	} else {
		// Otherwise, use OpenTPM for character devices
		tpm, err = transport.OpenTPM(cfg.DevicePath)
		if err != nil {
			globalTPMMutex.Unlock()
			if os.IsNotExist(err) {
				return nil, tpm2auth.ErrTPMUnavailable
			}
			return nil, fmt.Errorf("failed to open TPM device: %w", err)
		}
	}

	return &realTPMSession{
		tpm:           tpm,
		cfg:           cfg,
		hashAlgorithm: parseHashAlgorithm(cfg.HashAlgorithm),
	}, nil
}

// realTPMSession implements TPMSession using go-tpm.
type realTPMSession struct {
	tpm           transport.TPMCloser
	cfg           tpm2auth.Config
	hashAlgorithm tpm2.TPMAlgID
}

func (s *realTPMSession) Unseal(ctx context.Context, handle tpm2auth.Handle, password string) ([]byte, error) {
	// Create TPM handle
	tpmHandle := tpm2.TPMHandle(handle)

	// First, read the object's public area to get its Name and check if it has a policy
	readPub := tpm2.ReadPublic{
		ObjectHandle: tpmHandle,
	}

	readPubResp, err := readPub.Execute(s.tpm)
	if err != nil {
		return nil, mapTPMError(err)
	}

	// Extract the TPMTPublic structure to check for authorization policy
	pubArea, err := readPubResp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to read public area contents: %w", err)
	}

	// Check if the object has an authorization policy (authPolicy field is non-empty)
	hasPolicy := len(pubArea.AuthPolicy.Buffer) > 0

	if hasPolicy {
		// Object has a policy - use policy session for authorization
		return s.unsealWithPCRPolicy(tpmHandle, readPubResp.Name)
	}

	// No policy - use simple password authorization
	return s.unsealWithPassword(tpmHandle, readPubResp.Name, password)
}

// unsealWithPassword unseals an object using password authorization.
func (s *realTPMSession) unsealWithPassword(tpmHandle tpm2.TPMHandle, name tpm2.TPM2BName, password string) ([]byte, error) {
	auth := tpm2.PasswordAuth([]byte(password))

	unsealCmd := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: tpmHandle,
			Name:   name,
			Auth:   auth,
		},
	}

	rsp, err := unsealCmd.Execute(s.tpm)
	if err != nil {
		return nil, mapTPMError(err)
	}

	return rsp.OutData.Buffer, nil
}

// unsealWithPCRPolicy unseals an object that has a PCR policy.
func (s *realTPMSession) unsealWithPCRPolicy(tpmHandle tpm2.TPMHandle, name tpm2.TPM2BName) ([]byte, error) {
	// Start a real policy session (not a trial session)
	// Don't pass tpm2.Trial() - that's only for policy calculation, not actual authorization
	sess, cleanup, err := tpm2.PolicySession(s.tpm, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy session: %w", err)
	}
	defer cleanup()

	// Build PCR selection from config
	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      s.hashAlgorithm,
				PCRSelect: buildPCRSelect(s.cfg.PCRSelection),
			},
		},
	}

	// Apply the PCR policy to the session
	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs:          pcrSelection,
	}.Execute(s.tpm)
	if err != nil {
		return nil, mapTPMError(err)
	}

	// Now unseal using the policy session
	unsealCmd := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: tpmHandle,
			Name:   name,
			Auth:   sess,
		},
	}

	rsp, err := unsealCmd.Execute(s.tpm)
	if err != nil {
		return nil, mapTPMError(err)
	}

	return rsp.OutData.Buffer, nil
}

// buildPCRSelect creates a PCR selection bitmask from a list of PCR indices.
func buildPCRSelect(pcrs []int) []byte {
	// PCRSelect is a byte array where each bit represents a PCR
	// TPM 2.0 supports up to 24 PCRs (3 bytes)
	pcrSelect := make([]byte, 3)
	for _, pcr := range pcrs {
		if pcr >= 0 && pcr < 24 {
			byteIndex := pcr / 8
			bitIndex := uint(pcr % 8)
			pcrSelect[byteIndex] |= 1 << bitIndex
		}
	}
	return pcrSelect
}

func (s *realTPMSession) Close(ctx context.Context) error {
	// Unlock the global mutex when closing the session
	defer globalTPMMutex.Unlock()

	if s.tpm != nil {
		return s.tpm.Close()
	}
	return nil
}

// parseHashAlgorithm converts string hash algorithm to TPM algorithm ID.
func parseHashAlgorithm(alg string) tpm2.TPMAlgID {
	switch alg {
	case "SHA1":
		return tpm2.TPMAlgSHA1
	case "SHA256", "":
		return tpm2.TPMAlgSHA256
	case "SHA384":
		return tpm2.TPMAlgSHA384
	case "SHA512":
		return tpm2.TPMAlgSHA512
	default:
		return tpm2.TPMAlgSHA256
	}
}

// mapTPMError maps go-tpm errors to our authentication errors.
func mapTPMError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for authorization failures (wrong password)
	// TPM error code 0x98e is TPM_RC_BAD_AUTH
	if containsAny(errStr, "auth", "authorization", "0x98e", "bad auth") {
		return tpm2auth.ErrInvalidPassword
	}

	// Check for PCR policy failures
	// TPM error code 0x1d is TPM_RC_POLICY_FAIL
	if containsAny(errStr, "pcr", "policy", "0x1d", "policy fail") {
		return tpm2auth.ErrPCRMismatch
	}

	// Check for invalid handle
	// TPM error code 0x18b is TPM_RC_HANDLE
	if containsAny(errStr, "handle", "0x18b", "invalid handle") {
		return tpm2auth.ErrInvalidHandle
	}

	// Return original error wrapped
	return fmt.Errorf("tpm2: unseal failed: %w", err)
}

// containsAny checks if a string contains any of the substrings (case-insensitive).
func containsAny(s string, substrs ...string) bool {
	sLower := toLower(s)
	for _, substr := range substrs {
		substrLower := toLower(substr)
		if contains(sLower, substrLower) {
			return true
		}
	}
	return false
}

// toLower converts a string to lowercase.
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		result[i] = c
	}
	return string(result)
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// testContext creates a context with a reasonable timeout for TPM operations.
func testContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// skipIfTPMUnavailable skips the test if the TPM device is not available.
func skipIfTPMUnavailable(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(tpmDevicePath); os.IsNotExist(err) {
		t.Skipf("TPM device not available at %s", tpmDevicePath)
	}
}

// resetTPMLockout resets the TPM dictionary attack lockout counter.
// This is called after tests that intentionally cause authentication failures
// to prevent lockout from affecting subsequent tests.
//
// TPM dictionary attack protection triggers after 3 failed auth attempts and
// locks out ALL authentications (even correct ones) for 1000 seconds.
// The lockout state persists in NV storage across TPM restarts.
func resetTPMLockout(t *testing.T) {
	t.Helper()

	t.Log("Resetting TPM dictionary attack lockout counter...")

	// Check if there's a helper script (set by Docker environment)
	resetScript := os.Getenv("TPM_LOCKOUT_RESET_SCRIPT")
	if resetScript != "" {
		t.Logf("Using reset script: %s", resetScript)
		cmd := exec.Command(resetScript)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("Warning: Could not reset TPM lockout via script %s: %v\nOutput: %s", resetScript, err, string(output))
		} else {
			t.Log("Successfully reset lockout via helper script")
		}
		return
	}

	// Fallback: Try to reset directly via tpm2-tools
	// The TCTI must match the TPM setup. In Docker with swtpm, use swtpm TCTI.
	// For real hardware TPMs, use device TCTI.

	// First, check if we're using a Unix socket (Docker/swtpm environment)
	fileInfo, err := os.Stat(tpmDevicePath)
	if err == nil && fileInfo.Mode()&os.ModeSocket != 0 {
		// It's a Unix socket - likely swtpm via socat
		// Try to determine the actual swtpm socket path
		swtpmSock := "/tmp/swtpm-sock"
		if _, err := os.Stat(swtpmSock); err == nil {
			t.Logf("Detected swtpm socket at %s", swtpmSock)
			cmd := exec.Command("tpm2_dictionarylockout", "-c")
			cmd.Env = append(os.Environ(), "TPM2TOOLS_TCTI=swtpm:path="+swtpmSock)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Logf("Warning: Could not reset TPM lockout counter via swtpm TCTI: %v\nOutput: %s", err, string(output))
			} else {
				t.Log("Successfully reset lockout via swtpm TCTI")
			}
			return
		}

		// Fallback: Try connecting directly to the socket as if it were a device
		t.Logf("Attempting direct socket reset at %s", tpmDevicePath)
		cmd := exec.Command("tpm2_dictionarylockout", "-c")
		cmd.Env = append(os.Environ(), "TPM2TOOLS_TCTI=device:"+tpmDevicePath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("Warning: Could not reset TPM lockout counter via device TCTI: %v\nOutput: %s", err, string(output))
		} else {
			t.Log("Successfully reset lockout via device TCTI")
		}
	} else {
		// It's a character device - use standard device TCTI
		t.Logf("Using device TCTI for %s", tpmDevicePath)
		cmd := exec.Command("tpm2_dictionarylockout", "-c")
		cmd.Env = append(os.Environ(), "TPM2TOOLS_TCTI=device:"+tpmDevicePath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("Warning: Could not reset TPM lockout counter: %v\nOutput: %s", err, string(output))
		} else {
			t.Log("Successfully reset lockout")
		}
	}
}

func TestMain(m *testing.M) {
	// Set the real TPM provider for integration tests
	tpm2auth.SetSystemTPMProvider(sharedProvider)
	os.Exit(m.Run())
}

// TestAuthenticateSuccess verifies successful unsealing with correct password.
func TestAuthenticateSuccess(t *testing.T) {
	skipIfTPMUnavailable(t)

	cfg := tpm2auth.Config{
		DevicePath:    tpmDevicePath,
		SealedHandle:  validHandle,
		PCRSelection:  []int{testPCR},
		HashAlgorithm: "SHA256",
	}

	auth, err := tpm2auth.NewAuthenticator(cfg, sharedProvider)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	ctx, cancel := testContext(t)
	defer cancel()

	err = auth.Authenticate(ctx, correctPassword)
	if err != nil {
		t.Fatalf("expected successful authentication, got error: %v", err)
	}
}

// TestAuthenticateFailureWrongPassword verifies authentication fails with incorrect password.
func TestAuthenticateFailureWrongPassword(t *testing.T) {
	skipIfTPMUnavailable(t)
	defer resetTPMLockout(t) // Reset lockout after this test causes auth failure

	cfg := tpm2auth.Config{
		DevicePath:    tpmDevicePath,
		SealedHandle:  validHandle,
		PCRSelection:  []int{testPCR},
		HashAlgorithm: "SHA256",
	}

	auth, err := tpm2auth.NewAuthenticator(cfg, sharedProvider)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	ctx, cancel := testContext(t)
	defer cancel()

	err = auth.Authenticate(ctx, wrongPassword)
	if err == nil {
		t.Fatal("expected authentication failure with wrong password")
	}
	if !errors.Is(err, tpm2auth.ErrInvalidPassword) {
		t.Errorf("expected ErrInvalidPassword, got: %v", err)
	}
}

// TestAuthenticateDifferentPasswords verifies the TPM distinguishes between sealed objects.
func TestAuthenticateDifferentPasswords(t *testing.T) {
	skipIfTPMUnavailable(t)
	defer resetTPMLockout(t) // Reset lockout after this test causes auth failures

	tests := []struct {
		name     string
		handle   tpm2auth.Handle
		password string
		wantErr  error
	}{
		{
			name:     "correct password for validHandle",
			handle:   validHandle,
			password: correctPassword,
			wantErr:  nil,
		},
		{
			name:     "wrong password for validHandle",
			handle:   validHandle,
			password: wrongPassword,
			wantErr:  tpm2auth.ErrInvalidPassword,
		},
		{
			name:     "correct password on wrong handle",
			handle:   invalidHandle,
			password: correctPassword,
			wantErr:  tpm2auth.ErrInvalidPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tpm2auth.Config{
				DevicePath:    tpmDevicePath,
				SealedHandle:  tt.handle,
				PCRSelection:  []int{testPCR},
				HashAlgorithm: "SHA256",
			}

			auth, err := tpm2auth.NewAuthenticator(cfg, sharedProvider)
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}

			ctx, cancel := testContext(t)
			defer cancel()

			err = auth.Authenticate(ctx, tt.password)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("expected success, got error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				} else if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

// TestAuthenticatePCRPolicy verifies PCR policy validation.
// Note: The sealed object was created with PCR 7 in its current state,
// so unsealing should succeed as long as PCR 7 hasn't been modified.
func TestAuthenticatePCRPolicy(t *testing.T) {
	skipIfTPMUnavailable(t)

	cfg := tpm2auth.Config{
		DevicePath:    tpmDevicePath,
		SealedHandle:  pcrPolicyHandle,
		PCRSelection:  []int{testPCR},
		HashAlgorithm: "SHA256",
	}

	auth, err := tpm2auth.NewAuthenticator(cfg, sharedProvider)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	ctx, cancel := testContext(t)
	defer cancel()

	// Should succeed when PCRs match the sealed policy
	// Note: password parameter is ignored for policy-based objects
	err = auth.Authenticate(ctx, correctPassword)
	if err != nil {
		t.Errorf("expected successful authentication with matching PCRs, got error: %v", err)
	}
}

// TestAuthenticateMultiplePCRs verifies unsealing with multiple PCR selections.
func TestAuthenticateMultiplePCRs(t *testing.T) {
	skipIfTPMUnavailable(t)
	defer resetTPMLockout(t) // Reset lockout after this test causes auth failure

	cfg := tpm2auth.Config{
		DevicePath:    tpmDevicePath,
		SealedHandle:  pcrPolicyHandle,
		PCRSelection:  []int{0, 1, 7}, // Multiple PCRs
		HashAlgorithm: "SHA256",
	}

	auth, err := tpm2auth.NewAuthenticator(cfg, sharedProvider)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	ctx, cancel := testContext(t)
	defer cancel()

	err = auth.Authenticate(ctx, correctPassword)
	// This test should fail because the object was sealed with only PCR 7,
	// but we're trying to validate with PCRs 0, 1, and 7
	if err == nil {
		t.Error("expected authentication failure with mismatched PCR selection")
	} else if !errors.Is(err, tpm2auth.ErrPCRMismatch) {
		t.Logf("Expected ErrPCRMismatch, got: %v", err)
	}
}

// TestAuthenticateHashAlgorithms verifies different hash algorithms.
func TestAuthenticateHashAlgorithms(t *testing.T) {
	skipIfTPMUnavailable(t)

	tests := []struct {
		name      string
		handle    tpm2auth.Handle
		algorithm string
		wantErr   bool
	}{
		{
			name:      "SHA256 explicit",
			handle:    validHandle,
			algorithm: "SHA256",
			wantErr:   false,
		},
		{
			name:      "SHA256 default (empty string)",
			handle:    validHandle,
			algorithm: "",
			wantErr:   false,
		},
		{
			name:      "SHA384",
			handle:    sha384Handle,
			algorithm: "SHA384",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tpm2auth.Config{
				DevicePath:    tpmDevicePath,
				SealedHandle:  tt.handle,
				PCRSelection:  []int{testPCR},
				HashAlgorithm: tt.algorithm,
			}

			auth, err := tpm2auth.NewAuthenticator(cfg, sharedProvider)
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}

			ctx, cancel := testContext(t)
			defer cancel()

			err = auth.Authenticate(ctx, correctPassword)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected success, got error: %v", err)
			}
		})
	}
}

// TestAuthenticateInvalidHandle verifies error handling for invalid handles.
func TestAuthenticateInvalidHandle(t *testing.T) {
	skipIfTPMUnavailable(t)

	cfg := tpm2auth.Config{
		DevicePath:    tpmDevicePath,
		SealedHandle:  tpm2auth.Handle(0x81009999), // Non-existent handle
		PCRSelection:  []int{testPCR},
		HashAlgorithm: "SHA256",
	}

	auth, err := tpm2auth.NewAuthenticator(cfg, sharedProvider)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	ctx, cancel := testContext(t)
	defer cancel()

	err = auth.Authenticate(ctx, correctPassword)
	if err == nil {
		t.Fatal("expected error for invalid handle, got nil")
	}

	// The error should indicate a handle-related issue
	t.Logf("Invalid handle error (expected): %v", err)
}

// TestAuthenticateTPMUnavailable verifies error when TPM device doesn't exist.
func TestAuthenticateTPMUnavailable(t *testing.T) {
	cfg := tpm2auth.Config{
		DevicePath:    "/dev/nonexistent-tpm",
		SealedHandle:  validHandle,
		PCRSelection:  []int{testPCR},
		HashAlgorithm: "SHA256",
	}

	auth, err := tpm2auth.NewAuthenticator(cfg, sharedProvider)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	ctx, cancel := testContext(t)
	defer cancel()

	err = auth.Authenticate(ctx, correctPassword)
	if err == nil {
		t.Fatal("expected error for unavailable TPM, got nil")
	}
	if !errors.Is(err, tpm2auth.ErrTPMUnavailable) {
		t.Errorf("expected ErrTPMUnavailable, got: %v", err)
	}
}

// TestAuthenticateContextCancellation verifies context cancellation is respected.
func TestAuthenticateContextCancellation(t *testing.T) {
	skipIfTPMUnavailable(t)

	cfg := tpm2auth.Config{
		DevicePath:    tpmDevicePath,
		SealedHandle:  validHandle,
		PCRSelection:  []int{testPCR},
		HashAlgorithm: "SHA256",
	}

	auth, err := tpm2auth.NewAuthenticator(cfg, sharedProvider)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = auth.Authenticate(ctx, correctPassword)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

// TestAuthenticateContextTimeout verifies context timeout is respected.
func TestAuthenticateContextTimeout(t *testing.T) {
	skipIfTPMUnavailable(t)

	cfg := tpm2auth.Config{
		DevicePath:    tpmDevicePath,
		SealedHandle:  validHandle,
		PCRSelection:  []int{testPCR},
		HashAlgorithm: "SHA256",
	}

	auth, err := tpm2auth.NewAuthenticator(cfg, sharedProvider)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Create context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait to ensure timeout
	time.Sleep(1 * time.Millisecond)

	err = auth.Authenticate(ctx, correctPassword)
	if err == nil {
		t.Fatal("expected error for timeout context, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}
}

// TestConcurrentAuthentication verifies thread-safety of the authenticator.
func TestConcurrentAuthentication(t *testing.T) {
	skipIfTPMUnavailable(t)

	cfg := tpm2auth.Config{
		DevicePath:    tpmDevicePath,
		SealedHandle:  validHandle,
		PCRSelection:  []int{testPCR},
		HashAlgorithm: "SHA256",
	}

	auth, err := tpm2auth.NewAuthenticator(cfg, sharedProvider)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	const numGoroutines = 5
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			ctx, cancel := testContext(t)
			defer cancel()
			errChan <- auth.Authenticate(ctx, correctPassword)
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		if err := <-errChan; err != nil {
			t.Errorf("concurrent authentication %d failed: %v", i, err)
		}
	}
}

// BenchmarkAuthenticate measures TPM unsealing performance.
func BenchmarkAuthenticate(b *testing.B) {
	if _, err := os.Stat(tpmDevicePath); os.IsNotExist(err) {
		b.Skipf("TPM device not available at %s", tpmDevicePath)
	}

	cfg := tpm2auth.Config{
		DevicePath:    tpmDevicePath,
		SealedHandle:  validHandle,
		PCRSelection:  []int{testPCR},
		HashAlgorithm: "SHA256",
	}

	auth, err := tpm2auth.NewAuthenticator(cfg, sharedProvider)
	if err != nil {
		b.Fatalf("failed to create authenticator: %v", err)
	}

	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := auth.Authenticate(ctx, correctPassword); err != nil {
			b.Fatalf("authentication failed: %v", err)
		}
	}
}
