//go:build integration && cgo && pkcs11

package auth_integration_test

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-auth/pkg/api"
	"github.com/jeremyhahn/go-auth/pkg/pkcs11"
	"github.com/jeremyhahn/go-auth/pkg/yubikey"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func setupSoftHSMToken(t *testing.T) (pkcs11.Config, string) {
	modulePath := "/usr/lib/softhsm/libsofthsm2.so"
	if _, err := os.Stat(modulePath); err != nil {
		t.Skipf("SoftHSM module not present at %s", modulePath)
	}

	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, "softhsm2.conf")
	if err := os.WriteFile(confPath, []byte(fmt.Sprintf("directories.tokendir = %s\nobjectstore.backend = file\n", filepath.Join(tempDir, "tokens"))), 0600); err != nil {
		t.Fatalf("write softhsm config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tempDir, "tokens"), 0700); err != nil {
		t.Fatalf("mkdir tokens: %v", err)
	}

	if err := os.Setenv("SOFTHSM2_CONF", confPath); err != nil {
		t.Fatalf("set SOFTHSM2_CONF: %v", err)
	}

	label := fmt.Sprintf("go-auth-%d", rand.Int())
	soPIN := "123456"
	userPIN := "987654"

	cmd := exec.Command("softhsm2-util", "--init-token", "--free", "--label", label, "--so-pin", soPIN, "--pin", userPIN)
	cmd.Env = append(os.Environ(), fmt.Sprintf("SOFTHSM2_CONF=%s", confPath))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("init token failed: %v (%s)", err, string(out))
	}

	return pkcs11.Config{ModulePath: modulePath, TokenLabel: label}, userPIN
}

func TestPKCS11SoftHSMIntegration(t *testing.T) {
	cfg, pin := setupSoftHSMToken(t)

	auth, err := pkcs11.NewAuthenticator(cfg, nil)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	service, err := api.NewService(api.Config{Backends: []api.Backend{
		{Name: api.BackendPKCS11, Handler: api.PKCS11(auth)},
	}})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	if err := service.Login(context.Background(), api.LoginRequest{Username: "token-user", Password: pin}); err != nil {
		t.Fatalf("expected PKCS#11 login success, got %v", err)
	}
}

func TestPKCS11FallbackToYubiKey(t *testing.T) {
	// Use stub validator to confirm fallback path without hitting external service.
	validator := &stubYubiValidator{expectedOTP: "otp-value"}
	yubikey.SetSystemValidator(validator)
	t.Cleanup(func() { yubikey.SetSystemValidator(nil) })
	yubiAuth, err := yubikey.NewAuthenticator(yubikey.Config{ClientID: "client", APIKey: "secret"}, nil)
	if err != nil {
		t.Fatalf("NewAuthenticator(yubikey): %v", err)
	}

	cfg, pin := setupSoftHSMToken(t)
	pkcsAuth, err := pkcs11.NewAuthenticator(cfg, nil)
	if err != nil {
		t.Fatalf("NewAuthenticator(pkcs11): %v", err)
	}

	service, err := api.NewService(api.Config{Backends: []api.Backend{
		{Name: api.BackendPKCS11, Handler: api.PKCS11(pkcsAuth)},
		{Name: api.BackendYubiKey, Handler: api.YubiKey(yubiAuth)},
	}})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// Wrong PIN, correct OTP. Should fall back to YubiKey backend.
	if err := service.Login(context.Background(), api.LoginRequest{Username: "user", Password: pin + "!", OTP: "otp-value"}); err != nil {
		t.Fatalf("expected fallback success, got %v", err)
	}

	if validator.calls != 1 {
		t.Fatalf("expected YubiKey validator called once, got %d", validator.calls)
	}
}

// Stub validator used for fallback testing.
type stubYubiValidator struct {
	expectedOTP string
	calls       int
	err         error
}

func (v *stubYubiValidator) Validate(ctx context.Context, clientID, secret, otp string) error {
	v.calls++
	if v.err != nil {
		return v.err
	}
	if otp != v.expectedOTP {
		return yubikey.ErrInvalidOTP
	}
	return nil
}
