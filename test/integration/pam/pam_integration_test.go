//go:build integration

package pam_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pamlib "github.com/jeremyhahn/go-auth/pkg/pam"
)

func newAuthenticator(t *testing.T) *pamlib.Authenticator {
	t.Helper()
	auth, err := pamlib.NewAuthenticator("go-auth-test", nil)
	if err != nil {
		t.Fatalf("failed to construct authenticator: %v", err)
	}
	return auth
}

func TestAuthenticateSuccess(t *testing.T) {
	auth := newAuthenticator(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := auth.Authenticate(ctx, "pamuser", sealed(t, "secretpw")); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestAuthenticateRejectsWrongPassword(t *testing.T) {
	auth := newAuthenticator(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := auth.Authenticate(ctx, "pamuser", sealed(t, "badpass"))
	if err == nil {
		t.Fatal("expected authentication failure for wrong password")
	}
	if !strings.Contains(err.Error(), "Authentication") {
		t.Fatalf("expected PAM authentication error, got: %v", err)
	}
}

func TestAuthenticateRejectsUnknownUser(t *testing.T) {
	auth := newAuthenticator(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := auth.Authenticate(ctx, "doesnotexist", sealed(t, "secretpw"))
	if err == nil {
		t.Fatal("expected failure for unknown user")
	}
	if !strings.Contains(err.Error(), "User unknown") && !strings.Contains(err.Error(), "User not known") {
		t.Fatalf("expected PAM unknown user error, got: %v", err)
	}
}

func TestAuthenticateRejectsExpiredAccount(t *testing.T) {
	auth := newAuthenticator(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := auth.Authenticate(ctx, "expireduser", sealed(t, "secretpw"))
	if err == nil {
		t.Fatal("expected failure for expired account")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "account") {
		t.Fatalf("expected account error, got: %v", err)
	}
}

func TestAuthenticateHonorsCanceledContextBeforeCall(t *testing.T) {
	auth := newAuthenticator(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := auth.Authenticate(ctx, "pamuser", sealed(t, "secretpw")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
}

// TestAuthenticateBorrowsThePassword drives the real cgo conversation twice
// with one enclave: the password is lent to libpam through a wiped transient
// copy (residue R6), so the caller's enclave is still alive and usable after
// each call, and a second login with it succeeds.
func TestAuthenticateBorrowsThePassword(t *testing.T) {
	auth := newAuthenticator(t)
	password := sealed(t, "secretpw")

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := auth.Authenticate(ctx, "pamuser", password)
		cancel()
		if err != nil {
			t.Fatalf("attempt %d: expected success, got error: %v", i, err)
		}
		if !password.IsAlive() {
			t.Fatalf("attempt %d: Authenticate destroyed a borrowed password", i)
		}
	}
}

// TestAuthenticateRejectsDestroyedPassword: a destroyed enclave never reaches
// libpam.
func TestAuthenticateRejectsDestroyedPassword(t *testing.T) {
	auth := newAuthenticator(t)
	password := sealed(t, "secretpw")
	password.Destroy()

	err := auth.Authenticate(context.Background(), "pamuser", password)
	if !errors.Is(err, pamlib.ErrMissingPassword) {
		t.Fatalf("expected ErrMissingPassword, got %v", err)
	}
}
