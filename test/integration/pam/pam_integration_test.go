//go:build integration

package pam_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pamlib "github.com/jhahn/go-auth/pkg/pam"
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

	if err := auth.Authenticate(ctx, "pamuser", "secretpw"); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestAuthenticateRejectsWrongPassword(t *testing.T) {
	auth := newAuthenticator(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := auth.Authenticate(ctx, "pamuser", "badpass")
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

	err := auth.Authenticate(ctx, "doesnotexist", "secretpw")
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

	err := auth.Authenticate(ctx, "expireduser", "secretpw")
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

	if err := auth.Authenticate(ctx, "pamuser", "secretpw"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
}
