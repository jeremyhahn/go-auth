package pam

import (
	"context"
	"errors"
	"testing"
)

func TestNewAuthenticatorValidatesServiceName(t *testing.T) {
	_, err := NewAuthenticator("", nil)
	if err == nil {
		t.Fatalf("expected error for empty service name")
	}
}

func TestNewAuthenticatorUsesDefaultOpenerWhenNil(t *testing.T) {
	original := systemSessionOpener
	defer func() { systemSessionOpener = original }()

	fake := &fakeSessionOpener{}
	systemSessionOpener = fake

	auth, err := NewAuthenticator("testservice", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth.sessionOpener != fake {
		t.Fatalf("expected default session opener to be injected")
	}
}

type fakeSession struct {
	authenticateErr error
	closeErr        error
	authenticated   bool
	closed          bool
}

func (f *fakeSession) Authenticate(_ context.Context, password string) error {
	if password == "" {
		return errors.New("password must not be empty")
	}
	if f.authenticateErr != nil {
		return f.authenticateErr
	}
	f.authenticated = true
	return nil
}

func (f *fakeSession) Close() error {
	f.closed = true
	return f.closeErr
}

type fakeSessionOpener struct {
	session       Session
	openErr       error
	lastService   string
	lastUsername  string
	openCallCount int
}

func (f *fakeSessionOpener) Open(_ context.Context, service, username string) (Session, error) {
	f.openCallCount++
	f.lastService = service
	f.lastUsername = username
	if f.openErr != nil {
		return nil, f.openErr
	}
	return f.session, nil
}

func TestAuthenticateSuccess(t *testing.T) {
	fakeSess := &fakeSession{}
	opener := &fakeSessionOpener{session: fakeSess}
	auth, err := NewAuthenticator("login", opener)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "jane", "s3cret")
	if err != nil {
		t.Fatalf("unexpected authentication error: %v", err)
	}

	if !fakeSess.authenticated {
		t.Fatalf("expected session to authenticate")
	}
	if !fakeSess.closed {
		t.Fatalf("expected session to close")
	}
	if opener.lastService != "login" || opener.lastUsername != "jane" {
		t.Fatalf("unexpected session open parameters: got service=%q username=%q", opener.lastService, opener.lastUsername)
	}
}

func TestAuthenticateValidatesInputs(t *testing.T) {
	opener := &fakeSessionOpener{}
	auth, err := NewAuthenticator("login", opener)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	cases := []struct {
		name     string
		username string
		password string
	}{
		{name: "empty username", password: "secret"},
		{name: "empty password", username: "jane"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := auth.Authenticate(context.Background(), tc.username, tc.password)
			if err == nil {
				t.Fatalf("expected error for invalid input")
			}
			if opener.openCallCount != 0 {
				t.Fatalf("expected session opener to not be called on invalid input")
			}
		})
	}
}

func TestAuthenticatePropagatesSessionOpenError(t *testing.T) {
	opener := &fakeSessionOpener{openErr: errors.New("boom")}
	auth, err := NewAuthenticator("login", opener)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "jane", "pw")
	if !errors.Is(err, opener.openErr) {
		t.Fatalf("expected open error, got %v", err)
	}
}

func TestAuthenticatePropagatesSessionAuthenticateError(t *testing.T) {
	fakeSess := &fakeSession{authenticateErr: errors.New("denied")}
	opener := &fakeSessionOpener{session: fakeSess}
	auth, err := NewAuthenticator("login", opener)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "jane", "pw")
	if !errors.Is(err, fakeSess.authenticateErr) {
		t.Fatalf("expected authenticate error, got %v", err)
	}
	if !fakeSess.closed {
		t.Fatalf("expected session to close even on failure")
	}
}

func TestAuthenticateJoinsErrorsWhenCloseFailsAfterAuthError(t *testing.T) {
	authErr := errors.New("denied")
	closeErr := errors.New("close failure")
	fakeSess := &fakeSession{authenticateErr: authErr, closeErr: closeErr}
	opener := &fakeSessionOpener{session: fakeSess}
	auth, err := NewAuthenticator("login", opener)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "jane", "pw")
	if !errors.Is(err, authErr) {
		t.Fatalf("expected authenticate error to be present, got %v", err)
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("expected close error to be present, got %v", err)
	}
	if !fakeSess.closed {
		t.Fatalf("expected session to close when errors occur")
	}
}

func TestAuthenticateClosesSessionOnCloseFailure(t *testing.T) {
	fakeSess := &fakeSession{closeErr: errors.New("close failure")}
	opener := &fakeSessionOpener{session: fakeSess}
	auth, err := NewAuthenticator("login", opener)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(context.Background(), "jane", "pw")
	if err == nil {
		t.Fatalf("expected error when close fails")
	}
	if !errors.Is(err, fakeSess.closeErr) {
		t.Fatalf("expected close error, got %v", err)
	}
}

func TestAuthenticateHonorsCanceledContext(t *testing.T) {
	opener := &fakeSessionOpener{}
	auth, err := NewAuthenticator("login", opener)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = auth.Authenticate(ctx, "jane", "pw")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
	if opener.openCallCount != 0 {
		t.Fatalf("expected session open not to run when context canceled")
	}
}

func TestAuthenticateHonorsContextCanceledAfterOpen(t *testing.T) {
	sess := &idleSession{}
	ctx, cancel := context.WithCancel(context.Background())
	opener := &cancelingSessionOpener{session: sess, cancel: cancel}
	auth, err := NewAuthenticator("login", opener)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	err = auth.Authenticate(ctx, "jane", "pw")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
	if sess.authenticateCalled {
		t.Fatalf("expected session authenticate not to be called when context canceled")
	}
	if !sess.closed {
		t.Fatalf("expected session to close when context canceled")
	}
}

func TestAuthenticateAllowsNilContext(t *testing.T) {
	fakeSess := &fakeSession{}
	opener := &fakeSessionOpener{session: fakeSess}
	auth, err := NewAuthenticator("login", opener)
	if err != nil {
		t.Fatalf("unexpected error creating authenticator: %v", err)
	}

	if err := auth.Authenticate(nil, "jane", "pw"); err != nil {
		t.Fatalf("unexpected authentication error: %v", err)
	}
	if !fakeSess.authenticated {
		t.Fatalf("expected session to authenticate with nil context")
	}
	if !fakeSess.closed {
		t.Fatalf("expected session to close with nil context")
	}
}

type idleSession struct {
	authenticateCalled bool
	closed             bool
}

func (s *idleSession) Authenticate(_ context.Context, _ string) error {
	s.authenticateCalled = true
	return nil
}

func (s *idleSession) Close() error {
	s.closed = true
	return nil
}

type cancelingSessionOpener struct {
	session Session
	cancel  context.CancelFunc
}

func (o *cancelingSessionOpener) Open(ctx context.Context, service, username string) (Session, error) {
	_ = service
	_ = username
	if o.cancel != nil {
		o.cancel()
	}
	return o.session, nil
}
