//go:build cgo

package pam

import (
	"context"
	"errors"
	"fmt"
	"sync"

	pam "github.com/msteinert/pam/v2"
)

var _ SessionOpener = defaultSessionOpener{}

func init() {
	systemSessionOpener = defaultSessionOpener{}
}

func (defaultSessionOpener) Open(ctx context.Context, service, username string) (Session, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	sess := &pamSession{}
	txn, err := pam.StartFunc(service, username, sess.conversation)
	if err != nil {
		return nil, err
	}
	sess.txn = txn
	return sess, nil
}

type pamSession struct {
	txn      *pam.Transaction
	mu       sync.Mutex
	password string
}

func (s *pamSession) conversation(style pam.Style, msg string) (string, error) {
	switch style {
	case pam.PromptEchoOff:
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.password == "" {
			return "", errors.New("pam password not set")
		}
		return s.password, nil
	case pam.PromptEchoOn:
		return "", fmt.Errorf("unexpected echo-on prompt: %s", msg)
	case pam.ErrorMsg, pam.TextInfo:
		return "", nil
	default:
		return "", fmt.Errorf("unsupported PAM style: %d", style)
	}
}

func (s *pamSession) Authenticate(ctx context.Context, password string) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	} else {
		ctx = context.Background()
	}

	s.setPassword(password)
	defer s.clearPassword()

	if err := s.txn.Authenticate(pam.Silent); err != nil {
		return err
	}
	if err := s.txn.AcctMgmt(pam.Silent); err != nil {
		return err
	}
	return nil
}

func (s *pamSession) Close() error {
	return s.txn.End()
}

func (s *pamSession) setPassword(password string) {
	s.mu.Lock()
	s.password = password
	s.mu.Unlock()
}

func (s *pamSession) clearPassword() {
	s.mu.Lock()
	s.password = ""
	s.mu.Unlock()
}
