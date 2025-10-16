//go:build pkcs11 && cgo

package pkcs11

import (
	"context"
	"errors"
	"strconv"
	"strings"

	pkcs "github.com/miekg/pkcs11"
)

func init() {
	systemSessionProvider = &nativeProvider{}
}

type nativeProvider struct{}

func (nativeProvider) Open(ctx context.Context, cfg Config) (Session, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	module := pkcs.New(cfg.ModulePath)
	if module == nil {
		return nil, errors.New("pkcs11: failed to load module")
	}
	if err := module.Initialize(); err != nil {
		module.Destroy()
		return nil, err
	}

	slot, err := selectSlot(module, cfg)
	if err != nil {
		module.Finalize()
		module.Destroy()
		return nil, err
	}

	sessionHandle, err := module.OpenSession(slot, pkcs.CKF_SERIAL_SESSION|pkcs.CKF_RW_SESSION)
	if err != nil {
		module.Finalize()
		module.Destroy()
		return nil, err
	}

	return &nativeSession{module: module, session: sessionHandle}, nil
}

func selectSlot(module *pkcs.Ctx, cfg Config) (uint, error) {
	if cfg.Slot != "" {
		id, err := strconv.ParseUint(cfg.Slot, 10, 32)
		if err != nil {
			return 0, err
		}
		return uint(id), nil
	}

	slots, err := module.GetSlotList(true)
	if err != nil {
		return 0, err
	}
	label := strings.TrimSpace(cfg.TokenLabel)
	for _, slot := range slots {
		info, err := module.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(info.Label), label) {
			return slot, nil
		}
	}
	return 0, errors.New("pkcs11: token not found")
}

type nativeSession struct {
	module  *pkcs.Ctx
	session pkcs.SessionHandle
}

func (s *nativeSession) Login(ctx context.Context, pin string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.module.Login(s.session, pkcs.CKU_USER, pin)
}

func (s *nativeSession) Logout(ctx context.Context) error {
	defer func() {
		s.module.CloseSession(s.session)
		s.module.Finalize()
		s.module.Destroy()
	}()

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.module.Logout(s.session); err != nil && err != pkcs.Error(pkcs.CKR_USER_NOT_LOGGED_IN) {
		return err
	}
	return nil
}
