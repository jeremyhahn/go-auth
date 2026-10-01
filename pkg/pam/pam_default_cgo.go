//go:build cgo

package pam

import (
	"context"
	"errors"
	"sync"

	enclave "github.com/jeremyhahn/go-enclave"
	pam "github.com/msteinert/pam/v2"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
)

var _ SessionOpener = defaultSessionOpener{}

var (
	// errResponseNotSet means the PAM stack prompted for a password outside
	// an Authenticate call, when there is nothing to answer with.
	errResponseNotSet = errors.New("pam: conversation password not set")
	// errUnexpectedEchoOnPrompt means the stack asked for visible input,
	// which a password login never answers.
	errUnexpectedEchoOnPrompt = errors.New("pam: unexpected echo-on prompt")
	// errUnsupportedStyle means the stack used a conversation style this
	// client does not implement (the binary prompt, or an unknown one).
	errUnsupportedStyle = errors.New("pam: unsupported conversation style")
)

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
	txn *pam.Transaction
	mu  sync.Mutex
	// response is the reply to a password prompt, set only while
	// Authenticate is running. It is a string because msteinert/pam's
	// conversation callback must return one, but it is not an ordinary
	// string: credential.WithTransientString backs it with a heap buffer that
	// is wiped as soon as the PAM calls return. Residue R6.
	response string
}

// conversationStyles answers each PAM message style. Informational messages
// get an empty reply; every style not listed is refused.
var conversationStyles = map[pam.Style]func(s *pamSession, msg string) (string, error){
	pam.PromptEchoOff: func(s *pamSession, _ string) (string, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.response == "" {
			return "", errResponseNotSet
		}
		return s.response, nil
	},
	pam.PromptEchoOn: func(*pamSession, string) (string, error) {
		return "", errUnexpectedEchoOnPrompt
	},
	pam.ErrorMsg: func(*pamSession, string) (string, error) { return "", nil },
	pam.TextInfo: func(*pamSession, string) (string, error) { return "", nil },
}

// conversation is msteinert/pam's callback. The string it returns is copied
// straight into C memory with C.CString and handed to the PAM module, which
// owns and frees that copy (Linux-PAM's pam_get_authtok overwrites it before
// freeing; other modules may not). go-auth cannot reach the C copy: it is the
// part of residue R6 that belongs to the binding and the module.
func (s *pamSession) conversation(style pam.Style, msg string) (string, error) {
	respond, ok := conversationStyles[style]
	if !ok {
		return "", errUnsupportedStyle
	}
	return respond(s, msg)
}

func (s *pamSession) Authenticate(ctx context.Context, password *enclave.MemoryEnclave) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	// Residue R6: the conversation reply must be a Go string. It lives in a
	// buffer that is wiped when the PAM calls below return, on every path.
	return credential.WithTransientString(password, func(reply string) error {
		s.setResponse(reply)
		defer s.clearResponse()

		if err := s.txn.Authenticate(pam.Silent); err != nil {
			return err
		}
		return s.txn.AcctMgmt(pam.Silent)
	})
}

func (s *pamSession) Close() error {
	return s.txn.End()
}

func (s *pamSession) setResponse(reply string) {
	s.mu.Lock()
	s.response = reply
	s.mu.Unlock()
}

// clearResponse drops the session's reference to the reply. The bytes
// themselves are wiped by credential.WithTransientString, which this runs
// inside of; dropping the reference keeps a later prompt from seeing zeros
// instead of being refused.
func (s *pamSession) clearResponse() {
	s.mu.Lock()
	s.response = ""
	s.mu.Unlock()
}
