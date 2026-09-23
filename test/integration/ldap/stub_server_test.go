//go:build integration

package ldap_integration_test

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// This file is the suite's LDAP fixture: a minimal in-process LDAPv3 server
// implementing exactly the operations pkg/ldap's Authenticator performs —
// simple Bind, the StartTLS extended operation, and Unbind — plus Search over a
// fixed directory, served over plain TCP or a TLS listener (ldaps). It replaces github.com/vjeantet/ldapserver, which is
// unmaintained and carries a shutdown race (#15). Shutdown here is ordered:
// Close stops the listener, closes every live connection, and waits for every
// connection goroutine before returning, so no goroutine outlives the test.

// LDAPv3 protocol-op application tags (RFC 4511 §4.2, §4.3, §4.5, §4.12).
const (
	appBindRequest      ber.Tag = 0
	appBindResponse     ber.Tag = 1
	appUnbindRequest    ber.Tag = 2
	appSearchRequest    ber.Tag = 3
	appSearchResultItem ber.Tag = 4
	appSearchResultDone ber.Tag = 5
	appExtendedRequest  ber.Tag = 23
	appExtendedResponse ber.Tag = 24
)

// LDAP result codes used by the stub (RFC 4511 §4.1.9).
const (
	resultSuccess              = 0
	resultProtocolError        = 2
	resultInvalidCredentials   = 49
	resultUnwillingToPerform   = 53
	startTLSOID                = "1.3.6.1.4.1.1466.20037"
	simpleAuthenticationTag    = ber.Tag(0)
	extendedRequestNameTag     = ber.Tag(0)
	messageIDIndex             = 0
	protocolOpIndex            = 1
	bindNameIndex              = 1
	bindAuthenticationIndex    = 2
	minLDAPMessageChildren     = 2
	minBindRequestChildren     = 3
	minExtendedRequestChildren = 1

	// SearchRequest fields (RFC 4511 §4.5.1).
	searchBaseIndex        = 0
	searchScopeIndex       = 1
	searchFilterIndex      = 6
	searchAttributesIndex  = 7
	minSearchRequestFields = 8
	scopeBaseObject        = 0
	scopeSingleLevel       = 1
	scopeWholeSubtree      = 2
	filterEqualityTag      = ber.Tag(3)
	filterPresentTag       = ber.Tag(7)
	equalityFilterFields   = 2
)

var (
	errMalformedMessage     = errors.New("ldap stub: malformed LDAPMessage")
	errUnsupportedOperation = errors.New("ldap stub: unsupported operation")
	errUnbind               = errors.New("ldap stub: client unbound")
	errUnsupportedFilter    = errors.New("ldap stub: unsupported search filter")
	errUnsupportedScope     = errors.New("ldap stub: unsupported search scope")
)

// stubEntry is one directory entry the stub serves to Search.
type stubEntry struct {
	dn    string
	attrs map[string][]string
}

// scopeMatchers decide whether dn is within scope of base (both lower-cased).
var scopeMatchers = map[int64]func(dn, base string) bool{
	scopeBaseObject: func(dn, base string) bool { return dn == base },
	scopeSingleLevel: func(dn, base string) bool {
		rdn, ok := strings.CutSuffix(dn, ","+base)
		return ok && rdn != "" && !strings.Contains(rdn, ",")
	},
	scopeWholeSubtree: func(dn, base string) bool {
		return dn == base || strings.HasSuffix(dn, ","+base)
	},
}

// filterMatchers evaluate the filter choices the stub supports (RFC 4511
// §4.5.1.7): equalityMatch and present.
var filterMatchers = map[ber.Tag]func(f *ber.Packet, e stubEntry) (bool, error){
	filterEqualityTag: func(f *ber.Packet, e stubEntry) (bool, error) {
		if len(f.Children) != equalityFilterFields {
			return false, errMalformedMessage
		}
		want := f.Children[1].Data.String()
		for _, v := range entryValues(e, f.Children[0].Data.String()) {
			if strings.EqualFold(v, want) {
				return true, nil
			}
		}
		return false, nil
	},
	filterPresentTag: func(f *ber.Packet, e stubEntry) (bool, error) {
		return len(entryValues(e, f.Data.String())) > 0, nil
	},
}

// entryValues returns the values of attr on e; attribute names are
// case-insensitive (RFC 4512 §2.5).
func entryValues(e stubEntry, attr string) []string {
	for name, vals := range e.attrs {
		if strings.EqualFold(name, attr) {
			return vals
		}
	}
	return nil
}

// stubServer is the in-process LDAP fixture.
type stubServer struct {
	t         *testing.T
	listener  net.Listener
	creds     map[string]string
	startTLS  *tls.Config
	handlers  map[ber.Tag]opHandler
	wg        sync.WaitGroup
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	closed    bool
	closeOnce sync.Once
	entries   []stubEntry

	// binds records every bind DN the server answered, in order, so tests
	// can assert which bind paths the client actually exercised.
	binds []bindRecord
}

type bindRecord struct {
	dn      string
	success bool
	tls     bool
}

// session is one client connection's state.
type session struct {
	conn net.Conn
	tls  bool
}

// opHandler handles one protocol op. It may replace sess.conn (StartTLS
// does); a non-nil error ends the session.
type opHandler func(s *stubServer, sess *session, messageID int64, op *ber.Packet) error

type stubOption func(*stubServer)

// withLDAPS wraps the listener in TLS, serving ldaps://.
func withLDAPS(cfg *tls.Config) stubOption {
	return func(s *stubServer) {
		s.listener = tls.NewListener(s.listener, cfg)
	}
}

// withEntries sets the directory the stub serves to Search.
func withEntries(entries ...stubEntry) stubOption {
	return func(s *stubServer) {
		s.entries = entries
	}
}

// withStartTLS enables the StartTLS extended operation using cfg.
func withStartTLS(cfg *tls.Config) stubOption {
	return func(s *stubServer) {
		s.startTLS = cfg
	}
}

// startStubServer listens on a loopback port and serves until the test ends.
// The returned address is ready for connections as soon as it is returned.
func startStubServer(t *testing.T, creds map[string]string, opts ...stubOption) *stubServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ldap stub: listen: %v", err)
	}

	s := &stubServer{
		t:        t,
		listener: ln,
		creds:    creds,
		conns:    make(map[net.Conn]struct{}),
		handlers: map[ber.Tag]opHandler{
			appBindRequest:     handleBind,
			appUnbindRequest:   handleUnbind,
			appExtendedRequest: handleExtended,
			appSearchRequest:   handleSearch,
		},
	}
	for _, opt := range opts {
		opt(s)
	}

	s.wg.Add(1)
	go s.acceptLoop()
	t.Cleanup(s.Close)
	return s
}

// Addr is the host:port the server listens on.
func (s *stubServer) Addr() string {
	return s.listener.Addr().String()
}

// Close stops accepting, closes every open connection, and waits for all
// server goroutines to exit. It is safe to call more than once.
func (s *stubServer) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		_ = s.listener.Close()
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
}

// Binds returns a copy of the bind log.
func (s *stubServer) Binds() []bindRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]bindRecord(nil), s.binds...)
}

func (s *stubServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		if !s.track(conn) {
			_ = conn.Close()
			return
		}
		s.wg.Add(1)
		go s.serve(conn)
	}
}

// track registers conn for shutdown; it reports false once Close has begun.
func (s *stubServer) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *stubServer) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *stubServer) untrack(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

func (s *stubServer) serve(conn net.Conn) {
	defer s.wg.Done()
	_, isTLS := conn.(*tls.Conn)
	sess := &session{conn: conn, tls: isTLS}
	defer func() {
		_ = sess.conn.Close()
		s.untrack(conn)
	}()

	for {
		// Read straight from the connection, never through a buffer: after
		// StartTLS the next bytes on the wire are the client's TLS handshake,
		// and a read-ahead buffer would swallow them.
		packet, err := ber.ReadPacket(sess.conn)
		if err != nil {
			return
		}
		if err := s.dispatch(sess, packet); err != nil {
			if !errors.Is(err, errUnbind) && !s.isClosed() {
				s.t.Errorf("ldap stub: %v", err)
			}
			return
		}
	}
}

func (s *stubServer) dispatch(sess *session, packet *ber.Packet) error {
	if len(packet.Children) < minLDAPMessageChildren {
		return errMalformedMessage
	}
	messageID, ok := packet.Children[messageIDIndex].Value.(int64)
	if !ok {
		return errMalformedMessage
	}
	op := packet.Children[protocolOpIndex]
	handler, ok := s.handlers[op.Tag]
	if !ok || op.ClassType != ber.ClassApplication {
		return fmt.Errorf("%w: class %d tag %d", errUnsupportedOperation, op.ClassType, op.Tag)
	}
	return handler(s, sess, messageID, op)
}

func handleBind(s *stubServer, sess *session, messageID int64, op *ber.Packet) error {
	if len(op.Children) < minBindRequestChildren {
		return errMalformedMessage
	}
	dn := op.Children[bindNameIndex].Data.String()
	auth := op.Children[bindAuthenticationIndex]
	if auth.ClassType != ber.ClassContext || auth.Tag != simpleAuthenticationTag {
		return fmt.Errorf("%w: non-simple bind", errUnsupportedOperation)
	}
	password := auth.Data.String()

	expected, known := s.creds[dn]
	success := known && expected == password

	s.mu.Lock()
	s.binds = append(s.binds, bindRecord{dn: dn, success: success, tls: sess.tls})
	s.mu.Unlock()

	code, diag := resultSuccess, ""
	if !success {
		code, diag = resultInvalidCredentials, "invalid credentials"
	}
	return writeResponse(sess.conn, messageID, appBindResponse, code, diag)
}

func handleUnbind(_ *stubServer, _ *session, _ int64, _ *ber.Packet) error {
	return errUnbind
}

func handleExtended(s *stubServer, sess *session, messageID int64, op *ber.Packet) error {
	if len(op.Children) < minExtendedRequestChildren ||
		op.Children[0].ClassType != ber.ClassContext ||
		op.Children[0].Tag != extendedRequestNameTag {
		return errMalformedMessage
	}
	name := op.Children[0].Data.String()
	if name != startTLSOID {
		return writeResponse(sess.conn, messageID, appExtendedResponse, resultProtocolError, "unsupported extended operation")
	}
	if s.startTLS == nil || sess.tls {
		return writeResponse(sess.conn, messageID, appExtendedResponse, resultUnwillingToPerform, "StartTLS not available")
	}
	if err := writeResponse(sess.conn, messageID, appExtendedResponse, resultSuccess, ""); err != nil {
		return err
	}
	tlsConn := tls.Server(sess.conn, s.startTLS)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("ldap stub: StartTLS handshake: %w", err)
	}
	sess.conn = tlsConn
	sess.tls = true
	return nil
}

func handleSearch(s *stubServer, sess *session, messageID int64, op *ber.Packet) error {
	if len(op.Children) < minSearchRequestFields {
		return errMalformedMessage
	}
	base := strings.ToLower(op.Children[searchBaseIndex].Data.String())
	scope, ok := op.Children[searchScopeIndex].Value.(int64)
	if !ok {
		return errMalformedMessage
	}
	inScope, ok := scopeMatchers[scope]
	if !ok {
		return fmt.Errorf("%w: %d", errUnsupportedScope, scope)
	}
	filter := op.Children[searchFilterIndex]
	match, ok := filterMatchers[filter.Tag]
	if !ok || filter.ClassType != ber.ClassContext {
		return fmt.Errorf("%w: class %d tag %d", errUnsupportedFilter, filter.ClassType, filter.Tag)
	}
	var requested []string
	for _, a := range op.Children[searchAttributesIndex].Children {
		requested = append(requested, a.Data.String())
	}

	for _, e := range s.entries {
		if !inScope(strings.ToLower(e.dn), base) {
			continue
		}
		matched, err := match(filter, e)
		if err != nil {
			return err
		}
		if !matched {
			continue
		}
		if err := writeMessage(sess.conn, messageID, encodeEntry(e, requested)); err != nil {
			return err
		}
	}
	return writeResponse(sess.conn, messageID, appSearchResultDone, resultSuccess, "")
}

// encodeEntry builds a SearchResultEntry (RFC 4511 §4.5.2) carrying the
// requested attributes, or all of them when none were requested.
func encodeEntry(e stubEntry, requested []string) *ber.Packet {
	names := requested
	if len(names) == 0 {
		for name := range e.attrs {
			names = append(names, name)
		}
		sort.Strings(names)
	}
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchResultItem, nil, "SearchResultEntry")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, "objectName"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, name := range names {
		vals := entryValues(e, name)
		if len(vals) == 0 {
			continue
		}
		attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range vals {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "value"))
		}
		attr.AppendChild(set)
		attrs.AppendChild(attr)
	}
	entry.AppendChild(attrs)
	return entry
}

// writeResponse sends an LDAPResult-shaped response (RFC 4511 §4.1.9).
func writeResponse(conn net.Conn, messageID int64, tag ber.Tag, code int, diag string) error {
	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "Response")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diag, "diagnosticMessage"))
	return writeMessage(conn, messageID, resp)
}

// writeMessage wraps op in an LDAPMessage envelope and sends it.
func writeMessage(conn net.Conn, messageID int64, op *ber.Packet) error {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	msg.AppendChild(op)
	if _, err := conn.Write(msg.Bytes()); err != nil {
		return fmt.Errorf("ldap stub: write response: %w", err)
	}
	return nil
}
