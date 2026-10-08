package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-auth/pkg/internal/credential"
)

// This file holds the plumbing that keeps OAuth credentials — the client
// secret, access, refresh and ID tokens, passwords and PKCE verifiers — in
// go-enclave locked memory between the caller and the wire.
//
// A credential is opened with WithBytes only where a dependency forces it, and
// every such site carries a one-line comment naming its residue:
//
//   - R5 (go-auth#3): net/http and crypto/tls keep their own copies of request
//     bodies and headers, and of response bodies, in ordinary heap that this
//     package cannot wipe. Form bodies are assembled in locked pages and token
//     responses are decoded straight into enclaves, so R5 is the transport's
//     own buffers and nothing more.
//   - JWT parse boundary: golang-jwt parses a token only from a Go string, so
//     a bearer or ID token being validated is copied into one for the parse.

// sealedFormField is one application/x-www-form-urlencoded parameter whose
// value is a credential held in an enclave. The enclave is borrowed: building
// a body from it never destroys it.
type sealedFormField struct {
	name  string
	value *enclave.MemoryEnclave
}

// withFormBody assembles public and sealed into a form body inside a locked
// scratch enclave and calls fn with it.
//
// The public parameters are encoded first, then every sealed value is
// form-escaped out of its enclave directly into the scratch pages, so no step
// produces a heap string holding a credential — which the url.Values path would
// do twice, once in the map and once in Encode's output. The scratch enclave is
// destroyed when fn returns; fn must not retain body.
//
// A nil or destroyed sealed value fails with ErrCredentialUnavailable before
// anything is sent. Failing to lock the scratch pages propagates
// enclave.ErrLockedMemoryUnavailable: there is no fallback to ordinary memory.
func withFormBody(public url.Values, sealed []sealedFormField, fn func(body []byte) error) error {
	prefix := public.Encode()

	size := len(prefix)
	for _, field := range sealed {
		var escaped int
		if err := field.value.WithBytes(func(v []byte) error {
			escaped = formEscapedLen(v)
			return nil
		}); err != nil {
			return errors.Join(ErrCredentialUnavailable, err)
		}
		if size > 0 {
			size++ // '&'
		}
		size += len(url.QueryEscape(field.name)) + 1 + escaped
	}

	scratch, err := enclave.NewMemoryEnclaveSized(size)
	if err != nil {
		return err
	}

	err = scratch.WithBytes(func(body []byte) error {
		n := copy(body, prefix)
		for _, field := range sealed {
			if n > 0 {
				body[n] = '&'
				n++
			}
			n += copy(body[n:], url.QueryEscape(field.name))
			body[n] = '='
			n++

			if err := field.value.WithBytes(func(v []byte) error {
				if formEscapedLen(v) > len(body)-n {
					return ErrCredentialChanged
				}
				n += formEscapeInto(body[n:], v)
				return nil
			}); err != nil {
				if errors.Is(err, ErrCredentialChanged) {
					return err
				}
				return errors.Join(ErrCredentialUnavailable, err)
			}
		}
		if n != len(body) {
			return ErrCredentialChanged
		}
		return fn(body)
	})
	return credential.DestroyAll(err, scratch)
}

// formUnreserved reports the bytes application/x-www-form-urlencoded leaves
// untouched, exactly as url.QueryEscape does.
func formUnreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '-' || c == '_' || c == '.' || c == '~'
}

// formEscapedLen returns the length of src once form-escaped.
func formEscapedLen(src []byte) int {
	n := 0
	for _, c := range src {
		if formUnreserved(c) || c == ' ' {
			n++
		} else {
			n += 3
		}
	}
	return n
}

// formEscapeInto form-escapes src into dst, which must hold formEscapedLen(src)
// bytes, and returns the number written. It is url.QueryEscape without the
// heap string, so a credential can be escaped from one locked buffer into
// another.
func formEscapeInto(dst, src []byte) int {
	const hex = "0123456789ABCDEF"
	n := 0
	for _, c := range src {
		switch {
		case formUnreserved(c):
			dst[n] = c
			n++
		case c == ' ':
			dst[n] = '+'
			n++
		default:
			dst[n] = '%'
			dst[n+1] = hex[c>>4]
			dst[n+2] = hex[c&0x0f]
			n += 3
		}
	}
	return n
}

// jsonSimpleEscapes maps the single-character JSON escapes to the byte they
// stand for.
var jsonSimpleEscapes = map[byte]byte{
	'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t',
}

// unquoteJSONString decodes the JSON string literal raw, quotes included.
//
// With a nil dst it only counts, returning the decoded length; with a dst of
// that length it writes the decoded bytes. Two passes let a token response be
// decoded straight into an enclave sized for it, so the token never exists as
// a Go string — encoding/json would have to build one to decode it. Lone
// surrogates decode to U+FFFD, as encoding/json does.
func unquoteJSONString(raw, dst []byte) (int, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, ErrMalformedTokenResponse
	}
	s := raw[1 : len(raw)-1]

	n := 0
	emit := func(b byte) {
		if dst != nil {
			dst[n] = b
		}
		n++
	}
	emitRune := func(r rune) {
		var buf [utf8.UTFMax]byte
		for _, b := range buf[:utf8.EncodeRune(buf[:], r)] {
			emit(b)
		}
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			emit(c)
			continue
		}
		if i+1 >= len(s) {
			return 0, ErrMalformedTokenResponse
		}
		i++
		if b, ok := jsonSimpleEscapes[s[i]]; ok {
			emit(b)
			continue
		}
		if s[i] != 'u' {
			return 0, ErrMalformedTokenResponse
		}
		r, ok := hex4(s[i+1:])
		if !ok {
			return 0, ErrMalformedTokenResponse
		}
		i += 4
		if utf16.IsSurrogate(r) {
			// A high surrogate pairs with an immediately following \uXXXX low
			// surrogate; anything else is a lone surrogate.
			if len(s) > i+6 && s[i+1] == '\\' && s[i+2] == 'u' {
				if r2, ok := hex4(s[i+3:]); ok {
					if dec := utf16.DecodeRune(r, r2); dec != utf8.RuneError {
						emitRune(dec)
						i += 6
						continue
					}
				}
			}
			r = utf8.RuneError
		}
		emitRune(r)
	}
	return n, nil
}

// hex4 parses the four hex digits at the start of s.
func hex4(s []byte) (rune, bool) {
	if len(s) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range s[:4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r |= rune(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return r, true
}

// sealJSONString decodes the JSON string literal raw directly into locked
// pages. An absent, null or empty value yields a nil enclave and no error: an
// enclave cannot be empty, and an empty token is no token.
func sealJSONString(raw json.RawMessage) (*enclave.MemoryEnclave, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	size, err := unquoteJSONString(raw, nil)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}

	sealed, err := enclave.NewMemoryEnclaveSized(size)
	if err != nil {
		return nil, err
	}
	if err := sealed.WithBytes(func(dst []byte) error {
		_, err := unquoteJSONString(raw, dst)
		return err
	}); err != nil {
		return nil, credential.DestroyAll(err, sealed)
	}
	if err := sealed.Freeze(); err != nil {
		return nil, credential.DestroyAll(err, sealed)
	}
	return sealed, nil
}

// tokenFingerprint returns the cache key for a token: the unpadded base64url
// SHA-256 of its bytes, taken inside the enclave. A fingerprint is not a
// credential — it cannot be presented in place of the token — so it can key an
// ordinary map.
func tokenFingerprint(token *enclave.MemoryEnclave) (string, error) {
	var sum [sha256.Size]byte
	if err := token.WithBytes(func(b []byte) error {
		sum = sha256.Sum256(b)
		return nil
	}); err != nil {
		return "", errors.Join(ErrMissingToken, err)
	}
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// allocFunc moves data into a new enclave, taking ownership of it and wiping
// it on every path, as enclave.NewMemoryEnclave and enclave.Allocator.New do.
// The caches take one so a locked-memory budget can be imposed on them.
type allocFunc func(data []byte) (*enclave.MemoryEnclave, error)

// sealJSON encodes v into a new enclave from alloc. The allocator takes
// ownership of the encoded bytes and wipes them, so the only plaintext left
// behind is whatever encoding/json's own pooled buffer retained.
func sealJSON(alloc allocFunc, v any) (*enclave.MemoryEnclave, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return alloc(data)
}

// openJSON decodes the JSON held in e into v without copying it out first.
func openJSON(e *enclave.MemoryEnclave, v any) error {
	return e.WithBytes(func(b []byte) error {
		return json.Unmarshal(b, v)
	})
}
