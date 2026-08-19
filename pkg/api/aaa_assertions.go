// The RADIUS and TACACS+ interface assertions live here rather than in
// api.go because both backends are excluded from fips140only builds (their
// wire protocols mandate MD5 — see docs/fips.md). Keeping the assertions in a
// file that carries the same constraint lets pkg/api itself stay in the
// FIPS-140-only build with the rest of its backends intact.

//go:build !fips140only

package api

import (
	"github.com/jeremyhahn/go-auth/pkg/radius"
	"github.com/jeremyhahn/go-auth/pkg/tacacs"
)

// Ensure the AAA authenticators satisfy the passwordAuthenticator interface.
var (
	_ passwordAuthenticator = (*radius.Authenticator)(nil)
	_ passwordAuthenticator = (*tacacs.Authenticator)(nil)
)
