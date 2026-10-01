package oauth

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// These tests pin at_hash validation (OIDC Core §3.1.3.6) and the ID-token
// algorithm allowlist (Local Codex review, round 3, of #47). Every path that
// cannot check at_hash has to reject the token, never skip the check.

// atHashOf computes the at_hash for accessToken with h: the left half of the
// digest, base64url-encoded without padding.
func atHashOf(h func() hash.Hash, accessToken string) string {
	d := h()
	d.Write([]byte(accessToken))
	sum := d.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// atHashValidator returns an OIDC validator with at_hash validation on for
// client "client", and claims that pass every other check.
func atHashValidator(atHash string) (*oidcValidator, *IDTokenClaims) {
	v := &oidcValidator{config: &Config{
		ClientID: "client",
		OIDC:     &OIDCConfig{Enabled: true, ValidateAtHash: true},
	}}
	return v, &IDTokenClaims{Issuer: "https://issuer.example", Audience: []string{"client"}, AtHash: atHash}
}

func TestAtHashIsCheckedWithTheTokensAlgorithm(t *testing.T) {
	const access = "access-token-value"

	cases := []struct {
		alg  string
		hash func() hash.Hash
	}{
		{"RS256", sha256.New}, {"ES256", sha256.New}, {"PS256", sha256.New},
		{"RS384", sha512.New384}, {"ES384", sha512.New384}, {"PS384", sha512.New384},
		{"RS512", sha512.New}, {"ES512", sha512.New}, {"PS512", sha512.New},
		{"EdDSA", sha512.New},
	}

	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			v, claims := atHashValidator(atHashOf(tc.hash, access))
			if err := v.validateOIDCClaims(claims, "", sealedForTest(t, access), tc.alg, nil); err != nil {
				t.Errorf("a correct %s at_hash was rejected: %v", tc.alg, err)
			}

			// The same at_hash under a different access token must fail.
			if err := v.validateOIDCClaims(claims, "", sealedForTest(t, "substituted"), tc.alg, nil); !errors.Is(err, ErrOIDCInvalidAtHash) {
				t.Errorf("a substituted access token under %s = %v, want ErrOIDCInvalidAtHash", tc.alg, err)
			}
		})
	}

	// A SHA-256 at_hash on an RS384 token is wrong, not "close enough".
	v, claims := atHashValidator(atHashOf(sha256.New, access))
	if err := v.validateOIDCClaims(claims, "", sealedForTest(t, access), "RS384", nil); !errors.Is(err, ErrOIDCInvalidAtHash) {
		t.Errorf("a SHA-256 at_hash on an RS384 token = %v, want ErrOIDCInvalidAtHash", err)
	}
}

func TestAtHashRejectsAnAlgorithmItCannotHash(t *testing.T) {
	const access = "access-token-value"
	v, claims := atHashValidator(atHashOf(sha256.New, access))

	for _, alg := range []string{"", "none", "HS256", "XS999"} {
		err := v.validateOIDCClaims(claims, "", sealedForTest(t, access), alg, nil)
		if !errors.Is(err, ErrOIDCInvalidAtHash) || !errors.Is(err, ErrOIDCUnsupportedAtHashAlgorithm) {
			t.Errorf("at_hash under alg %q = %v, want ErrOIDCInvalidAtHash and ErrOIDCUnsupportedAtHashAlgorithm", alg, err)
		}
	}
}

func TestValidateAtHashFailsClosedWithoutAHashFunction(t *testing.T) {
	v := &oidcValidator{}
	err := v.validateAtHash("anything", sealedForTest(t, "access-token"), nil)
	if !errors.Is(err, ErrOIDCInvalidAtHash) || !errors.Is(err, ErrOIDCUnsupportedAtHashAlgorithm) {
		t.Errorf("validateAtHash() with no hash function = %v, want ErrOIDCInvalidAtHash and ErrOIDCUnsupportedAtHashAlgorithm", err)
	}
}

func TestAtHashRejectsADestroyedAccessToken(t *testing.T) {
	const access = "access-token-value"
	v, claims := atHashValidator(atHashOf(sha256.New, access))

	destroyed := sealedForTest(t, access)
	destroyed.Destroy()

	// Supplied but destroyed is not "not supplied": the check cannot run, so
	// the token is rejected.
	if err := v.validateOIDCClaims(claims, "", destroyed, "RS256", nil); !errors.Is(err, ErrOIDCInvalidAtHash) {
		t.Errorf("at_hash with a destroyed access token = %v, want ErrOIDCInvalidAtHash", err)
	}

	// Only nil means the caller supplied no access token.
	if err := v.validateOIDCClaims(claims, "", nil, "RS256", nil); err != nil {
		t.Errorf("at_hash with no access token supplied = %v, want nil", err)
	}
}

// TestIDTokenParseRefusesSymmetricAndUnsignedAlgorithms is the alg-confusion
// guard: even with a key function that would verify them, an HMAC-signed or
// unsigned ID token is refused by the algorithm allowlist.
func TestIDTokenParseRefusesSymmetricAndUnsignedAlgorithms(t *testing.T) {
	secret := []byte("shared-secret-an-attacker-might-know")
	claims := jwt.MapClaims{"iss": "https://issuer.example", "sub": "user", "aud": "client"}

	hs256, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("signing HS256: %v", err)
	}
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("signing none: %v", err)
	}

	permissive := func(token *jwt.Token) (interface{}, error) {
		if token.Method == jwt.SigningMethodNone {
			return jwt.UnsafeAllowNoneSignatureType, nil
		}
		return secret, nil
	}

	for name, token := range map[string]string{"HS256": hs256, "none": unsigned} {
		if _, err := parseVerifiedIDToken(token, permissive); err == nil {
			t.Errorf("an ID token signed with %s was accepted", name)
		}
	}
}
