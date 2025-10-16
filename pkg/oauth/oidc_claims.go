package oauth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IDTokenClaims represents the standard OpenID Connect ID token claims.
type IDTokenClaims struct {
	// Standard JWT claims
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`

	// OIDC-specific claims
	AuthTime int64  `json:"auth_time,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	ACR      string `json:"acr,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	AZP      string `json:"azp,omitempty"`

	// Hash claims for validation
	AtHash string `json:"at_hash,omitempty"`
	CHash  string `json:"c_hash,omitempty"`

	// Profile claims
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Profile           string `json:"profile,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Website           string `json:"website,omitempty"`
	Gender            string `json:"gender,omitempty"`
	Birthdate         string `json:"birthdate,omitempty"`
	Zoneinfo          string `json:"zoneinfo,omitempty"`
	Locale            string `json:"locale,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`

	// Email claims
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`

	// Phone claims
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`

	// Address claim (structured)
	Address *AddressClaim `json:"address,omitempty"`

	// Custom claims
	Custom map[string]interface{} `json:"-"`
}

// AddressClaim represents the structured address claim.
type AddressClaim struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

// UserInfo represents claims from the OIDC UserInfo endpoint.
type UserInfo struct {
	Subject           string         `json:"sub"`
	Name              string         `json:"name,omitempty"`
	GivenName         string         `json:"given_name,omitempty"`
	FamilyName        string         `json:"family_name,omitempty"`
	MiddleName        string         `json:"middle_name,omitempty"`
	Nickname          string         `json:"nickname,omitempty"`
	PreferredUsername string         `json:"preferred_username,omitempty"`
	Profile           string         `json:"profile,omitempty"`
	Picture           string         `json:"picture,omitempty"`
	Website           string         `json:"website,omitempty"`
	Email             string         `json:"email,omitempty"`
	EmailVerified     bool           `json:"email_verified,omitempty"`
	Gender            string         `json:"gender,omitempty"`
	Birthdate         string         `json:"birthdate,omitempty"`
	Zoneinfo          string         `json:"zoneinfo,omitempty"`
	Locale            string         `json:"locale,omitempty"`
	PhoneNumber       string         `json:"phone_number,omitempty"`
	PhoneNumberVerified bool         `json:"phone_number_verified,omitempty"`
	Address           *AddressClaim  `json:"address,omitempty"`
	UpdatedAt         int64          `json:"updated_at,omitempty"`
	Custom            map[string]interface{} `json:"-"`
}

// IdentityClaims represents the merged identity information from ID token and UserInfo.
type IdentityClaims struct {
	// Identity
	Subject           string
	PreferredUsername string

	// Profile
	Name       string
	GivenName  string
	FamilyName string
	MiddleName string
	Nickname   string
	Profile    string
	Picture    string
	Website    string
	Gender     string
	Birthdate  string
	Zoneinfo   string
	Locale     string
	UpdatedAt  time.Time

	// Email
	Email         string
	EmailVerified bool

	// Phone
	PhoneNumber         string
	PhoneNumberVerified bool

	// Address
	Address *AddressClaim

	// Authentication metadata
	AuthTime   time.Time
	ACR        string
	AMR        []string
	Issuer     string
	IssuedAt   time.Time
	ExpiresAt  time.Time

	// Custom claims from both ID token and UserInfo
	Custom map[string]interface{}
}

// parseIDTokenClaims extracts IDTokenClaims from a JWT token.
func parseIDTokenClaims(token *jwt.Token) (*IDTokenClaims, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims type", ErrOIDCInvalidIDToken)
	}

	idClaims := &IDTokenClaims{
		Custom: make(map[string]interface{}),
	}

	// Standard JWT claims
	if iss, ok := claims["iss"].(string); ok {
		idClaims.Issuer = iss
	}
	if sub, ok := claims["sub"].(string); ok {
		idClaims.Subject = sub
	}

	// Audience can be string or array
	if aud, ok := claims["aud"].(string); ok {
		idClaims.Audience = []string{aud}
	} else if audArr, ok := claims["aud"].([]interface{}); ok {
		for _, a := range audArr {
			if s, ok := a.(string); ok {
				idClaims.Audience = append(idClaims.Audience, s)
			}
		}
	}

	// Time claims
	if exp, ok := claims["exp"].(float64); ok {
		idClaims.ExpiresAt = int64(exp)
	}
	if iat, ok := claims["iat"].(float64); ok {
		idClaims.IssuedAt = int64(iat)
	}
	if nbf, ok := claims["nbf"].(float64); ok {
		idClaims.NotBefore = int64(nbf)
	}
	if authTime, ok := claims["auth_time"].(float64); ok {
		idClaims.AuthTime = int64(authTime)
	}
	if updatedAt, ok := claims["updated_at"].(float64); ok {
		idClaims.UpdatedAt = int64(updatedAt)
	}

	// OIDC-specific claims
	if nonce, ok := claims["nonce"].(string); ok {
		idClaims.Nonce = nonce
	}
	if acr, ok := claims["acr"].(string); ok {
		idClaims.ACR = acr
	}
	if azp, ok := claims["azp"].(string); ok {
		idClaims.AZP = azp
	}

	// AMR can be string or array
	if amr, ok := claims["amr"].(string); ok {
		idClaims.AMR = []string{amr}
	} else if amrArr, ok := claims["amr"].([]interface{}); ok {
		for _, a := range amrArr {
			if s, ok := a.(string); ok {
				idClaims.AMR = append(idClaims.AMR, s)
			}
		}
	}

	// Hash claims
	if atHash, ok := claims["at_hash"].(string); ok {
		idClaims.AtHash = atHash
	}
	if cHash, ok := claims["c_hash"].(string); ok {
		idClaims.CHash = cHash
	}

	// Profile claims
	extractStringClaim(claims, "name", &idClaims.Name)
	extractStringClaim(claims, "given_name", &idClaims.GivenName)
	extractStringClaim(claims, "family_name", &idClaims.FamilyName)
	extractStringClaim(claims, "middle_name", &idClaims.MiddleName)
	extractStringClaim(claims, "nickname", &idClaims.Nickname)
	extractStringClaim(claims, "preferred_username", &idClaims.PreferredUsername)
	extractStringClaim(claims, "profile", &idClaims.Profile)
	extractStringClaim(claims, "picture", &idClaims.Picture)
	extractStringClaim(claims, "website", &idClaims.Website)
	extractStringClaim(claims, "gender", &idClaims.Gender)
	extractStringClaim(claims, "birthdate", &idClaims.Birthdate)
	extractStringClaim(claims, "zoneinfo", &idClaims.Zoneinfo)
	extractStringClaim(claims, "locale", &idClaims.Locale)

	// Email claims
	extractStringClaim(claims, "email", &idClaims.Email)
	if emailVerified, ok := claims["email_verified"].(bool); ok {
		idClaims.EmailVerified = emailVerified
	}

	// Phone claims
	extractStringClaim(claims, "phone_number", &idClaims.PhoneNumber)
	if phoneVerified, ok := claims["phone_number_verified"].(bool); ok {
		idClaims.PhoneNumberVerified = phoneVerified
	}

	// Address claim
	if addrMap, ok := claims["address"].(map[string]interface{}); ok {
		addr := &AddressClaim{}
		extractStringClaim(addrMap, "formatted", &addr.Formatted)
		extractStringClaim(addrMap, "street_address", &addr.StreetAddress)
		extractStringClaim(addrMap, "locality", &addr.Locality)
		extractStringClaim(addrMap, "region", &addr.Region)
		extractStringClaim(addrMap, "postal_code", &addr.PostalCode)
		extractStringClaim(addrMap, "country", &addr.Country)
		idClaims.Address = addr
	}

	// Store custom claims
	standardClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nbf": true,
		"auth_time": true, "nonce": true, "acr": true, "amr": true, "azp": true,
		"at_hash": true, "c_hash": true,
		"name": true, "given_name": true, "family_name": true, "middle_name": true,
		"nickname": true, "preferred_username": true, "profile": true, "picture": true,
		"website": true, "gender": true, "birthdate": true, "zoneinfo": true, "locale": true,
		"updated_at": true, "email": true, "email_verified": true,
		"phone_number": true, "phone_number_verified": true, "address": true,
	}

	for key, value := range claims {
		if !standardClaims[key] {
			idClaims.Custom[key] = value
		}
	}

	return idClaims, nil
}

// MergeIdentityClaims creates IdentityClaims by merging ID token and UserInfo claims.
// UserInfo claims take precedence for profile data, but authentication metadata comes from ID token.
func MergeIdentityClaims(idToken *IDTokenClaims, userInfo *UserInfo) *IdentityClaims {
	ic := &IdentityClaims{
		Custom: make(map[string]interface{}),
	}

	// Identity from ID token (always required)
	if idToken != nil {
		ic.Subject = idToken.Subject
		ic.Issuer = idToken.Issuer
		ic.IssuedAt = time.Unix(idToken.IssuedAt, 0)
		ic.ExpiresAt = time.Unix(idToken.ExpiresAt, 0)

		if idToken.AuthTime > 0 {
			ic.AuthTime = time.Unix(idToken.AuthTime, 0)
		}
		ic.ACR = idToken.ACR
		ic.AMR = idToken.AMR

		// Copy ID token custom claims
		for k, v := range idToken.Custom {
			ic.Custom[k] = v
		}
	}

	// Merge profile data, preferring UserInfo
	if userInfo != nil {
		// Verify subject matches
		if idToken != nil && userInfo.Subject != "" && userInfo.Subject != idToken.Subject {
			// Subject mismatch - don't merge
			return ic
		}

		ic.Name = coalesce(userInfo.Name, idToken.Name)
		ic.GivenName = coalesce(userInfo.GivenName, idToken.GivenName)
		ic.FamilyName = coalesce(userInfo.FamilyName, idToken.FamilyName)
		ic.MiddleName = coalesce(userInfo.MiddleName, idToken.MiddleName)
		ic.Nickname = coalesce(userInfo.Nickname, idToken.Nickname)
		ic.PreferredUsername = coalesce(userInfo.PreferredUsername, idToken.PreferredUsername)
		ic.Profile = coalesce(userInfo.Profile, idToken.Profile)
		ic.Picture = coalesce(userInfo.Picture, idToken.Picture)
		ic.Website = coalesce(userInfo.Website, idToken.Website)
		ic.Gender = coalesce(userInfo.Gender, idToken.Gender)
		ic.Birthdate = coalesce(userInfo.Birthdate, idToken.Birthdate)
		ic.Zoneinfo = coalesce(userInfo.Zoneinfo, idToken.Zoneinfo)
		ic.Locale = coalesce(userInfo.Locale, idToken.Locale)

		ic.Email = coalesce(userInfo.Email, idToken.Email)
		ic.EmailVerified = userInfo.EmailVerified || idToken.EmailVerified

		ic.PhoneNumber = coalesce(userInfo.PhoneNumber, idToken.PhoneNumber)
		ic.PhoneNumberVerified = userInfo.PhoneNumberVerified || idToken.PhoneNumberVerified

		if userInfo.Address != nil {
			ic.Address = userInfo.Address
		} else if idToken != nil && idToken.Address != nil {
			ic.Address = idToken.Address
		}

		if userInfo.UpdatedAt > 0 {
			ic.UpdatedAt = time.Unix(userInfo.UpdatedAt, 0)
		} else if idToken != nil && idToken.UpdatedAt > 0 {
			ic.UpdatedAt = time.Unix(idToken.UpdatedAt, 0)
		}

		// Merge UserInfo custom claims
		for k, v := range userInfo.Custom {
			ic.Custom[k] = v
		}
	} else if idToken != nil {
		// No UserInfo, use ID token data
		ic.Name = idToken.Name
		ic.GivenName = idToken.GivenName
		ic.FamilyName = idToken.FamilyName
		ic.MiddleName = idToken.MiddleName
		ic.Nickname = idToken.Nickname
		ic.PreferredUsername = idToken.PreferredUsername
		ic.Profile = idToken.Profile
		ic.Picture = idToken.Picture
		ic.Website = idToken.Website
		ic.Gender = idToken.Gender
		ic.Birthdate = idToken.Birthdate
		ic.Zoneinfo = idToken.Zoneinfo
		ic.Locale = idToken.Locale

		ic.Email = idToken.Email
		ic.EmailVerified = idToken.EmailVerified

		ic.PhoneNumber = idToken.PhoneNumber
		ic.PhoneNumberVerified = idToken.PhoneNumberVerified

		ic.Address = idToken.Address

		if idToken.UpdatedAt > 0 {
			ic.UpdatedAt = time.Unix(idToken.UpdatedAt, 0)
		}
	}

	return ic
}

// extractStringClaim is a helper to extract string claims from a map.
func extractStringClaim(claims map[string]interface{}, key string, dest *string) {
	if val, ok := claims[key].(string); ok {
		*dest = val
	}
}

// coalesce returns the first non-empty string.
func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
