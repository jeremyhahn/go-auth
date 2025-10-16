package oauth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseIDTokenClaims(t *testing.T) {
	t.Run("parses standard claims", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "https://example.com",
			"sub": "user123",
			"aud": "client-id",
			"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat": float64(time.Now().Unix()),
		}

		token := &jwt.Token{
			Claims: claims,
		}

		idClaims, err := parseIDTokenClaims(token)
		if err != nil {
			t.Fatalf("parseIDTokenClaims() error = %v", err)
		}

		if idClaims.Issuer != "https://example.com" {
			t.Errorf("Issuer = %s, want https://example.com", idClaims.Issuer)
		}
		if idClaims.Subject != "user123" {
			t.Errorf("Subject = %s, want user123", idClaims.Subject)
		}
		if len(idClaims.Audience) != 1 || idClaims.Audience[0] != "client-id" {
			t.Errorf("Audience = %v, want [client-id]", idClaims.Audience)
		}
	})

	t.Run("parses audience as array", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "https://example.com",
			"sub": "user123",
			"aud": []interface{}{"client-id-1", "client-id-2"},
			"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat": float64(time.Now().Unix()),
		}

		token := &jwt.Token{Claims: claims}
		idClaims, err := parseIDTokenClaims(token)
		if err != nil {
			t.Fatalf("parseIDTokenClaims() error = %v", err)
		}

		if len(idClaims.Audience) != 2 {
			t.Errorf("Audience length = %d, want 2", len(idClaims.Audience))
		}
	})

	t.Run("parses OIDC-specific claims", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss":       "https://example.com",
			"sub":       "user123",
			"aud":       "client-id",
			"exp":       float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":       float64(time.Now().Unix()),
			"nonce":     "test-nonce",
			"acr":       "urn:mace:incommon:iap:silver",
			"amr":       []interface{}{"password", "otp"},
			"azp":       "client-id",
			"at_hash":   "test-hash",
			"c_hash":    "code-hash",
			"auth_time": float64(time.Now().Unix()),
		}

		token := &jwt.Token{Claims: claims}
		idClaims, err := parseIDTokenClaims(token)
		if err != nil {
			t.Fatalf("parseIDTokenClaims() error = %v", err)
		}

		if idClaims.Nonce != "test-nonce" {
			t.Errorf("Nonce = %s, want test-nonce", idClaims.Nonce)
		}
		if idClaims.ACR != "urn:mace:incommon:iap:silver" {
			t.Errorf("ACR = %s, want urn:mace:incommon:iap:silver", idClaims.ACR)
		}
		if len(idClaims.AMR) != 2 {
			t.Errorf("AMR length = %d, want 2", len(idClaims.AMR))
		}
		if idClaims.AZP != "client-id" {
			t.Errorf("AZP = %s, want client-id", idClaims.AZP)
		}
		if idClaims.AtHash != "test-hash" {
			t.Errorf("AtHash = %s, want test-hash", idClaims.AtHash)
		}
		if idClaims.CHash != "code-hash" {
			t.Errorf("CHash = %s, want code-hash", idClaims.CHash)
		}
		if idClaims.AuthTime == 0 {
			t.Error("AuthTime not parsed")
		}
	})

	t.Run("parses profile claims", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss":                "https://example.com",
			"sub":                "user123",
			"aud":                "client-id",
			"exp":                float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":                float64(time.Now().Unix()),
			"name":               "John Doe",
			"given_name":         "John",
			"family_name":        "Doe",
			"middle_name":        "A",
			"nickname":           "johnny",
			"preferred_username": "johndoe",
			"profile":            "https://example.com/johndoe",
			"picture":            "https://example.com/picture.jpg",
			"website":            "https://johndoe.com",
			"gender":             "male",
			"birthdate":          "1990-01-01",
			"zoneinfo":           "America/New_York",
			"locale":             "en-US",
		}

		token := &jwt.Token{Claims: claims}
		idClaims, err := parseIDTokenClaims(token)
		if err != nil {
			t.Fatalf("parseIDTokenClaims() error = %v", err)
		}

		if idClaims.Name != "John Doe" {
			t.Errorf("Name = %s, want John Doe", idClaims.Name)
		}
		if idClaims.GivenName != "John" {
			t.Errorf("GivenName = %s, want John", idClaims.GivenName)
		}
		if idClaims.FamilyName != "Doe" {
			t.Errorf("FamilyName = %s, want Doe", idClaims.FamilyName)
		}
		if idClaims.PreferredUsername != "johndoe" {
			t.Errorf("PreferredUsername = %s, want johndoe", idClaims.PreferredUsername)
		}
	})

	t.Run("parses email claims", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss":            "https://example.com",
			"sub":            "user123",
			"aud":            "client-id",
			"exp":            float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":            float64(time.Now().Unix()),
			"email":          "john@example.com",
			"email_verified": true,
		}

		token := &jwt.Token{Claims: claims}
		idClaims, err := parseIDTokenClaims(token)
		if err != nil {
			t.Fatalf("parseIDTokenClaims() error = %v", err)
		}

		if idClaims.Email != "john@example.com" {
			t.Errorf("Email = %s, want john@example.com", idClaims.Email)
		}
		if !idClaims.EmailVerified {
			t.Error("EmailVerified = false, want true")
		}
	})

	t.Run("parses phone claims", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss":                    "https://example.com",
			"sub":                    "user123",
			"aud":                    "client-id",
			"exp":                    float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":                    float64(time.Now().Unix()),
			"phone_number":           "+1234567890",
			"phone_number_verified":  true,
		}

		token := &jwt.Token{Claims: claims}
		idClaims, err := parseIDTokenClaims(token)
		if err != nil {
			t.Fatalf("parseIDTokenClaims() error = %v", err)
		}

		if idClaims.PhoneNumber != "+1234567890" {
			t.Errorf("PhoneNumber = %s, want +1234567890", idClaims.PhoneNumber)
		}
		if !idClaims.PhoneNumberVerified {
			t.Error("PhoneNumberVerified = false, want true")
		}
	})

	t.Run("parses address claim", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "https://example.com",
			"sub": "user123",
			"aud": "client-id",
			"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat": float64(time.Now().Unix()),
			"address": map[string]interface{}{
				"formatted":      "123 Main St, City, State 12345",
				"street_address": "123 Main St",
				"locality":       "City",
				"region":         "State",
				"postal_code":    "12345",
				"country":        "US",
			},
		}

		token := &jwt.Token{Claims: claims}
		idClaims, err := parseIDTokenClaims(token)
		if err != nil {
			t.Fatalf("parseIDTokenClaims() error = %v", err)
		}

		if idClaims.Address == nil {
			t.Fatal("Address is nil")
		}
		if idClaims.Address.Formatted != "123 Main St, City, State 12345" {
			t.Errorf("Address.Formatted = %s", idClaims.Address.Formatted)
		}
		if idClaims.Address.PostalCode != "12345" {
			t.Errorf("Address.PostalCode = %s, want 12345", idClaims.Address.PostalCode)
		}
	})

	t.Run("stores custom claims", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss":       "https://example.com",
			"sub":       "user123",
			"aud":       "client-id",
			"exp":       float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":       float64(time.Now().Unix()),
			"custom1":   "value1",
			"custom2":   123,
			"custom3":   true,
		}

		token := &jwt.Token{Claims: claims}
		idClaims, err := parseIDTokenClaims(token)
		if err != nil {
			t.Fatalf("parseIDTokenClaims() error = %v", err)
		}

		if len(idClaims.Custom) != 3 {
			t.Errorf("Custom claims length = %d, want 3", len(idClaims.Custom))
		}
		if idClaims.Custom["custom1"] != "value1" {
			t.Errorf("Custom[custom1] = %v, want value1", idClaims.Custom["custom1"])
		}
	})

	t.Run("handles invalid claims type", func(t *testing.T) {
		token := &jwt.Token{
			Claims: jwt.RegisteredClaims{},
		}

		_, err := parseIDTokenClaims(token)
		if err == nil {
			t.Error("parseIDTokenClaims() should error on invalid claims type")
		}
	})
}

func TestMergeIdentityClaims(t *testing.T) {
	now := time.Now()
	idToken := &IDTokenClaims{
		Issuer:    "https://example.com",
		Subject:   "user123",
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
		IssuedAt:  now.Unix(),
		AuthTime:  now.Unix(),
		Name:      "ID Token Name",
		Email:     "idtoken@example.com",
	}

	t.Run("merges ID token only", func(t *testing.T) {
		ic := MergeIdentityClaims(idToken, nil)

		if ic.Subject != "user123" {
			t.Errorf("Subject = %s, want user123", ic.Subject)
		}
		if ic.Issuer != "https://example.com" {
			t.Errorf("Issuer = %s, want https://example.com", ic.Issuer)
		}
		if ic.Name != "ID Token Name" {
			t.Errorf("Name = %s, want ID Token Name", ic.Name)
		}
		if ic.Email != "idtoken@example.com" {
			t.Errorf("Email = %s, want idtoken@example.com", ic.Email)
		}
	})

	t.Run("prefers UserInfo for profile data", func(t *testing.T) {
		userInfo := &UserInfo{
			Subject: "user123",
			Name:    "UserInfo Name",
			Email:   "userinfo@example.com",
		}

		ic := MergeIdentityClaims(idToken, userInfo)

		if ic.Name != "UserInfo Name" {
			t.Errorf("Name = %s, want UserInfo Name (should prefer UserInfo)", ic.Name)
		}
		if ic.Email != "userinfo@example.com" {
			t.Errorf("Email = %s, want userinfo@example.com (should prefer UserInfo)", ic.Email)
		}
		// Auth metadata still from ID token
		if ic.Issuer != "https://example.com" {
			t.Errorf("Issuer = %s, want https://example.com", ic.Issuer)
		}
	})

	t.Run("falls back to ID token when UserInfo empty", func(t *testing.T) {
		userInfo := &UserInfo{
			Subject: "user123",
		}

		ic := MergeIdentityClaims(idToken, userInfo)

		if ic.Name != "ID Token Name" {
			t.Errorf("Name = %s, want ID Token Name (fallback)", ic.Name)
		}
		if ic.Email != "idtoken@example.com" {
			t.Errorf("Email = %s, want idtoken@example.com (fallback)", ic.Email)
		}
	})

	t.Run("rejects subject mismatch", func(t *testing.T) {
		userInfo := &UserInfo{
			Subject: "different-user",
			Name:    "UserInfo Name",
		}

		ic := MergeIdentityClaims(idToken, userInfo)

		// Should not merge UserInfo data due to subject mismatch
		// With subject mismatch, function returns early without merging
		if ic.Subject != "user123" {
			t.Errorf("Subject = %s, want user123", ic.Subject)
		}
	})

	t.Run("merges custom claims", func(t *testing.T) {
		idToken := &IDTokenClaims{
			Issuer:    "https://example.com",
			Subject:   "user123",
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
			Custom: map[string]interface{}{
				"id_custom": "id_value",
			},
		}

		userInfo := &UserInfo{
			Subject: "user123",
			Custom: map[string]interface{}{
				"ui_custom": "ui_value",
			},
		}

		ic := MergeIdentityClaims(idToken, userInfo)

		if len(ic.Custom) != 2 {
			t.Errorf("Custom length = %d, want 2", len(ic.Custom))
		}
		if ic.Custom["id_custom"] != "id_value" {
			t.Error("ID token custom claim not merged")
		}
		if ic.Custom["ui_custom"] != "ui_value" {
			t.Error("UserInfo custom claim not merged")
		}
	})

	t.Run("merges address claim", func(t *testing.T) {
		idToken := &IDTokenClaims{
			Issuer:    "https://example.com",
			Subject:   "user123",
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
			Address: &AddressClaim{
				Country: "ID",
			},
		}

		userInfo := &UserInfo{
			Subject: "user123",
			Address: &AddressClaim{
				Country: "UI",
			},
		}

		ic := MergeIdentityClaims(idToken, userInfo)

		if ic.Address.Country != "UI" {
			t.Errorf("Address.Country = %s, want UI (prefer UserInfo)", ic.Address.Country)
		}
	})

	t.Run("handles verified flags", func(t *testing.T) {
		idToken := &IDTokenClaims{
			Issuer:        "https://example.com",
			Subject:       "user123",
			ExpiresAt:     now.Add(1 * time.Hour).Unix(),
			IssuedAt:      now.Unix(),
			EmailVerified: true,
		}

		userInfo := &UserInfo{
			Subject:             "user123",
			PhoneNumberVerified: true,
		}

		ic := MergeIdentityClaims(idToken, userInfo)

		if !ic.EmailVerified {
			t.Error("EmailVerified should be true from ID token")
		}
		if !ic.PhoneNumberVerified {
			t.Error("PhoneNumberVerified should be true from UserInfo")
		}
	})

	t.Run("converts time fields", func(t *testing.T) {
		authTime := now.Add(-1 * time.Hour).Unix()
		idToken := &IDTokenClaims{
			Issuer:    "https://example.com",
			Subject:   "user123",
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
			AuthTime:  authTime,
		}

		ic := MergeIdentityClaims(idToken, nil)

		if ic.AuthTime.Unix() != authTime {
			t.Errorf("AuthTime = %v, want %v", ic.AuthTime.Unix(), authTime)
		}
		if ic.IssuedAt.IsZero() {
			t.Error("IssuedAt should be set")
		}
		if ic.ExpiresAt.IsZero() {
			t.Error("ExpiresAt should be set")
		}
	})

}

func TestCoalesce(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{
			name:   "returns first non-empty",
			values: []string{"", "second", "third"},
			want:   "second",
		},
		{
			name:   "returns first value if non-empty",
			values: []string{"first", "second"},
			want:   "first",
		},
		{
			name:   "returns empty if all empty",
			values: []string{"", "", ""},
			want:   "",
		},
		{
			name:   "handles single value",
			values: []string{"only"},
			want:   "only",
		},
		{
			name:   "handles empty slice",
			values: []string{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := coalesce(tt.values...)
			if got != tt.want {
				t.Errorf("coalesce() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestExtractStringClaim(t *testing.T) {
	t.Run("extracts valid string claim", func(t *testing.T) {
		claims := map[string]interface{}{
			"key": "value",
		}
		var dest string

		extractStringClaim(claims, "key", &dest)

		if dest != "value" {
			t.Errorf("extractStringClaim() dest = %s, want value", dest)
		}
	})

	t.Run("ignores non-string claim", func(t *testing.T) {
		claims := map[string]interface{}{
			"key": 123,
		}
		var dest string

		extractStringClaim(claims, "key", &dest)

		if dest != "" {
			t.Errorf("extractStringClaim() dest = %s, want empty", dest)
		}
	})

	t.Run("ignores missing claim", func(t *testing.T) {
		claims := map[string]interface{}{}
		var dest string
		dest = "default"

		extractStringClaim(claims, "key", &dest)

		if dest != "default" {
			t.Errorf("extractStringClaim() dest = %s, want default", dest)
		}
	})
}
