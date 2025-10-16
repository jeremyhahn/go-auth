package oauth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestToken_Valid(t *testing.T) {
	tests := []struct {
		name  string
		token *Token
		want  bool
	}{
		{
			name: "valid token",
			token: &Token{
				AccessToken: "test-token",
				Expiry:      time.Now().Add(1 * time.Hour),
			},
			want: true,
		},
		{
			name: "expired token",
			token: &Token{
				AccessToken: "test-token",
				Expiry:      time.Now().Add(-1 * time.Hour),
			},
			want: false,
		},
		{
			name: "token without expiry",
			token: &Token{
				AccessToken: "test-token",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.Valid(); got != tt.want {
				t.Errorf("Token.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToken_ExpiresIn(t *testing.T) {
	tests := []struct {
		name  string
		token *Token
		want  bool
	}{
		{
			name: "expires in future",
			token: &Token{
				Expiry: time.Now().Add(5 * time.Minute),
			},
			want: true,
		},
		{
			name: "already expired",
			token: &Token{
				Expiry: time.Now().Add(-1 * time.Minute),
			},
			want: false,
		},
		{
			name:  "no expiry",
			token: &Token{},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			duration := tt.token.ExpiresIn()
			hasTime := duration > 0
			if hasTime != tt.want {
				t.Errorf("Token.ExpiresIn() returned %v, expected positive duration: %v", duration, tt.want)
			}
		})
	}
}

func TestTokenClaims_Valid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name   string
		claims *TokenClaims
		want   bool
	}{
		{
			name: "valid claims",
			claims: &TokenClaims{
				Subject:   "user123",
				ExpiresAt: now.Add(1 * time.Hour),
			},
			want: true,
		},
		{
			name: "expired claims",
			claims: &TokenClaims{
				Subject:   "user123",
				ExpiresAt: now.Add(-1 * time.Hour),
			},
			want: false,
		},
		{
			name: "not yet valid",
			claims: &TokenClaims{
				Subject:   "user123",
				NotBefore: now.Add(1 * time.Hour),
			},
			want: false,
		},
		{
			name: "claims without time restrictions",
			claims: &TokenClaims{
				Subject: "user123",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.claims.Valid(); got != tt.want {
				t.Errorf("TokenClaims.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenClaims_ValidWithClockSkew(t *testing.T) {
	now := time.Now()
	skew := 1 * time.Minute

	tests := []struct {
		name   string
		claims *TokenClaims
		want   bool
	}{
		{
			name: "valid with skew",
			claims: &TokenClaims{
				Subject:   "user123",
				ExpiresAt: now.Add(-30 * time.Second),
			},
			want: true,
		},
		{
			name: "expired even with skew",
			claims: &TokenClaims{
				Subject:   "user123",
				ExpiresAt: now.Add(-2 * time.Minute),
			},
			want: false,
		},
		{
			name: "not before with skew",
			claims: &TokenClaims{
				Subject:   "user123",
				NotBefore: now.Add(30 * time.Second),
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.claims.ValidWithClockSkew(skew); got != tt.want {
				t.Errorf("TokenClaims.ValidWithClockSkew() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSplitScopes(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		want  int
	}{
		{
			name:  "multiple scopes",
			scope: "openid profile email",
			want:  3,
		},
		{
			name:  "single scope",
			scope: "openid",
			want:  1,
		},
		{
			name:  "empty scope",
			scope: "",
			want:  0,
		},
		{
			name:  "scopes with extra spaces",
			scope: "openid  profile   email",
			want:  3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitScopes(tt.scope)
			if len(got) != tt.want {
				t.Errorf("splitScopes() returned %d scopes, want %d", len(got), tt.want)
			}
		})
	}
}

func TestClaimsFromJWT_ValidToken(t *testing.T) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "user123",
		"iss":   "https://issuer.example.com",
		"aud":   "test-client",
		"exp":   float64(now.Add(1 * time.Hour).Unix()),
		"iat":   float64(now.Unix()),
		"nbf":   float64(now.Unix()),
		"email": "test@example.com",
		"name":  "Test User",
		"scope": "openid profile email",
	}

	token := &jwt.Token{
		Claims: claims,
	}

	tc, err := claimsFromJWT(token)
	if err != nil {
		t.Fatalf("claimsFromJWT() failed: %v", err)
	}

	if tc.Subject != "user123" {
		t.Errorf("Expected subject 'user123', got '%s'", tc.Subject)
	}

	if tc.Issuer != "https://issuer.example.com" {
		t.Errorf("Expected issuer 'https://issuer.example.com', got '%s'", tc.Issuer)
	}

	if len(tc.Audience) != 1 || tc.Audience[0] != "test-client" {
		t.Errorf("Expected audience ['test-client'], got %v", tc.Audience)
	}

	if tc.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", tc.Email)
	}

	if tc.Name != "Test User" {
		t.Errorf("Expected name 'Test User', got '%s'", tc.Name)
	}

	if len(tc.Scopes) != 3 {
		t.Errorf("Expected 3 scopes, got %d", len(tc.Scopes))
	}
}

func TestClaimsFromJWT_ExpiredToken(t *testing.T) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user123",
		"exp": float64(now.Add(-1 * time.Hour).Unix()),
		"iat": float64(now.Add(-2 * time.Hour).Unix()),
	}

	token := &jwt.Token{
		Claims: claims,
	}

	tc, err := claimsFromJWT(token)
	if err != nil {
		t.Fatalf("claimsFromJWT() failed: %v", err)
	}

	// claimsFromJWT doesn't validate expiry, it just extracts claims
	if tc.Subject != "user123" {
		t.Errorf("Expected subject 'user123', got '%s'", tc.Subject)
	}

	if !tc.ExpiresAt.Before(now) {
		t.Error("Expected token to be expired")
	}
}

func TestClaimsFromJWT_MalformedToken(t *testing.T) {
	// Not a MapClaims
	token := &jwt.Token{
		Claims: jwt.RegisteredClaims{
			Subject: "user123",
		},
	}

	_, err := claimsFromJWT(token)
	if err == nil {
		t.Error("Expected error for non-MapClaims token")
	}

	if !containsError(err, ErrInvalidClaims) {
		t.Errorf("Expected ErrInvalidClaims, got %v", err)
	}
}

func TestClaimsFromJWT_AudienceString(t *testing.T) {
	claims := jwt.MapClaims{
		"sub": "user123",
		"aud": "single-audience",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	token := &jwt.Token{
		Claims: claims,
	}

	tc, err := claimsFromJWT(token)
	if err != nil {
		t.Fatalf("claimsFromJWT() failed: %v", err)
	}

	if len(tc.Audience) != 1 || tc.Audience[0] != "single-audience" {
		t.Errorf("Expected audience ['single-audience'], got %v", tc.Audience)
	}
}

func TestClaimsFromJWT_AudienceArray(t *testing.T) {
	claims := jwt.MapClaims{
		"sub": "user123",
		"aud": []interface{}{"audience1", "audience2", "audience3"},
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	token := &jwt.Token{
		Claims: claims,
	}

	tc, err := claimsFromJWT(token)
	if err != nil {
		t.Fatalf("claimsFromJWT() failed: %v", err)
	}

	if len(tc.Audience) != 3 {
		t.Errorf("Expected 3 audiences, got %d", len(tc.Audience))
	}

	expectedAudiences := []string{"audience1", "audience2", "audience3"}
	for i, expected := range expectedAudiences {
		if i >= len(tc.Audience) || tc.Audience[i] != expected {
			t.Errorf("Expected audience[%d] = '%s', got '%s'", i, expected, tc.Audience[i])
		}
	}
}

func TestClaimsFromJWT_ScopeVariations(t *testing.T) {
	tests := []struct {
		name          string
		claims        jwt.MapClaims
		expectedCount int
	}{
		{
			name: "scope as string",
			claims: jwt.MapClaims{
				"sub":   "user123",
				"scope": "openid profile email",
			},
			expectedCount: 3,
		},
		{
			name: "scopes as array",
			claims: jwt.MapClaims{
				"sub":    "user123",
				"scopes": []interface{}{"openid", "profile", "email"},
			},
			expectedCount: 3,
		},
		{
			name: "scp as array (Azure AD)",
			claims: jwt.MapClaims{
				"sub": "user123",
				"scp": []interface{}{"api.read", "api.write"},
			},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &jwt.Token{
				Claims: tt.claims,
			}

			tc, err := claimsFromJWT(token)
			if err != nil {
				t.Fatalf("claimsFromJWT() failed: %v", err)
			}

			if len(tc.Scopes) != tt.expectedCount {
				t.Errorf("Expected %d scopes, got %d", tt.expectedCount, len(tc.Scopes))
			}
		})
	}
}

func TestClaimsFromJWT_CustomClaims(t *testing.T) {
	claims := jwt.MapClaims{
		"sub":           "user123",
		"custom_field1": "value1",
		"custom_field2": 42,
		"custom_field3": true,
		"groups":        []interface{}{"admin", "users"},
	}

	token := &jwt.Token{
		Claims: claims,
	}

	tc, err := claimsFromJWT(token)
	if err != nil {
		t.Fatalf("claimsFromJWT() failed: %v", err)
	}

	if tc.Custom["custom_field1"] != "value1" {
		t.Errorf("Expected custom_field1 = 'value1', got %v", tc.Custom["custom_field1"])
	}

	// JWT MapClaims stores integers as int, not float64
	switch v := tc.Custom["custom_field2"].(type) {
	case int:
		if v != 42 {
			t.Errorf("Expected custom_field2 = 42, got %v", v)
		}
	case float64:
		if int(v) != 42 {
			t.Errorf("Expected custom_field2 = 42, got %v", v)
		}
	default:
		t.Errorf("Expected custom_field2 to be int or float64, got %T: %v", v, v)
	}

	if tc.Custom["custom_field3"] != true {
		t.Errorf("Expected custom_field3 = true, got %v", tc.Custom["custom_field3"])
	}

	// Groups should be extracted separately
	if len(tc.Groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(tc.Groups))
	}

	// Groups should not be in custom claims
	if _, exists := tc.Custom["groups"]; exists {
		t.Error("groups should not be in custom claims")
	}
}

func TestClaimsFromJWT_EmailVerified(t *testing.T) {
	tests := []struct {
		name     string
		claims   jwt.MapClaims
		expected bool
	}{
		{
			name: "email verified true",
			claims: jwt.MapClaims{
				"sub":            "user123",
				"email":          "test@example.com",
				"email_verified": true,
			},
			expected: true,
		},
		{
			name: "email verified false",
			claims: jwt.MapClaims{
				"sub":            "user123",
				"email":          "test@example.com",
				"email_verified": false,
			},
			expected: false,
		},
		{
			name: "email verified missing",
			claims: jwt.MapClaims{
				"sub":   "user123",
				"email": "test@example.com",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &jwt.Token{
				Claims: tt.claims,
			}

			tc, err := claimsFromJWT(token)
			if err != nil {
				t.Fatalf("claimsFromJWT() failed: %v", err)
			}

			if tc.EmailVerified != tt.expected {
				t.Errorf("Expected email_verified = %v, got %v", tt.expected, tc.EmailVerified)
			}
		})
	}
}

func TestClaimsFromJWT_AllTimeClaims(t *testing.T) {
	now := time.Now()
	exp := now.Add(1 * time.Hour)
	iat := now
	nbf := now.Add(-1 * time.Minute)

	claims := jwt.MapClaims{
		"sub": "user123",
		"exp": float64(exp.Unix()),
		"iat": float64(iat.Unix()),
		"nbf": float64(nbf.Unix()),
	}

	token := &jwt.Token{
		Claims: claims,
	}

	tc, err := claimsFromJWT(token)
	if err != nil {
		t.Fatalf("claimsFromJWT() failed: %v", err)
	}

	if tc.ExpiresAt.Unix() != exp.Unix() {
		t.Errorf("Expected ExpiresAt = %v, got %v", exp.Unix(), tc.ExpiresAt.Unix())
	}

	if tc.IssuedAt.Unix() != iat.Unix() {
		t.Errorf("Expected IssuedAt = %v, got %v", iat.Unix(), tc.IssuedAt.Unix())
	}

	if tc.NotBefore.Unix() != nbf.Unix() {
		t.Errorf("Expected NotBefore = %v, got %v", nbf.Unix(), tc.NotBefore.Unix())
	}
}

func TestClaimsFromJWT_EmptyClaims(t *testing.T) {
	claims := jwt.MapClaims{}

	token := &jwt.Token{
		Claims: claims,
	}

	tc, err := claimsFromJWT(token)
	if err != nil {
		t.Fatalf("claimsFromJWT() failed: %v", err)
	}

	if tc.Subject != "" {
		t.Errorf("Expected empty subject, got '%s'", tc.Subject)
	}

	if len(tc.Audience) != 0 {
		t.Errorf("Expected empty audience, got %v", tc.Audience)
	}

	if tc.Custom == nil {
		t.Error("Expected non-nil Custom map")
	}
}
