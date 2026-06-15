package secret_detect

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// cloudflareAccessMetaToken is the verbatim JWT from the Cloudflare Access SSO
// login-page false positive: a pre-auth "meta" token (type=meta, auth_status=NONE,
// no identity) embedded in the /cdn-cgi/access/login/...?meta=<jwt> URL and
// reflected into the page body.
const cloudflareAccessMetaToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjMzZmZlMWNjMWZiYTUyMmMwZmNmMWQ0ODVkODMxZjU4ZWZiYTIyZGEyOTRmMTYzNWY2NWQ1YWU4ZDQ3ZWYwNjMifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImZkNjI4ZGUwN2Y4OGJiOTFlNjQ3MmVhMTI3NGI3ZjE3Nzg2MjQ0ZTc2ZjI3NzYzMGQwNTRhYjY3MWQ0N2NhNTUiLCJob3N0bmFtZSI6ImEucGFnZXMtcGVyZi5yb2NoZS5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc4MTM1NzI1MSwibmJmIjoxNzgxMzU2OTUxLCJpYXQiOjE3ODEzNTY5NTEsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJTRyIsImFwcF9zZXNzaW9uX2hhc2giOiI5N2JkM2RjYjJlNDk2MzY1OTM5OWQxMGViZmM3NjIyNDAwOTc2MmYyY2EyNzVhNWY3YjExMjMxMTEyOGY5Y2M1In0.azTVcieY9dZmh2mu0l9pCIDM8iyEN-lz9m8yqKcy8-Dhq40Ys6y7tMp5gVt477d4xXvuDL_kqt0UPERV-Sy5cOCiVby3rsY2fS-khHXR5ciC_DJSJFEnmU1iEEig6kC1qhlPjVU0tVzlqLiPjJb1Uxg9AZy6hXWcHwZ3DScohmsH83wy4XijOr68TpIWiCoJD7bAi06vD-_TOzwOF2JKNmBsdKpMBApaLZd1HPbxH34AlR7uUK_BgRckHDTe9Xm3eIO01CeBUP4C1xopGS6HeZ1XUg0HOEJy2sL9M-pxfLD_vdqOKVbG7wHYKhdjRDsCmSumBCU9wluLn0xzciAsIQ"

// makeJWT builds an unsigned-but-well-formed compact JWT from a header and
// payload (signature segment is a fixed placeholder — the classifier never
// verifies it).
func makeJWT(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	enc := func(v map[string]any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(header) + "." + enc(payload) + ".c2ln"
}

func TestClassifyJWTSnippet(t *testing.T) {
	rs256 := map[string]any{"alg": "RS256", "typ": "JWT"}

	tests := []struct {
		name          string
		snippet       string
		wantIsJWT     bool
		wantSensitive bool
	}{
		{
			name:          "cloudflare access meta token is a non-sensitive JWT",
			snippet:       cloudflareAccessMetaToken,
			wantIsJWT:     true,
			wantSensitive: false,
		},
		{
			name:          "auth_status NONE is non-sensitive",
			snippet:       makeJWT(t, rs256, map[string]any{"auth_status": "NONE", "aud": "app"}),
			wantIsJWT:     true,
			wantSensitive: false,
		},
		{
			name:          "type meta is non-sensitive",
			snippet:       makeJWT(t, rs256, map[string]any{"type": "meta", "hostname": "x.example.com"}),
			wantIsJWT:     true,
			wantSensitive: false,
		},
		{
			name:          "payload with only registered/no-identity claims is non-sensitive",
			snippet:       makeJWT(t, rs256, map[string]any{"iss": "cf", "exp": 1781357251, "iat": 1781356951}),
			wantIsJWT:     true,
			wantSensitive: false,
		},
		{
			name:          "token with sub identity is sensitive",
			snippet:       makeJWT(t, rs256, map[string]any{"sub": "user-42", "iss": "auth"}),
			wantIsJWT:     true,
			wantSensitive: true,
		},
		{
			name:          "token with email is sensitive",
			snippet:       makeJWT(t, rs256, map[string]any{"email": "alice@example.com"}),
			wantIsJWT:     true,
			wantSensitive: true,
		},
		{
			name:          "token with scope grant is sensitive",
			snippet:       makeJWT(t, rs256, map[string]any{"scope": "read write admin"}),
			wantIsJWT:     true,
			wantSensitive: true,
		},
		{
			name:          "token with roles array is sensitive",
			snippet:       makeJWT(t, rs256, map[string]any{"roles": []any{"admin"}}),
			wantIsJWT:     true,
			wantSensitive: true,
		},
		{
			name:          "authenticated auth_status is sensitive",
			snippet:       makeJWT(t, rs256, map[string]any{"auth_status": "AUTHENTICATED"}),
			wantIsJWT:     true,
			wantSensitive: true,
		},
		{
			name:          "empty sub/scope do not count as sensitive",
			snippet:       makeJWT(t, rs256, map[string]any{"sub": "", "scope": "", "roles": []any{}}),
			wantIsJWT:     true,
			wantSensitive: false,
		},
		{
			name:      "non-JWT secret is not a JWT",
			snippet:   "AKIAIOSFODNN7EXAMPLE",
			wantIsJWT: false,
		},
		{
			name:      "two-segment token is not a JWT",
			snippet:   "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0",
			wantIsJWT: false,
		},
		{
			name:      "header without alg is not treated as a JWT",
			snippet:   makeJWT(t, map[string]any{"typ": "JWT"}, map[string]any{"sub": "x"}),
			wantIsJWT: false,
		},
		{
			name:      "malformed base64 segments are not a JWT",
			snippet:   "@@@.@@@.@@@",
			wantIsJWT: false,
		},
		{
			name:      "empty snippet is not a JWT",
			snippet:   "",
			wantIsJWT: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsJWT, gotSensitive := ClassifyJWTSnippet(tt.snippet)
			if gotIsJWT != tt.wantIsJWT {
				t.Errorf("isJWT = %v, want %v", gotIsJWT, tt.wantIsJWT)
			}
			if gotIsJWT && gotSensitive != tt.wantSensitive {
				t.Errorf("sensitive = %v, want %v", gotSensitive, tt.wantSensitive)
			}
		})
	}
}

func TestLowValueJWT(t *testing.T) {
	rs256 := map[string]any{"alg": "RS256", "typ": "JWT"}

	// The Cloudflare Access meta token is the canonical low-value JWT.
	if !LowValueJWT(cloudflareAccessMetaToken) {
		t.Error("LowValueJWT(cloudflareAccessMetaToken) = false, want true")
	}
	// A token with a real identity is not low-value.
	if LowValueJWT(makeJWT(t, rs256, map[string]any{"sub": "user-1", "email": "a@b.com"})) {
		t.Error("LowValueJWT(identity token) = true, want false")
	}
	// A non-JWT snippet is never low-value (downgrade is JWT-scoped).
	if LowValueJWT("AKIAIOSFODNN7EXAMPLE") {
		t.Error("LowValueJWT(non-JWT) = true, want false")
	}
}
