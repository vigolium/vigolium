package jwtutil

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

// makeJWT builds a well-formed compact JWT from a header and payload (the
// signature segment is a fixed placeholder — these helpers never verify it).
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

func TestIsPreAuthMetaTokenString(t *testing.T) {
	rs256 := map[string]any{"alg": "RS256", "typ": "JWT"}

	tests := []struct {
		name    string
		snippet string
		want    bool
	}{
		{"cloudflare access meta token", cloudflareAccessMetaToken, true},
		{"type=meta", makeJWT(t, rs256, map[string]any{"type": "meta"}), true},
		{"auth_status=NONE", makeJWT(t, rs256, map[string]any{"auth_status": "NONE"}), true},
		{"auth_status=none lowercase", makeJWT(t, rs256, map[string]any{"auth_status": "none"}), true},
		{"authenticated session token", makeJWT(t, rs256, map[string]any{"sub": "u1", "auth_status": "AUTHENTICATED"}), false},
		{"plain identity token", makeJWT(t, rs256, map[string]any{"sub": "u1", "email": "a@b.com"}), false},
		{"non-JWT", "AKIAIOSFODNN7EXAMPLE", false},
		{"two-segment", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPreAuthMetaTokenString(tt.snippet); got != tt.want {
				t.Errorf("IsPreAuthMetaTokenString(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestClassifyAndIsLowValue(t *testing.T) {
	rs256 := map[string]any{"alg": "RS256", "typ": "JWT"}

	tests := []struct {
		name          string
		snippet       string
		wantIsJWT     bool
		wantSensitive bool
		wantLowValue  bool
	}{
		{"cloudflare meta token", cloudflareAccessMetaToken, true, false, true},
		{"type=meta", makeJWT(t, rs256, map[string]any{"type": "meta"}), true, false, true},
		{"auth_status=NONE", makeJWT(t, rs256, map[string]any{"auth_status": "NONE", "aud": "app"}), true, false, true},
		{"no-identity registered claims", makeJWT(t, rs256, map[string]any{"iss": "cf", "exp": 1781357251}), true, false, true},
		{"sub identity", makeJWT(t, rs256, map[string]any{"sub": "user-42"}), true, true, false},
		{"email identity", makeJWT(t, rs256, map[string]any{"email": "a@b.com"}), true, true, false},
		{"scope grant", makeJWT(t, rs256, map[string]any{"scope": "read write"}), true, true, false},
		{"roles array", makeJWT(t, rs256, map[string]any{"roles": []any{"admin"}}), true, true, false},
		{"authenticated auth_status", makeJWT(t, rs256, map[string]any{"auth_status": "AUTHENTICATED"}), true, true, false},
		{"empty identity/scope", makeJWT(t, rs256, map[string]any{"sub": "", "scope": "", "roles": []any{}}), true, false, true},
		{"header without alg", makeJWT(t, map[string]any{"typ": "JWT"}, map[string]any{"sub": "x"}), false, false, false},
		{"non-JWT secret", "AKIAIOSFODNN7EXAMPLE", false, false, false},
		{"malformed base64", "@@@.@@@.@@@", false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsJWT, gotSensitive := Classify(tt.snippet)
			if gotIsJWT != tt.wantIsJWT {
				t.Errorf("Classify isJWT = %v, want %v", gotIsJWT, tt.wantIsJWT)
			}
			if gotIsJWT && gotSensitive != tt.wantSensitive {
				t.Errorf("Classify sensitive = %v, want %v", gotSensitive, tt.wantSensitive)
			}
			if got := IsLowValue(tt.snippet); got != tt.wantLowValue {
				t.Errorf("IsLowValue = %v, want %v", got, tt.wantLowValue)
			}
		})
	}
}

func TestIsJWT(t *testing.T) {
	if !IsJWT(cloudflareAccessMetaToken) {
		t.Error("IsJWT(cloudflareAccessMetaToken) = false, want true")
	}
	if IsJWT("not.a.jwt!") {
		t.Error("IsJWT(non-base64) = true, want false")
	}
	if IsJWT("onlytwo.segments") {
		t.Error("IsJWT(two-segment) = true, want false")
	}
}

func TestDecode(t *testing.T) {
	header, payload, ok := Decode(cloudflareAccessMetaToken)
	if !ok {
		t.Fatal("Decode failed for valid JWT")
	}
	if header["alg"] != "RS256" {
		t.Errorf("header alg = %v, want RS256", header["alg"])
	}
	if payload["type"] != "meta" {
		t.Errorf("payload type = %v, want meta", payload["type"])
	}
	if _, _, ok := Decode("AKIAIOSFODNN7EXAMPLE"); ok {
		t.Error("Decode(non-JWT) ok = true, want false")
	}
}
