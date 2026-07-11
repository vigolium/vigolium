package crypto_weakness_detect

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestCheckMagicHash(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantLen int
	}{
		{
			name:    "detects magic hash",
			body:    `{"hash":"0e462097431906509019562988736854"}`,
			wantLen: 1,
		},
		{
			name:    "detects uppercase E magic hash",
			body:    `hash=0E462097431906509019562988736854`,
			wantLen: 1,
		},
		{
			name:    "no false positive on normal numbers",
			body:    `{"id": 12345, "count": 0}`,
			wantLen: 0,
		},
		{
			name:    "no false positive on short 0e",
			body:    `0e123`,
			wantLen: 0,
		},
		{
			name:    "unstructured magic-looking telemetry is ignored",
			body:    `build artifact token 0e462097431906509019562988736854`,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := checkMagicHash(tt.body)
			if len(findings) != tt.wantLen {
				t.Errorf("checkMagicHash() returned %d findings, want %d", len(findings), tt.wantLen)
			}
		})
	}
}

func TestCheckWeakHashes(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantLen int
	}{
		{
			name:    "detects MD5 near password keyword",
			body:    `password: 5d41402abc4b2a76b9719d911017c592`,
			wantLen: 1,
		},
		{
			name:    "detects SHA1 in password digest field",
			body:    `password_digest: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`,
			wantLen: 1,
		},
		{
			name:    "token-shaped hex is not assumed to be a password hash",
			body:    `token: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`,
			wantLen: 0,
		},
		{
			name:    "no detection for hash without sensitive context",
			body:    `some random 5d41402abc4b2a76b9719d911017c592 text`,
			wantLen: 0,
		},
		{
			name:    "no false positive on UUIDs",
			body:    `password: 550e8400-e29b-41d4-a716-446655440000`,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := checkWeakHashes(tt.body)
			if len(findings) != tt.wantLen {
				t.Errorf("checkWeakHashes() returned %d findings, want %d", len(findings), tt.wantLen)
			}
		})
	}
}

func cryptoContext(body string, setCookies ...string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /account HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure("example.com", 443, true), rawReq)
	headers := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
	for _, cookie := range setCookies {
		headers += "Set-Cookie: " + cookie + "\r\n"
	}
	resp := httpmsg.NewHttpResponse([]byte(headers + "\r\n" + body))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestPassiveIndicatorsNeverBecomeConfirmedFindings(t *testing.T) {
	t.Parallel()
	body := `{"password_hash":"5d41402abc4b2a76b9719d911017c592","error":"BadPaddingException"}`
	results, err := New().ScanPerRequest(cryptoContext(body), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	for _, result := range results {
		assert.NotEqual(t, output.RecordKindFinding, result.RecordKind)
		assert.NotEmpty(t, result.ModuleID)
	}
}

func TestEncryptedCookieCompanionOrderIndependent(t *testing.T) {
	t.Parallel()
	decoded := make([]byte, 32)
	for i := range decoded {
		decoded[i] = byte(i)
	}
	value := base64.StdEncoding.EncodeToString(decoded)
	ctx := cryptoContext(`{"ok":true}`,
		fmt.Sprintf("SESSION=%s; Path=/; HttpOnly", value),
		"SESSION_mac=separate-signature; Path=/; HttpOnly",
	)
	assert.Empty(t, checkEncryptedCookies(ctx, nil, "example.com"), "a companion MAC appearing later in the headers must still be recognized")
}

func TestOpaqueCookieIsObservationNotMissingMACFinding(t *testing.T) {
	t.Parallel()
	decoded := make([]byte, 32)
	for i := range decoded {
		decoded[i] = byte(i)
	}
	ctx := cryptoContext(`{"ok":true}`, fmt.Sprintf("SESSION=%s; Path=/; HttpOnly", base64.StdEncoding.EncodeToString(decoded)))
	findings := checkEncryptedCookies(ctx, nil, "example.com")
	require.Len(t, findings, 1)
	assert.Equal(t, output.RecordKindObservation, findings[0].kind)
	assert.NotContains(t, findings[0].name, "Without MAC")
}

// TestPublishesCryptoCBCTechTag verifies both positive detection branches publish
// the "crypto-cbc" tech tag that the active padding-oracle module is gated on.
func TestPublishesCryptoCBCTechTag(t *testing.T) {
	t.Parallel()

	t.Run("padding error string", func(t *testing.T) {
		t.Parallel()
		sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
		findings := checkPaddingOracle(`javax.crypto.BadPaddingException: bad`, sc, "shop.example.com")
		require.NotEmpty(t, findings)
		assert.True(t, sc.TechStack.Has("shop.example.com", "crypto-cbc"),
			"a disclosed padding error must publish the crypto-cbc tech tag")
	})

	t.Run("opaque block-aligned cookie", func(t *testing.T) {
		t.Parallel()
		decoded := make([]byte, 32)
		for i := range decoded {
			decoded[i] = byte(i)
		}
		ctx := cryptoContext(`{"ok":true}`,
			fmt.Sprintf("SESSION=%s; Path=/; HttpOnly", base64.StdEncoding.EncodeToString(decoded)))
		sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
		findings := checkEncryptedCookies(ctx, sc, "shop.example.com")
		require.Len(t, findings, 1)
		assert.True(t, sc.TechStack.Has("shop.example.com", "crypto-cbc"),
			"an opaque block-aligned session cookie must publish the crypto-cbc tech tag")
	})
}

func TestCheckPaddingOracle(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantLen int
	}{
		{
			name:    "detects BadPaddingException",
			body:    `javax.crypto.BadPaddingException: Given final block not properly padded`,
			wantLen: 1,
		},
		{
			name:    "detects invalid padding",
			body:    `Error: Invalid padding in decryption`,
			wantLen: 1,
		},
		{
			name:    "detects CryptographicException",
			body:    `System.Security.Cryptography.CryptographicException: Padding is invalid`,
			wantLen: 1,
		},
		{
			name:    "detects decryption failed",
			body:    `<error>Decryption failed for the provided data</error>`,
			wantLen: 1,
		},
		{
			name:    "no detection for normal content",
			body:    `<html>Welcome to the application</html>`,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := checkPaddingOracle(tt.body, nil, "example.com")
			if len(findings) != tt.wantLen {
				t.Errorf("checkPaddingOracle() returned %d findings, want %d", len(findings), tt.wantLen)
			}
		})
	}
}

func TestParseCookieNameValue(t *testing.T) {
	tests := []struct {
		header   string
		wantName string
		wantVal  string
	}{
		{
			header:   "session=abc123; path=/; HttpOnly",
			wantName: "session",
			wantVal:  "abc123",
		},
		{
			header:   "token=xyz",
			wantName: "token",
			wantVal:  "xyz",
		},
		{
			header:   "",
			wantName: "",
			wantVal:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			name, val := parseCookieNameValue(tt.header)
			if name != tt.wantName || val != tt.wantVal {
				t.Errorf("parseCookieNameValue(%q) = (%q, %q), want (%q, %q)", tt.header, name, val, tt.wantName, tt.wantVal)
			}
		})
	}
}

func TestIsLikelyFalsePositiveHash(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{
			name:  "UUID is false positive",
			value: "550e8400-e29b-41d4-a716-446655440000",
			want:  true,
		},
		{
			name:  "CSS color is false positive",
			value: "#aabbcc",
			want:  true,
		},
		{
			name:  "ETag is false positive",
			value: `"5d41402abc4b2a76b9719d911017c592"`,
			want:  true,
		},
		{
			name:  "plain hex string is not false positive",
			value: "5d41402abc4b2a76b9719d911017c592",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLikelyFalsePositiveHash(tt.value)
			if got != tt.want {
				t.Errorf("isLikelyFalsePositiveHash(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}
