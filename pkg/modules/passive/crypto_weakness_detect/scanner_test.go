package crypto_weakness_detect

import (
	"testing"
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
			name:    "detects SHA1 near token keyword",
			body:    `token: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`,
			wantLen: 1,
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
			findings := checkPaddingOracle(tt.body)
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
