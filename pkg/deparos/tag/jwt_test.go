package tag

import (
	"testing"
)

func TestJWTMatcher_Match(t *testing.T) {
	matcher := NewJWTMatcher()

	// Real JWT structure (header.payload.signature)
	validJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	tests := []struct {
		name         string
		responseBody string
		wantMatch    bool
	}{
		{
			name:         "jwt in response body",
			responseBody: `{"access_token": "` + validJWT + `"}`,
			wantMatch:    true,
		},
		{
			name:         "jwt in html body",
			responseBody: `<script>var token = "` + validJWT + `";</script>`,
			wantMatch:    true,
		},
		{
			name:         "jwt raw in body",
			responseBody: validJWT,
			wantMatch:    true,
		},
		{
			name:         "no jwt plain text",
			responseBody: "Hello world",
			wantMatch:    false,
		},
		{
			name:         "no jwt empty",
			responseBody: "",
			wantMatch:    false,
		},
		{
			name:         "invalid jwt format - missing segment",
			responseBody: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
			wantMatch:    false,
		},
		{
			name:         "invalid jwt format - short segments",
			responseBody: "eyJhbGc.eyJzdWI.SflKx",
			wantMatch:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &MatchInput{
				ResponseBody: []byte(tt.responseBody),
			}
			got := matcher.Match(input)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestJWTMatcher_Tag(t *testing.T) {
	matcher := NewJWTMatcher()
	if matcher.Tag() != TagHasJWT {
		t.Errorf("Tag() = %v, want %v", matcher.Tag(), TagHasJWT)
	}
}
