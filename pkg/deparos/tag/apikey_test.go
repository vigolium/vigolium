package tag

import (
	"testing"
)

func TestAPIKeyMatcher_Match(t *testing.T) {
	matcher := NewAPIKeyMatcher()

	tests := []struct {
		name         string
		responseBody string
		wantMatch    bool
	}{
		{
			name:         "aws access key in body",
			responseBody: `{"aws_key": "AKIAIOSFODNN7EXAMPLE"}`,
			wantMatch:    true,
		},
		{
			name:         "google api key in body",
			responseBody: `{"google_key": "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"}`,
			wantMatch:    true,
		},
		{
			name:         "github token in body",
			responseBody: `{"token": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}`,
			wantMatch:    true,
		},
		{
			name:         "stripe key in body",
			responseBody: `{"stripe_key": "sk_live_abcdefghijklmnopqrstuvwxyz"}`,
			wantMatch:    true,
		},
		{
			name:         "slack token in body",
			responseBody: `{"slack_token": "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"}`,
			wantMatch:    true,
		},
		{
			name:         "generic api_key in json",
			responseBody: `{"api_key": "abcdefghijklmnopqrstuvwxyz123456"}`,
			wantMatch:    true,
		},
		{
			name:         "secret_key in json",
			responseBody: `{"secret_key": "my-super-secret-key-12345678901234567890"}`,
			wantMatch:    true,
		},
		{
			name:         "no api key plain text",
			responseBody: "Hello world",
			wantMatch:    false,
		},
		{
			name:         "no api key empty",
			responseBody: "",
			wantMatch:    false,
		},
		{
			name:         "short key should not match",
			responseBody: `{"api_key": "short"}`,
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

func TestAPIKeyMatcher_Tag(t *testing.T) {
	matcher := NewAPIKeyMatcher()
	if matcher.Tag() != TagHasAPIKey {
		t.Errorf("Tag() = %v, want %v", matcher.Tag(), TagHasAPIKey)
	}
}
