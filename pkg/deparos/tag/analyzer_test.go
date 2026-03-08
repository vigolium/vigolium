package tag

import (
	"github.com/vigolium/vigolium/pkg/deparos/storage"
	"net/url"
	"testing"
)

func TestAnalyzer_Analyze(t *testing.T) {
	analyzer := NewAnalyzer()

	// Valid JWT
	validJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	tests := []struct {
		name     string
		respBody string
		wantTags []Tag
	}{
		{
			name:     "no tags - plain response",
			respBody: "Hello world",
			wantTags: nil,
		},
		{
			name:     "vibeapp - emoji in body",
			respBody: "Welcome! 🎉 Have fun!",
			wantTags: []Tag{TagVibeApp},
		},
		{
			name:     "has-jwt - jwt in body",
			respBody: `{"token": "` + validJWT + `"}`,
			wantTags: []Tag{TagHasJWT},
		},
		{
			name:     "has-api-key - api key in body",
			respBody: `{"api_key": "AKIAIOSFODNN7EXAMPLE"}`,
			wantTags: []Tag{TagHasAPIKey},
		},
		{
			name:     "error-page - stack trace",
			respBody: "Error at com.example.App.main(App.java:42)",
			wantTags: []Tag{TagErrorPage},
		},
		{
			name:     "multiple tags - jwt and api key in body",
			respBody: `{"token": "` + validJWT + `", "aws_key": "AKIAIOSFODNN7EXAMPLE"}`,
			wantTags: []Tag{TagHasJWT, TagHasAPIKey},
		},
		{
			name:     "multiple tags - vibeapp and error",
			respBody: "Error! ⚠ at com.example.App.main(App.java:42)",
			wantTags: []Tag{TagVibeApp, TagErrorPage},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a DiscoveredNode with the test data
			testURL, _ := url.Parse("https://example.com/test")
			node := storage.NewDiscoveredNode(testURL)

			var resp *storage.ResponseData
			if tt.respBody != "" {
				resp = &storage.ResponseData{
					StatusCode: 200,
					Body:       []byte(tt.respBody),
				}
			}

			node.SetData(nil, resp, nil)

			got := analyzer.Analyze(node)

			// Check length
			if len(got) != len(tt.wantTags) {
				t.Errorf("Analyze() returned %d tags, want %d", len(got), len(tt.wantTags))
				t.Errorf("Got: %v, Want: %v", got, tt.wantTags)
				return
			}

			// Check each tag
			for i, wantTag := range tt.wantTags {
				if got[i] != wantTag {
					t.Errorf("Analyze()[%d] = %v, want %v", i, got[i], wantTag)
				}
			}
		})
	}
}
