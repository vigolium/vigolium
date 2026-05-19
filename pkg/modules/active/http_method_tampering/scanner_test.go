package http_method_tampering

import (
	"testing"
)

func TestIsSuccessfulMethod(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		want       bool
	}{
		{
			name:       "200 with meaningful body is successful",
			statusCode: 200,
			body:       "<html><body>Welcome to the admin panel, you have full access</body></html>",
			want:       true,
		},
		{
			name:       "405 is not successful",
			statusCode: 405,
			body:       "Method Not Allowed",
			want:       false,
		},
		{
			name:       "403 is not successful",
			statusCode: 403,
			body:       "Forbidden",
			want:       false,
		},
		{
			name:       "200 with method not allowed in body is not successful",
			statusCode: 200,
			body:       "<html>Method Not Allowed for this resource</html>",
			want:       false,
		},
		{
			name:       "200 with not supported in body is not successful",
			statusCode: 200,
			body:       "<html>This HTTP method is not supported on this endpoint</html>",
			want:       false,
		},
		{
			name:       "200 with login redirect is not successful",
			statusCode: 200,
			body:       "<html>Redirecting to /login please authenticate first</html>",
			want:       false,
		},
		{
			name:       "200 with empty body is not successful",
			statusCode: 200,
			body:       "",
			want:       false,
		},
		{
			name:       "200 with very short body is not successful",
			statusCode: 200,
			body:       "OK",
			want:       false,
		},
		{
			name:       "500 is not successful",
			statusCode: 500,
			body:       "Internal Server Error",
			want:       false,
		},
		{
			name:       "302 is not successful",
			statusCode: 302,
			body:       "",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSuccessfulMethod(tt.statusCode, tt.body)
			if got != tt.want {
				t.Errorf("isSuccessfulMethod(%d, ...) = %v, want %v", tt.statusCode, got, tt.want)
			}
		})
	}
}
