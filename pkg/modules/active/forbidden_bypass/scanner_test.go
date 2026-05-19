package forbidden_bypass

import (
	"testing"
)

func TestIsMethodBypassStatus(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		statusCode int
		body       string
		want       bool
	}{
		{
			name:       "PUT returning 200 is a bypass",
			method:     "PUT",
			statusCode: 200,
			body:       "<html>Admin Panel</html>",
			want:       true,
		},
		{
			name:       "DELETE returning 200 is a bypass",
			method:     "DELETE",
			statusCode: 200,
			body:       "<html>Resource deleted</html>",
			want:       true,
		},
		{
			name:       "PATCH returning 200 is a bypass",
			method:     "PATCH",
			statusCode: 200,
			body:       "<html>Updated</html>",
			want:       true,
		},
		{
			name:       "HEAD returning 200 is NOT a bypass (normal behavior)",
			method:     "HEAD",
			statusCode: 200,
			body:       "",
			want:       false,
		},
		{
			name:       "OPTIONS returning 200 with small body is NOT a bypass (CORS)",
			method:     "OPTIONS",
			statusCode: 200,
			body:       "OK",
			want:       false,
		},
		{
			name:       "OPTIONS returning 200 with large body IS a bypass",
			method:     "OPTIONS",
			statusCode: 200,
			body:       string(make([]byte, 600)),
			want:       true,
		},
		{
			name:       "405 Method Not Allowed is NOT a bypass",
			method:     "PUT",
			statusCode: 405,
			body:       "Method Not Allowed",
			want:       false,
		},
		{
			name:       "401 is NOT a bypass",
			method:     "PUT",
			statusCode: 401,
			body:       "Unauthorized",
			want:       false,
		},
		{
			name:       "403 is NOT a bypass",
			method:     "PUT",
			statusCode: 403,
			body:       "Forbidden",
			want:       false,
		},
		{
			name:       "404 is NOT a bypass",
			method:     "PUT",
			statusCode: 404,
			body:       "Not Found",
			want:       false,
		},
		{
			name:       "500 is NOT a bypass",
			method:     "TRACE",
			statusCode: 500,
			body:       "Internal Server Error",
			want:       false,
		},
		{
			name:       "302 redirect is NOT a bypass",
			method:     "PUT",
			statusCode: 302,
			body:       "",
			want:       false,
		},
		{
			name:       "200 with login redirect in body is NOT a bypass",
			method:     "PUT",
			statusCode: 200,
			body:       "<html>Redirecting to /login</html>",
			want:       false,
		},
		{
			name:       "200 with signin redirect in body is NOT a bypass",
			method:     "PUT",
			statusCode: 200,
			body:       "<html>Redirecting to /signin</html>",
			want:       false,
		},
		{
			name:       "200 with method not allowed in body is NOT a bypass",
			method:     "PUT",
			statusCode: 200,
			body:       "<html>Method Not Allowed</html>",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMethodBypassStatus(tt.method, tt.statusCode, tt.body)
			if got != tt.want {
				t.Errorf("isMethodBypassStatus(%q, %d, ...) = %v, want %v", tt.method, tt.statusCode, got, tt.want)
			}
		})
	}
}
