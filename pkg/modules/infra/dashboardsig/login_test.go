package dashboardsig

import "testing"

func hdr(m map[string]string) func(string) string {
	return func(name string) string { return m[name] }
}

func TestLoginSuccess_Match(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		s      LoginSuccess
		status int
		header map[string]string
		body   string
		want   bool
	}{
		{
			name:   "status+cookie+body all match",
			s:      LoginSuccess{Status: []int{200}, Headers: []HeaderSig{{Name: "Set-Cookie", Contains: "grafana_session"}}, BodyContains: []string{"logged in"}},
			status: 200,
			header: map[string]string{"Set-Cookie": "grafana_session=abc; Path=/"},
			body:   "Logged in",
			want:   true,
		},
		{
			name:   "wrong status fails",
			s:      LoginSuccess{Status: []int{200}, BodyContains: []string{"logged in"}},
			status: 401,
			body:   "Logged in",
			want:   false,
		},
		{
			name:   "missing cookie fails",
			s:      LoginSuccess{Status: []int{200}, Headers: []HeaderSig{{Name: "Set-Cookie", Contains: "grafana_session"}}},
			status: 200,
			header: map[string]string{"Set-Cookie": "other=1"},
			want:   false,
		},
		{
			name:   "body substring absent fails (AND across BodyContains)",
			s:      LoginSuccess{Status: []int{200}, BodyContains: []string{`"access_token"`, `"refresh_token"`}},
			status: 200,
			body:   `{"access_token":"x"}`,
			want:   false,
		},
		{
			name:   "empty body required and present",
			s:      LoginSuccess{Status: []int{200}, EmptyBody: true, Headers: []HeaderSig{{Name: "Set-Cookie", Contains: "jwt-session="}}},
			status: 200,
			header: map[string]string{"Set-Cookie": "JWT-SESSION=tok"},
			body:   "   \n",
			want:   true,
		},
		{
			name:   "empty body required but body present fails",
			s:      LoginSuccess{Status: []int{200}, EmptyBody: true},
			status: 200,
			body:   "not empty",
			want:   false,
		},
		{
			name:   "matcher asserting nothing never confirms",
			s:      LoginSuccess{},
			status: 200,
			body:   "anything",
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.s.Match(tt.status, hdr(tt.header), tt.body, toLower(tt.body))
			if got != tt.want {
				t.Fatalf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// toLower mirrors the precomputed-lowercase contract callers honour.
func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
