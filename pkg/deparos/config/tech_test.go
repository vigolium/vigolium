package config

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// headerWith builds an http.Header with a single key via Set (canonicalizes the
// key the same way net/http populates a real response).
func headerWith(key, val string) http.Header {
	h := make(http.Header)
	h.Set(key, val)
	return h
}

func TestDetectTechExtensions(t *testing.T) {
	tests := []struct {
		name      string
		header    http.Header
		wantTech  string   // expected stack name ("" = expect no match)
		wantExts  []string // extensions that must be present in the union
		wantEmpty bool
	}{
		{
			name:     "PHPSESSID cookie ⇒ PHP",
			header:   http.Header{"Set-Cookie": {"PHPSESSID=abc123; path=/"}},
			wantTech: "PHP",
			wantExts: []string{"php", "phtml"},
		},
		{
			name:     "X-Powered-By PHP",
			header:   http.Header{"X-Powered-By": {"PHP/8.2.1"}},
			wantTech: "PHP",
			wantExts: []string{"php"},
		},
		{
			name:     "JSESSIONID cookie ⇒ Java/JSP (incl. action/do)",
			header:   http.Header{"Set-Cookie": {"JSESSIONID=8F3A...; Path=/; HttpOnly"}},
			wantTech: "Java/JSP",
			wantExts: []string{"jsp", "jspx", "do", "action"},
		},
		{
			name:     "Tomcat server header ⇒ Java/JSP",
			header:   http.Header{"Server": {"Apache-Coyote/1.1"}},
			wantTech: "Java/JSP",
			wantExts: []string{"jsp", "action"},
		},
		{
			name:     "ASP.NET_SessionId cookie ⇒ ASP.NET",
			header:   http.Header{"Set-Cookie": {"ASP.NET_SessionId=xyz; path=/; HttpOnly"}},
			wantTech: "ASP.NET",
			wantExts: []string{"aspx", "ashx", "asmx"},
		},
		{
			name:     "X-AspNet-Version presence ⇒ ASP.NET",
			header:   headerWith("X-AspNet-Version", "4.0.30319"),
			wantTech: "ASP.NET",
			wantExts: []string{"aspx", "ashx"},
		},
		{
			name:     "ColdFusion cookies",
			header:   http.Header{"Set-Cookie": {"CFID=123", "CFTOKEN=456"}},
			wantTech: "ColdFusion",
			wantExts: []string{"cfm", "cfml"},
		},
		{
			name:      "plain static site ⇒ no match",
			header:    http.Header{"Server": {"nginx/1.25"}, "Content-Type": {"text/html"}},
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := DetectTechExtensions(tt.header.Get, tt.header.Values("Set-Cookie"))

			if tt.wantEmpty {
				assert.Empty(t, matches, "expected no tech match")
				return
			}

			// Collect tech names and the union of extensions.
			extSet := map[string]bool{}
			var techNames []string
			for _, m := range matches {
				techNames = append(techNames, m.Tech)
				for _, e := range m.Extensions {
					extSet[e] = true
				}
			}
			assert.Contains(t, techNames, tt.wantTech, "expected stack %q to be detected", tt.wantTech)
			for _, e := range tt.wantExts {
				assert.True(t, extSet[e], "expected extension %q in detected union, got %v", e, extSet)
			}
		})
	}
}
