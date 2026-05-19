package swagger_exposure

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	m := New()
	if m.ID() != ModuleID {
		t.Errorf("ID() = %q, want %q", m.ID(), ModuleID)
	}
	if m.Severity() != severity.Low {
		t.Errorf("Severity() = %v, want Low", m.Severity())
	}
	if !m.ScanScopes().Has(modkit.ScanScopeRequest) {
		t.Error("expected ScanScopeRequest to be set")
	}
	if len(m.Tags()) == 0 {
		t.Error("expected tags to be set")
	}
}

func TestCanProcess(t *testing.T) {
	m := New()
	if m.CanProcess(nil) {
		t.Error("CanProcess(nil) should return false")
	}
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	rr := httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequest(rawReq), nil)
	if !m.CanProcess(rr) {
		t.Error("CanProcess should return true for valid request")
	}
}

func TestIncludesBaseCanProcess(t *testing.T) {
	if New().IncludesBaseCanProcess() {
		t.Error("IncludesBaseCanProcess should return false")
	}
}

func TestProbePaths(t *testing.T) {
	if len(probePaths) == 0 {
		t.Fatal("probePaths should not be empty")
	}
	has := make(map[string]bool, len(probePaths))
	for _, p := range probePaths {
		if has[p] {
			t.Errorf("duplicate probe path %q", p)
		}
		has[p] = true
	}
	for _, exp := range []string{"swagger-ui.html", "openapi.json", "v3/api-docs"} {
		if !has[exp] {
			t.Errorf("probePaths missing %q", exp)
		}
	}
}

func TestLooksLikeSwaggerUI(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"swagger-ui div", `<div id="swagger-ui"></div>`, true},
		{"swagger ui bundle", `<script>window.ui = SwaggerUIBundle({})</script>`, true},
		{"redoc tag", `<redoc spec-url="/openapi.json"></redoc>`, true},
		{"plain html", `<html><body>hello world</body></html>`, false},
		{"empty", ``, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := looksLikeSwaggerUI([]byte(c.body)); got != c.want {
				t.Errorf("looksLikeSwaggerUI(%q) = %v, want %v", c.body, got, c.want)
			}
		})
	}
}
