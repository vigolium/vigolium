package iis_shortname_discovery

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestIsIISServer(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{
			name:    "Microsoft-IIS server header",
			headers: map[string]string{"Server": "Microsoft-IIS/10.0"},
			want:    true,
		},
		{
			name:    "Microsoft-IIS lowercase",
			headers: map[string]string{"Server": "microsoft-iis/8.5"},
			want:    true,
		},
		{
			name:    "X-AspNet-Version header",
			headers: map[string]string{"X-AspNet-Version": "4.0.30319"},
			want:    true,
		},
		{
			name:    "X-AspNetMvc-Version header",
			headers: map[string]string{"X-AspNetMvc-Version": "5.2"},
			want:    true,
		},
		{
			name:    "X-Powered-By ASP.NET",
			headers: map[string]string{"X-Powered-By": "ASP.NET"},
			want:    true,
		},
		{
			name:    "X-Powered-By asp.net lowercase",
			headers: map[string]string{"X-Powered-By": "asp.net"},
			want:    true,
		},
		{
			name:    "Apache server",
			headers: map[string]string{"Server": "Apache/2.4.41"},
			want:    false,
		},
		{
			name:    "Nginx server",
			headers: map[string]string{"Server": "nginx/1.18.0"},
			want:    false,
		},
		{
			name:    "No server header",
			headers: map[string]string{},
			want:    false,
		},
		{
			name:    "X-Powered-By PHP",
			headers: map[string]string{"X-Powered-By": "PHP/7.4"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := httpmsg.BuildRawResponse(200, tt.headers, "OK")
			resp := httpmsg.NewHttpResponse(raw)
			got := isIISServer(resp)
			if got != tt.want {
				t.Errorf("isIISServer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShortFileString(t *testing.T) {
	tests := []struct {
		sf   shortFile
		want string
	}{
		{shortFile{"WEBCON", "~1", "CON"}, "WEBCON~1.CON"},
		{shortFile{"DEFAUL", "~1", "ASP"}, "DEFAUL~1.ASP"},
		{shortFile{"INDEXH", "~2", "HTM"}, "INDEXH~2.HTM"},
		{shortFile{"MYDIR", "~1", ""}, "MYDIR~1"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.sf.String()
			if got != tt.want {
				t.Errorf("shortFile.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRequestBudget(t *testing.T) {
	rb := newRequestBudget(3)

	if rb.exhausted() {
		t.Error("should not be exhausted initially")
	}

	rb.inc()
	rb.inc()
	if rb.exhausted() {
		t.Error("should not be exhausted at count 2 with max 3")
	}

	rb.inc()
	if !rb.exhausted() {
		t.Error("should be exhausted at count 3 with max 3")
	}
}

func TestPathEscape(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"*~1*", "%2A~1%2A"},
		{"hello world", "hello%20world"},
		{"test+file", "test%2Bfile"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := pathEscape(tt.input)
			if got != tt.want {
				t.Errorf("pathEscape(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestModuleCanProcess(t *testing.T) {
	m := New()

	// nil context
	if m.CanProcess(nil) {
		t.Error("CanProcess(nil) should return false")
	}

	// IIS server
	iisRaw := httpmsg.BuildRawResponse(200, map[string]string{"Server": "Microsoft-IIS/10.0"}, "OK")
	iisResp := httpmsg.NewHttpResponse(iisRaw)

	reqRaw := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req, _ := httpmsg.ParseRawRequest(string(reqRaw))
	iisCtx := req.WithResponse(iisResp)

	if !m.CanProcess(iisCtx) {
		t.Error("CanProcess should return true for IIS server")
	}

	// Non-IIS server
	nginxRaw := httpmsg.BuildRawResponse(200, map[string]string{"Server": "nginx/1.18.0"}, "OK")
	nginxResp := httpmsg.NewHttpResponse(nginxRaw)
	nginxCtx := req.WithResponse(nginxResp)

	if m.CanProcess(nginxCtx) {
		t.Error("CanProcess should return false for nginx server")
	}

	// No response
	noRespCtx := req.WithResponse(nil)
	if m.CanProcess(noRespCtx) {
		t.Error("CanProcess should return false when response is nil")
	}
}

func TestModuleMetadata(t *testing.T) {
	m := New()

	if m.ID() != "active-iis-shortname-discovery" {
		t.Errorf("unexpected ID: %s", m.ID())
	}
	if m.Name() != "IIS Short Filename Discovery" {
		t.Errorf("unexpected Name: %s", m.Name())
	}
	if m.ScanScopes() != modkit.ScanScopeHost {
		t.Errorf("unexpected ScanScopes: %v", m.ScanScopes())
	}
	if m.IncludesBaseCanProcess() {
		t.Error("IncludesBaseCanProcess should return false")
	}
}
