package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRun_DetectsWordPressAndOpenAPIAndSpringActuator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "nginx/1.18.0 (Ubuntu)")
			w.Header().Set("X-Pingback", "https://example.com/xmlrpc.php")
			w.Header().Add("Set-Cookie", "wordpress_test_cookie=WP+Cookie+check; path=/")
			w.Header().Set("Strict-Transport-Security", "max-age=63072000")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head>
				<meta name="generator" content="WordPress 6.3.1">
				<link rel="https://api.w.org/" href="https://example.com/wp-json/">
				</head><body>asset:/wp-content/themes/twentytwentythree/style.css</body></html>`))
		case "/v3/api-docs":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"openapi":"3.0.1","info":{"title":"test","version":"1"}}`))
		case "/actuator/health":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"UP"}`))
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	report, err := Run(ctx, srv.URL, Config{Concurrency: 4, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if report == nil {
		t.Fatal("report is nil")
	}

	wantStacks := map[string]bool{"wordpress": false, "nginx": false, "spring-boot": false}
	for _, s := range report.Stacks {
		if _, ok := wantStacks[s.Name]; ok {
			wantStacks[s.Name] = true
		}
	}
	for name, found := range wantStacks {
		if !found {
			t.Errorf("expected stack %q to be detected, got stacks=%+v", name, report.Stacks)
		}
	}

	if len(report.APISpecs) == 0 {
		t.Error("expected at least one API spec detection (OpenAPI at /v3/api-docs)")
	} else {
		var foundOpenAPI bool
		for _, s := range report.APISpecs {
			if s.Kind == "openapi" && strings.HasSuffix(s.URL, "/v3/api-docs") {
				foundOpenAPI = true
				break
			}
		}
		if !foundOpenAPI {
			t.Errorf("expected openapi at /v3/api-docs in APISpecs, got %+v", report.APISpecs)
		}
	}

	// HSTS present, others missing.
	if _, ok := report.SecurityHeaders.Present["Strict-Transport-Security"]; !ok {
		t.Error("expected HSTS to be flagged as present")
	}
	if len(report.SecurityHeaders.Missing) == 0 {
		t.Error("expected at least CSP/X-Frame-Options to be flagged missing")
	}

	if !report.HasSignal() {
		t.Error("expected HasSignal() == true")
	}

	rendered := Render(report)
	if !strings.Contains(rendered, "wordpress") || !strings.Contains(rendered, "spring") {
		t.Errorf("expected rendered markdown to mention detected stacks, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Suggested MODULE_TAGS") {
		t.Errorf("expected MODULE_TAGS suggestion section, got:\n%s", rendered)
	}
}

func TestRun_DetectsGraphQLIntrospection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"__schema":{"types":[{"name":"Query"}]}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	report, err := Run(ctx, srv.URL, Config{Concurrency: 4})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	var found bool
	for _, s := range report.APISpecs {
		if s.Kind == "graphql" && s.Note == "introspection enabled" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected GraphQL introspection detection, got %+v", report.APISpecs)
	}
}

func TestRun_DetectsCORSReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions && r.Header.Get("Origin") != "" {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	report, err := Run(ctx, srv.URL, Config{Concurrency: 2})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if report.CORS == nil {
		t.Fatal("expected CORS detection, got nil")
	}
	if !report.CORS.Reflective {
		t.Errorf("expected reflective CORS, got %+v", report.CORS)
	}
	if report.CORS.AllowCredentials != "true" {
		t.Errorf("expected Allow-Credentials=true, got %q", report.CORS.AllowCredentials)
	}
}

func TestRun_NoSignalEmptyTarget(t *testing.T) {
	// Only GET / returns 200 (with all security headers set). Every other
	// path 404s, and every non-GET method on / returns 405 — matching how
	// a real read-only homepage behaves. No actuator, no /wp-login, no
	// /server-status, no JS framework markers, no login form.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodOptions {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "fullscreen=()")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	report, err := Run(ctx, srv.URL, Config{Concurrency: 2})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if report.HasSignal() {
		t.Errorf("expected HasSignal()==false for clean target, got stacks=%+v missing=%v methodMatrix=%+v vhost=%+v",
			report.Stacks, report.SecurityHeaders.Missing, report.MethodMatrix, report.VHostFindings)
	}
}

func TestExtractVersionAfter(t *testing.T) {
	cases := []struct {
		input  string
		prefix string
		want   string
	}{
		{"nginx/1.18.0 (Ubuntu)", "nginx/", "1.18.0"},
		{"Apache/2.4.41 (Unix)", "Apache/", "2.4.41"},
		{"Apache/2.4.41", "Apache/", "2.4.41"},
		{"PHP/8.1.2", "PHP/", "8.1.2"},
		{"PHP/8.1.2; nginx/1.20", "PHP/", "8.1.2"},
		{"PHP/8.1.2", "Apache/", ""}, // prefix absent
		{"", "PHP/", ""},
	}
	for _, tc := range cases {
		got := extractVersionAfter(tc.input, tc.prefix)
		if got != tc.want {
			t.Errorf("extractVersionAfter(%q, %q): got %q want %q", tc.input, tc.prefix, got, tc.want)
		}
	}
}
