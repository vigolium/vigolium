package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// buildSwarmPromptContext mirrors runMasterAgent's logic for building the
// request context string and Options from normalized records.
// This is extracted here so we can test the full normalize→prompt flow
// without needing a running agent subprocess.
func buildSwarmPromptContext(records []*httpmsg.HttpRequestResponse, targetURL string, vulnType string) (requestContext string, hostname string, opts Options) {
	var rc strings.Builder
	for i, rr := range records {
		if i > 0 {
			rc.WriteString("\n---\n\n")
		}
		fmt.Fprintf(&rc, "### Request %d\n\n", i+1)
		if rr.Request() != nil {
			rc.WriteString("```http\n")
			rc.Write(rr.Request().Raw())
			rc.WriteString("\n```\n")
		}
		if rr.Response() != nil && len(rr.Response().Raw()) > 0 {
			respRaw := string(rr.Response().Raw())
			if len(respRaw) > 4096 {
				respRaw = respRaw[:4096] + "\n... (truncated)"
			}
			rc.WriteString("\n```http\n")
			rc.WriteString(respRaw)
			rc.WriteString("\n```\n")
		}
	}
	requestContext = rc.String()

	if targetURL != "" {
		hostname = hostnameFromURL(targetURL)
	}

	opts = Options{
		PromptTemplate: "agent-swarm-master",
		TargetURL:      targetURL,
		Hostname:       hostname,
		Extra: map[string]string{
			"RequestContext": requestContext,
			"VulnType":       vulnType,
		},
	}
	return requestContext, hostname, opts
}

// TestSwarmPrompt_RawHTTPInput verifies that a raw HTTP request piped into
// the swarm flow produces a prompt containing the URL, hostname, and request.
func TestSwarmPrompt_RawHTTPInput(t *testing.T) {
	raw := "GET /rest/products/search?q=apple HTTP/1.1\r\nHost: localhost:3000\r\nAuthorization: Bearer eyJtoken\r\nAccept: application/json\r\n\r\n"

	records, err := NormalizeInput(context.Background(), raw, "", nil)
	if err != nil {
		t.Fatalf("NormalizeInput failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	u, err := records[0].URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}
	targetURL := u.String()

	reqCtx, hostname, opts := buildSwarmPromptContext(records, targetURL, "")

	// Verify request context contains the raw request
	if !strings.Contains(reqCtx, "GET /rest/products/search?q=apple") {
		t.Errorf("request context missing request line, got:\n%s", reqCtx)
	}
	if !strings.Contains(reqCtx, "Host: localhost:3000") {
		t.Errorf("request context missing Host header, got:\n%s", reqCtx)
	}
	if !strings.Contains(reqCtx, "Authorization: Bearer") {
		t.Errorf("request context missing Authorization header, got:\n%s", reqCtx)
	}

	// Verify hostname extraction
	if hostname != "localhost" {
		t.Errorf("hostname = %q, want %q", hostname, "localhost")
	}

	// Render the actual template and verify the prompt
	rendered := renderSwarmTemplate(t, opts)

	if !strings.Contains(rendered, "localhost") {
		t.Errorf("rendered prompt missing hostname")
	}
	if !strings.Contains(rendered, targetURL) {
		t.Errorf("rendered prompt missing target URL %q", targetURL)
	}
	if !strings.Contains(rendered, "GET /rest/products/search?q=apple") {
		t.Errorf("rendered prompt missing request line")
	}
}

// TestSwarmPrompt_URLInput verifies that a plain URL produces the correct prompt.
func TestSwarmPrompt_URLInput(t *testing.T) {
	input := "https://example.com/api/v1/users?role=admin"

	records, err := NormalizeInput(context.Background(), input, "", nil)
	if err != nil {
		t.Fatalf("NormalizeInput failed: %v", err)
	}

	u, err := records[0].URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}
	targetURL := u.String()

	_, hostname, opts := buildSwarmPromptContext(records, targetURL, "")

	if hostname != "example.com" {
		t.Errorf("hostname = %q, want %q", hostname, "example.com")
	}

	rendered := renderSwarmTemplate(t, opts)

	if !strings.Contains(rendered, "example.com") {
		t.Errorf("rendered prompt missing hostname")
	}
	if !strings.Contains(rendered, "/api/v1/users") {
		t.Errorf("rendered prompt missing path")
	}
}

// TestSwarmPrompt_CurlInput verifies that a curl command produces the correct prompt.
func TestSwarmPrompt_CurlInput(t *testing.T) {
	input := `curl -X POST https://example.com/api/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"secret"}'`

	records, err := NormalizeInput(context.Background(), input, "", nil)
	if err != nil {
		t.Fatalf("NormalizeInput failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	u, err := records[0].URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}
	targetURL := u.String()

	reqCtx, hostname, opts := buildSwarmPromptContext(records, targetURL, "")

	if hostname != "example.com" {
		t.Errorf("hostname = %q, want %q", hostname, "example.com")
	}
	if !strings.Contains(reqCtx, "POST") {
		t.Errorf("request context missing POST method")
	}

	rendered := renderSwarmTemplate(t, opts)

	if !strings.Contains(rendered, "example.com") {
		t.Errorf("rendered prompt missing hostname")
	}
	if !strings.Contains(rendered, "/api/login") {
		t.Errorf("rendered prompt missing path")
	}
}

// TestSwarmPrompt_Base64Input verifies that a base64-encoded HTTP request
// (as exported from Burp Suite) produces the correct prompt.
func TestSwarmPrompt_Base64Input(t *testing.T) {
	rawHTTP := "GET /rest/products/search?q=apple HTTP/1.1\r\nHost: localhost:3000\r\nAuthorization: Bearer eyJtoken123\r\nAccept: application/json\r\n\r\n"
	input := base64.StdEncoding.EncodeToString([]byte(rawHTTP))

	records, err := NormalizeInput(context.Background(), input, "", nil)
	if err != nil {
		t.Fatalf("NormalizeInput failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	u, err := records[0].URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}
	targetURL := u.String()

	reqCtx, hostname, opts := buildSwarmPromptContext(records, targetURL, "")

	if hostname != "localhost" {
		t.Errorf("hostname = %q, want %q", hostname, "localhost")
	}
	if !strings.Contains(reqCtx, "GET /rest/products/search?q=apple") {
		t.Errorf("request context missing request line")
	}

	rendered := renderSwarmTemplate(t, opts)

	if !strings.Contains(rendered, "localhost") {
		t.Errorf("rendered prompt missing hostname")
	}
	if !strings.Contains(rendered, targetURL) {
		t.Errorf("rendered prompt missing target URL")
	}
	if !strings.Contains(rendered, "Authorization: Bearer") {
		t.Errorf("rendered prompt missing Authorization header")
	}
}

// TestSwarmPrompt_VulnTypeFocus verifies that the vulnType parameter is
// injected into the prompt when provided.
func TestSwarmPrompt_VulnTypeFocus(t *testing.T) {
	raw := "GET /api/search?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n"

	records, err := NormalizeInput(context.Background(), raw, InputTypeRaw, nil)
	if err != nil {
		t.Fatalf("NormalizeInput failed: %v", err)
	}

	u, err := records[0].URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}

	_, _, opts := buildSwarmPromptContext(records, u.String(), "SQL Injection")

	rendered := renderSwarmTemplate(t, opts)

	if !strings.Contains(rendered, "SQL Injection") {
		t.Errorf("rendered prompt missing vuln type focus")
	}
	if !strings.Contains(rendered, "focus on") {
		t.Errorf("rendered prompt missing focus instruction for vuln type")
	}
}

// TestSwarmPrompt_NoVulnType verifies that the vuln type section is omitted
// when no vulnType is provided.
func TestSwarmPrompt_NoVulnType(t *testing.T) {
	raw := "GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n"

	records, err := NormalizeInput(context.Background(), raw, InputTypeRaw, nil)
	if err != nil {
		t.Fatalf("NormalizeInput failed: %v", err)
	}

	u, err := records[0].URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}

	_, _, opts := buildSwarmPromptContext(records, u.String(), "")

	rendered := renderSwarmTemplate(t, opts)

	if strings.Contains(rendered, "Vulnerability Focus") {
		t.Errorf("rendered prompt should not contain vuln focus section when empty")
	}
}

// TestSwarmPrompt_POSTWithJSONBody verifies that a POST request with a JSON
// body is correctly represented in the prompt.
func TestSwarmPrompt_POSTWithJSONBody(t *testing.T) {
	raw := "POST /api/v2/orders HTTP/1.1\r\nHost: shop.example.com\r\nContent-Type: application/json\r\nAuthorization: Bearer tok123\r\n\r\n{\"item_id\":42,\"quantity\":1,\"coupon\":\"SAVE10\"}"

	records, err := NormalizeInput(context.Background(), raw, InputTypeRaw, nil)
	if err != nil {
		t.Fatalf("NormalizeInput failed: %v", err)
	}

	u, err := records[0].URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}

	reqCtx, hostname, opts := buildSwarmPromptContext(records, u.String(), "")

	if hostname != "shop.example.com" {
		t.Errorf("hostname = %q, want %q", hostname, "shop.example.com")
	}
	if !strings.Contains(reqCtx, "POST /api/v2/orders") {
		t.Errorf("request context missing POST request line")
	}
	if !strings.Contains(reqCtx, `"coupon":"SAVE10"`) {
		t.Errorf("request context missing JSON body")
	}

	rendered := renderSwarmTemplate(t, opts)

	if !strings.Contains(rendered, "shop.example.com") {
		t.Errorf("rendered prompt missing hostname")
	}
	if !strings.Contains(rendered, "POST /api/v2/orders") {
		t.Errorf("rendered prompt missing request line")
	}
	if !strings.Contains(rendered, `"coupon":"SAVE10"`) {
		t.Errorf("rendered prompt missing JSON body content")
	}
}

// TestSwarmPrompt_GatherContext_NoSourcePath verifies that gatherContext
// correctly populates TargetURL, Hostname, and Extra when SourcePath is empty.
// This was the root cause of the original bug.
func TestSwarmPrompt_GatherContext_NoSourcePath(t *testing.T) {
	opts := Options{
		TargetURL: "http://localhost:3000/rest/products/search?q=apple",
		Hostname:  "localhost:3000",
		Extra: map[string]string{
			"RequestContext": "### Request 1\n\n```http\nGET /rest/products/search?q=apple HTTP/1.1\nHost: localhost:3000\n```\n",
			"VulnType":       "XSS",
		},
	}

	// Create a minimal engine (no settings/repo needed for gatherContext)
	e := &Engine{}
	data, err := e.gatherContext(context.Background(), opts, nil)
	if err != nil {
		t.Fatalf("gatherContext failed: %v", err)
	}

	if data.TargetURL != opts.TargetURL {
		t.Errorf("TargetURL = %q, want %q", data.TargetURL, opts.TargetURL)
	}
	if data.Hostname != opts.Hostname {
		t.Errorf("Hostname = %q, want %q", data.Hostname, opts.Hostname)
	}
	if data.Extra["RequestContext"] != opts.Extra["RequestContext"] {
		t.Errorf("Extra[RequestContext] not propagated")
	}
	if data.Extra["VulnType"] != "XSS" {
		t.Errorf("Extra[VulnType] = %q, want %q", data.Extra["VulnType"], "XSS")
	}
}

// TestSwarmPrompt_GatherContext_HostnameFromURL verifies that Hostname is
// derived from TargetURL when not explicitly set.
func TestSwarmPrompt_GatherContext_HostnameFromURL(t *testing.T) {
	opts := Options{
		TargetURL: "https://api.example.com:8443/v1/users",
		// Hostname intentionally left empty
	}

	e := &Engine{}
	data, err := e.gatherContext(context.Background(), opts, nil)
	if err != nil {
		t.Fatalf("gatherContext failed: %v", err)
	}

	// hostnameFromURL uses url.Hostname() which strips the port
	if data.Hostname != "api.example.com" {
		t.Errorf("Hostname = %q, want %q", data.Hostname, "api.example.com")
	}
}

// TestSwarmPrompt_MultipleRawRequests verifies that multiple requests are
// separated correctly in the prompt context.
func TestSwarmPrompt_MultipleRawRequests(t *testing.T) {
	inputs := []string{
		"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"POST /api/users HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\"}",
	}

	var allRecords []*httpmsg.HttpRequestResponse
	for _, input := range inputs {
		records, err := NormalizeInput(context.Background(), input, InputTypeRaw, nil)
		if err != nil {
			t.Fatalf("NormalizeInput failed: %v", err)
		}
		allRecords = append(allRecords, records...)
	}

	if len(allRecords) != 2 {
		t.Fatalf("expected 2 records, got %d", len(allRecords))
	}

	u, err := allRecords[0].URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}

	reqCtx, _, opts := buildSwarmPromptContext(allRecords, u.String(), "")

	// Verify both requests are present with separators
	if !strings.Contains(reqCtx, "### Request 1") {
		t.Errorf("request context missing Request 1 header")
	}
	if !strings.Contains(reqCtx, "### Request 2") {
		t.Errorf("request context missing Request 2 header")
	}
	if !strings.Contains(reqCtx, "GET /api/users") {
		t.Errorf("request context missing GET request")
	}
	if !strings.Contains(reqCtx, "POST /api/users") {
		t.Errorf("request context missing POST request")
	}
	if !strings.Contains(reqCtx, "---") {
		t.Errorf("request context missing separator between requests")
	}

	rendered := renderSwarmTemplate(t, opts)

	if !strings.Contains(rendered, "### Request 1") {
		t.Errorf("rendered prompt missing Request 1")
	}
	if !strings.Contains(rendered, "### Request 2") {
		t.Errorf("rendered prompt missing Request 2")
	}
}

// renderSwarmTemplate loads the embedded agent-swarm-master template and
// renders it with the given options, simulating gatherContext + RenderTemplate.
func renderSwarmTemplate(t *testing.T, opts Options) string {
	t.Helper()

	// Clear cache to avoid cross-test interference
	tmplCacheMu.Lock()
	clear(tmplCache)
	tmplCacheMu.Unlock()

	// Point HOME away so only embedded templates are found
	t.Setenv("HOME", t.TempDir())

	tmpl, err := LoadTemplate("agent-swarm-master", "")
	if err != nil {
		t.Fatalf("LoadTemplate(agent-swarm-master) failed: %v", err)
	}

	// Build TemplateData the same way gatherContext does
	e := &Engine{}
	data, err := e.gatherContext(context.Background(), opts, nil)
	if err != nil {
		t.Fatalf("gatherContext failed: %v", err)
	}

	rendered, err := RenderTemplate(tmpl, data)
	if err != nil {
		t.Fatalf("RenderTemplate failed: %v", err)
	}

	// Verify the basic structure is present (sanity check)
	if !strings.Contains(rendered, "## Target") {
		t.Errorf("rendered prompt missing ## Target section")
	}
	if !strings.Contains(rendered, "## HTTP Request/Response Under Test") {
		t.Errorf("rendered prompt missing HTTP Request/Response section")
	}

	return rendered
}
