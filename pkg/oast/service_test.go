package oast

import (
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestExtractNonce(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"abc123nonce456.oast.pro", "abc123nonce456"},
		{"correlationid.server.example.com", "correlationid"},
		{"nodot", ""},
		{"", ""},
		{".leading-dot", ""},
	}

	for _, tt := range tests {
		got := extractNonce(tt.url)
		if got != tt.want {
			t.Errorf("extractNonce(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestNewDisabledConfig(t *testing.T) {
	cfg := &config.OASTConfig{Enabled: false}
	svc, err := New(cfg, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc != nil {
		t.Fatal("expected nil service when disabled")
	}
}

func TestNewNilConfig(t *testing.T) {
	svc, err := New(nil, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc != nil {
		t.Fatal("expected nil service for nil config")
	}
}

func TestEnabledNilService(t *testing.T) {
	var svc *Service
	if svc.Enabled() {
		t.Fatal("nil service should not be enabled")
	}
}

func TestGenerateURLNilService(t *testing.T) {
	var svc *Service
	url := svc.GenerateURL("http://target.com", "url", "param", "mod-id", "hash123")
	if url != "" {
		t.Fatalf("expected empty URL from nil service, got %q", url)
	}
}

func TestFlushCloseNilService(t *testing.T) {
	// Should not panic on nil receiver
	var svc *Service
	svc.Flush()
	svc.Close()
	svc.Start()
}

func TestSetRequestUUIDResolverNilService(t *testing.T) {
	// Should not panic on nil receiver
	var svc *Service
	svc.SetRequestUUIDResolver(func(hash string) string { return "uuid-123" })
}

func TestSaveFindingNoRepo(t *testing.T) {
	// saveFinding with nil repo should not panic
	svc := &Service{}
	svc.saveFinding(nil, "hash123")
}

func TestSaveFindingEmptyHash(t *testing.T) {
	// saveFinding with empty request hash should be a no-op
	svc := &Service{repo: nil}
	svc.saveFinding(nil, "")
}

func extractedValue(results []string, prefix string) (string, bool) {
	for _, r := range results {
		if strings.HasPrefix(r, prefix) {
			return strings.TrimPrefix(r, prefix), true
		}
	}
	return "", false
}

// TestEnrichOASTResult verifies an out-of-band finding is made self-tracing: the
// planting request/response are embedded and human-readable anchors (origin
// request, http_record UUID, planted callback URL, callback evidence) are added.
func TestEnrichOASTResult(t *testing.T) {
	interaction := &server.Interaction{
		Protocol:      "http",
		UniqueID:      "nonce123",
		RawRequest:    "GET / HTTP/1.1\r\nHost: nonce123.oast.pro\r\n\r\n",
		RawResponse:   "HTTP/1.1 200 OK\r\n\r\n",
		RemoteAddress: "203.0.113.7",
		Timestamp:     time.Date(2026, 6, 9, 5, 30, 37, 0, time.UTC),
	}
	pctx := PayloadContext{
		TargetURL:     "http://victim.example/css",
		ParameterName: "request-line",
		InjectionType: "routing-ssrf (request-line)",
		ModuleID:      "routing-ssrf",
		RequestHash:   "deadbeef",
		CallbackURL:   "http://nonce123.oast.pro",
	}
	origin := &database.HTTPRecord{
		UUID:        "d85c371d-e536-4ad5-b00c-8204f32ddcfe",
		Method:      "GET",
		URL:         "http://victim.example/css",
		RawRequest:  []byte("GET /css HTTP/1.1\r\nHost: victim.example\r\n\r\n"),
		RawResponse: []byte("HTTP/1.1 200 OK\r\n\r\nbody"),
	}

	sev, desc := classifyInteraction(interaction.Protocol, pctx)
	result := &output.ResultEvent{
		ModuleID: pctx.ModuleID,
		Info:     output.Info{Description: desc, Severity: sev},
		ExtractedResults: []string{
			"protocol=" + interaction.Protocol,
			"oast_id=" + interaction.UniqueID,
			"remote_addr=" + interaction.RemoteAddress,
		},
	}

	enrichOASTResult(result, interaction, pctx, origin)

	// The planting request is embedded with the request-line payload re-applied,
	// so the panel shows where the callback URL was planted — not the bare
	// original. The original Host header (the victim) is preserved.
	if !strings.Contains(result.Request, "GET http://nonce123.oast.pro/ HTTP/1.1") {
		t.Errorf("Request missing reconstructed request-line payload: got %q", result.Request)
	}
	if !strings.Contains(result.Request, "Host: victim.example") {
		t.Errorf("Request dropped the victim Host header: got %q", result.Request)
	}
	if result.Response != string(origin.RawResponse) {
		t.Errorf("Response not embedded: got %q", result.Response)
	}

	// The planted payload + injection point are stated explicitly.
	if v, ok := extractedValue(result.ExtractedResults, "injected_payload="); !ok || v != "http://nonce123.oast.pro/ (request-line)" {
		t.Errorf("injected_payload anchor missing/wrong: %q ok=%v", v, ok)
	}

	// Trace anchors are present in extracted-results.
	if v, ok := extractedValue(result.ExtractedResults, "http_record="); !ok || v != origin.UUID {
		t.Errorf("http_record anchor missing/wrong: %q ok=%v", v, ok)
	}
	if v, ok := extractedValue(result.ExtractedResults, "callback_url="); !ok || v != pctx.CallbackURL {
		t.Errorf("callback_url anchor missing/wrong: %q ok=%v", v, ok)
	}
	if v, ok := extractedValue(result.ExtractedResults, "origin_request="); !ok || v != "GET http://victim.example/css" {
		t.Errorf("origin_request anchor missing/wrong: %q ok=%v", v, ok)
	}
	if _, ok := extractedValue(result.ExtractedResults, "interacted_at="); !ok {
		t.Error("interacted_at anchor missing")
	}

	// Description is self-describing in plain-text outputs.
	if !strings.Contains(result.Info.Description, origin.UUID) ||
		!strings.Contains(result.Info.Description, "GET http://victim.example/css") {
		t.Errorf("description missing origin anchors: %q", result.Info.Description)
	}

	// The out-of-band callback request is retained as evidence.
	if len(result.AdditionalEvidence) == 0 ||
		!strings.Contains(result.AdditionalEvidence[0], "nonce123.oast.pro") {
		t.Errorf("callback evidence missing: %v", result.AdditionalEvidence)
	}
}

// TestPayloadRequest verifies the payload is re-applied at the right injection
// point so the Request panel is never a bare original. Covers the real-world
// bare-host callback (no scheme), header injection, and the parameter fallback.
func TestPayloadRequest(t *testing.T) {
	raw := []byte("GET /foo?a=1 HTTP/1.1\r\nHost: victim.example\r\nAccept: */*\r\n\r\n")

	// Request-line SSRF with a bare-host callback (as interactsh emits it) over
	// https → absolute-URI target on the request line, Host header untouched.
	rl := payloadRequest(raw, PayloadContext{
		ParameterName: "request-line",
		InjectionType: "routing-ssrf (request-line)",
		CallbackURL:   "abc123.oast.vigolium.com",
	}, "https")
	if !strings.HasPrefix(rl, "GET https://abc123.oast.vigolium.com/ HTTP/1.1\r\n") {
		t.Errorf("request-line reconstruction wrong: %q", rl)
	}
	if !strings.Contains(rl, "Host: victim.example") || !strings.Contains(rl, "Accept: */*") {
		t.Errorf("request-line reconstruction dropped headers: %q", rl)
	}

	// Header injection → the named header carries the callback URL.
	hdr := payloadRequest(raw, PayloadContext{
		ParameterName: "X-Forwarded-Host",
		InjectionType: "header",
		CallbackURL:   "abc123.oast.vigolium.com",
	}, "http")
	if !strings.Contains(hdr, "X-Forwarded-Host: http://abc123.oast.vigolium.com") {
		t.Errorf("header reconstruction missing payload: %q", hdr)
	}

	// Parameter injection is not reconstructed (the wire form is unknown) — the
	// original request is returned unchanged.
	param := payloadRequest(raw, PayloadContext{
		ParameterName: "url",
		InjectionType: "parameter",
		CallbackURL:   "abc123.oast.vigolium.com",
	}, "http")
	if param != string(raw) {
		t.Errorf("parameter injection should return original request, got: %q", param)
	}
}

// TestEnrichOASTResultNoOrigin verifies enrichment degrades gracefully when the
// originating record could not be recovered (e.g. a fixed-URL OAST callback).
func TestEnrichOASTResultNoOrigin(t *testing.T) {
	interaction := &server.Interaction{Protocol: "dns", UniqueID: "n", RemoteAddress: "198.51.100.4"}
	pctx := PayloadContext{InjectionType: "parameter", CallbackURL: "http://n.oast.pro"}
	result := &output.ResultEvent{Info: output.Info{Description: "base"}}

	enrichOASTResult(result, interaction, pctx, nil)

	if result.Request != "" || result.Response != "" {
		t.Error("expected no embedded request/response without an origin record")
	}
	if _, ok := extractedValue(result.ExtractedResults, "http_record="); ok {
		t.Error("did not expect an http_record anchor without an origin record")
	}
	if v, ok := extractedValue(result.ExtractedResults, "callback_url="); !ok || v != pctx.CallbackURL {
		t.Errorf("callback_url anchor should still be present: %q ok=%v", v, ok)
	}
}

func TestClassifyInteraction(t *testing.T) {
	pctx := PayloadContext{
		TargetURL:     "http://target.com",
		ParameterName: "url",
		InjectionType: "parameter",
	}

	tests := []struct {
		protocol    string
		wantHighSev bool // true = High, false = not High
	}{
		{"http", true},
		{"https", true},
		{"HTTP", true},
		{"dns", false},
		{"smtp", false},
	}

	for _, tt := range tests {
		sev, desc := classifyInteraction(tt.protocol, pctx)
		if tt.wantHighSev && sev.String() != "high" {
			t.Errorf("classifyInteraction(%q) severity = %s, want high; desc: %s", tt.protocol, sev, desc)
		}
		if !tt.wantHighSev && sev.String() == "high" {
			t.Errorf("classifyInteraction(%q) severity = high, expected non-high; desc: %s", tt.protocol, desc)
		}
		if desc == "" {
			t.Errorf("classifyInteraction(%q) returned empty description", tt.protocol)
		}
	}
}

// TestClassifyInteractionHostRoutingInfo locks in the host-routing SSRF
// downgrade: request-line manipulation (routing-ssrf) and X-Forwarded-Host
// header injection are reported as informational (often low-impact), while
// generic parameter-based blind SSRF and the other forwarding headers stay high.
func TestClassifyInteractionHostRoutingInfo(t *testing.T) {
	// routing-ssrf (request-line) → Info on any HTTP-family callback.
	routing := PayloadContext{TargetURL: "http://target.com", InjectionType: "request-line", ModuleID: "routing-ssrf"}
	for _, proto := range []string{"http", "https", "HTTPS"} {
		if sev, _ := classifyInteraction(proto, routing); sev.String() != "info" {
			t.Errorf("routing-ssrf classifyInteraction(%q) severity = %s, want info", proto, sev)
		}
	}

	// X-Forwarded-Host header injection → Info (case-insensitive on the name).
	for _, name := range []string{"X-Forwarded-Host", "x-forwarded-host"} {
		xfh := PayloadContext{TargetURL: "http://target.com", InjectionType: "header", ParameterName: name, ModuleID: "oast-probe"}
		if sev, _ := classifyInteraction("http", xfh); sev.String() != "info" {
			t.Errorf("X-Forwarded-Host (%q) classifyInteraction severity = %s, want info", name, sev)
		}
	}

	// Other forwarding headers from the same module must remain high.
	for _, name := range []string{"X-Forwarded-For", "Referer", "Origin"} {
		other := PayloadContext{TargetURL: "http://target.com", InjectionType: "header", ParameterName: name, ModuleID: "oast-probe"}
		if sev, _ := classifyInteraction("http", other); sev.String() != "high" {
			t.Errorf("header %q classifyInteraction severity = %s, want high", name, sev)
		}
	}

	// A different module's parameter-based HTTP callback must remain high.
	generic := PayloadContext{TargetURL: "http://target.com", InjectionType: "parameter", ParameterName: "url", ModuleID: "ssrf-detection"}
	if sev, _ := classifyInteraction("http", generic); sev.String() != "high" {
		t.Errorf("generic SSRF classifyInteraction severity = %s, want high", sev)
	}
}
