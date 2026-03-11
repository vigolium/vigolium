package agent

import (
	"strings"
	"testing"
)

func TestGenerateQuickCheckPerInsertionPoint(t *testing.T) {
	qc := QuickCheck{
		ID:       "ssti-jinja2",
		Severity: "high",
		Scan:     "per_insertion_point",
		Payloads: []string{"{{7*7}}", "${7*7}"},
		Match:    QuickCheckMatch{BodyContains: "49"},
	}

	exts := GenerateQuickCheckExtensions([]QuickCheck{qc})
	if len(exts) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(exts))
	}

	ext := exts[0]
	if ext.Filename != "qc-ssti-jinja2.js" {
		t.Errorf("expected filename 'qc-ssti-jinja2.js', got %q", ext.Filename)
	}
	if !strings.Contains(ext.Code, `"qc-ssti-jinja2"`) {
		t.Error("expected module id in generated code")
	}
	if !strings.Contains(ext.Code, "scanPerInsertionPoint") {
		t.Error("expected scanPerInsertionPoint function")
	}
	if !strings.Contains(ext.Code, `"per_insertion_point"`) {
		t.Error("expected per_insertion_point scan type")
	}
	if !strings.Contains(ext.Code, `"high"`) {
		t.Error("expected high severity")
	}
	if !strings.Contains(ext.Code, "insertion.buildRequest") {
		t.Error("expected insertion.buildRequest call")
	}
	if !strings.Contains(ext.Code, `resp.body.indexOf("49") !== -1`) {
		t.Error("expected body_contains match condition")
	}
}

func TestGenerateQuickCheckPerRequest(t *testing.T) {
	qc := QuickCheck{
		ID:   "debug-endpoint",
		Scan: "per_request",
		Requests: []QuickCheckRequest{
			{Method: "GET", Path: "/.env"},
			{Method: "GET", Path: "/debug/vars"},
		},
		Match: QuickCheckMatch{Status: 200, BodyRegex: "(DB_PASSWORD|SECRET_KEY)"},
	}

	exts := GenerateQuickCheckExtensions([]QuickCheck{qc})
	if len(exts) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(exts))
	}

	ext := exts[0]
	if !strings.Contains(ext.Code, "scanPerRequest") {
		t.Error("expected scanPerRequest function")
	}
	if !strings.Contains(ext.Code, `"per_request"`) {
		t.Error("expected per_request scan type")
	}
	if !strings.Contains(ext.Code, "/.env") {
		t.Error("expected /.env path in requests array")
	}
	if !strings.Contains(ext.Code, "resp.status === 200") {
		t.Error("expected status match condition")
	}
	if !strings.Contains(ext.Code, "vigolium.utils.regexMatch") {
		t.Error("expected regex match condition")
	}
}

func TestGenerateQuickCheckPerHost(t *testing.T) {
	qc := QuickCheck{
		ID:   "actuator-check",
		Scan: "per_host",
		Requests: []QuickCheckRequest{
			{Method: "GET", Path: "/actuator/env"},
		},
		Match: QuickCheckMatch{BodyContains: "spring.datasource"},
	}

	exts := GenerateQuickCheckExtensions([]QuickCheck{qc})
	if len(exts) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(exts))
	}

	if !strings.Contains(exts[0].Code, "scanPerHost") {
		t.Error("expected scanPerHost function")
	}
}

func TestGenerateQuickCheckDefaultSeverity(t *testing.T) {
	qc := QuickCheck{
		ID:       "test-check",
		Scan:     "per_insertion_point",
		Payloads: []string{"test"},
		Match:    QuickCheckMatch{BodyContains: "test"},
	}

	exts := GenerateQuickCheckExtensions([]QuickCheck{qc})
	if len(exts) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(exts))
	}

	if !strings.Contains(exts[0].Code, `severity: "medium"`) {
		t.Error("expected default severity 'medium'")
	}
}

func TestGenerateQuickCheckMultipleMatchConditions(t *testing.T) {
	qc := QuickCheck{
		ID:       "multi-match",
		Scan:     "per_insertion_point",
		Payloads: []string{"test"},
		Match: QuickCheckMatch{
			BodyContains:   "error",
			Status:         500,
			HeaderContains: "X-Debug",
		},
	}

	exts := GenerateQuickCheckExtensions([]QuickCheck{qc})
	if len(exts) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(exts))
	}

	code := exts[0].Code
	if !strings.Contains(code, `resp.body.indexOf("error") !== -1`) {
		t.Error("expected body_contains condition")
	}
	if !strings.Contains(code, "resp.status === 500") {
		t.Error("expected status condition")
	}
	if !strings.Contains(code, `JSON.stringify(resp.headers).indexOf("X-Debug") !== -1`) {
		t.Error("expected header_contains condition")
	}
	// Conditions should be OR'd
	if !strings.Contains(code, " || ") {
		t.Error("expected OR logic between conditions")
	}
}

func TestGenerateQuickCheckNoMatchReturnsError(t *testing.T) {
	qc := QuickCheck{
		ID:       "no-match",
		Scan:     "per_insertion_point",
		Payloads: []string{"test"},
		Match:    QuickCheckMatch{},
	}

	exts := GenerateQuickCheckExtensions([]QuickCheck{qc})
	if len(exts) != 0 {
		t.Errorf("expected 0 extensions for empty match, got %d", len(exts))
	}
}

func TestGenerateQuickCheckInvalidScanType(t *testing.T) {
	qc := QuickCheck{
		ID:       "bad-scan",
		Scan:     "invalid",
		Payloads: []string{"test"},
		Match:    QuickCheckMatch{BodyContains: "x"},
	}

	exts := GenerateQuickCheckExtensions([]QuickCheck{qc})
	if len(exts) != 0 {
		t.Errorf("expected 0 extensions for invalid scan type, got %d", len(exts))
	}
}

func TestGenerateQuickCheckRequestWithHeaders(t *testing.T) {
	qc := QuickCheck{
		ID:   "auth-bypass",
		Scan: "per_request",
		Requests: []QuickCheckRequest{
			{Method: "GET", Path: "/admin", Headers: map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		},
		Match: QuickCheckMatch{Status: 200},
	}

	exts := GenerateQuickCheckExtensions([]QuickCheck{qc})
	if len(exts) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(exts))
	}

	if !strings.Contains(exts[0].Code, "requests[i].headers") {
		t.Error("expected headers handling in generated code")
	}
}

func TestGenerateSnippetPerRequest(t *testing.T) {
	snip := Snippet{
		ID:       "idor-check",
		Severity: "high",
		Scan:     "per_request",
		Body:     "var related = vigolium.db.records.getRelated(ctx.record.uuid);\nreturn null;",
	}

	exts := GenerateSnippetExtensions([]Snippet{snip})
	if len(exts) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(exts))
	}

	ext := exts[0]
	if ext.Filename != "snip-idor-check.js" {
		t.Errorf("expected filename 'snip-idor-check.js', got %q", ext.Filename)
	}
	if !strings.Contains(ext.Code, `"snip-idor-check"`) {
		t.Error("expected module id in generated code")
	}
	if !strings.Contains(ext.Code, "scanPerRequest") {
		t.Error("expected scanPerRequest function")
	}
	if !strings.Contains(ext.Code, "function(ctx)") {
		t.Error("expected ctx-only function signature for per_request")
	}
	if !strings.Contains(ext.Code, "vigolium.db.records.getRelated") {
		t.Error("expected snippet body in generated code")
	}
}

func TestGenerateSnippetPerInsertionPoint(t *testing.T) {
	snip := Snippet{
		ID:   "custom-inject",
		Scan: "per_insertion_point",
		Body: "var req = insertion.buildRequest('test');\nvar resp = vigolium.http.send(req);\nreturn null;",
	}

	exts := GenerateSnippetExtensions([]Snippet{snip})
	if len(exts) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(exts))
	}

	code := exts[0].Code
	if !strings.Contains(code, "scanPerInsertionPoint") {
		t.Error("expected scanPerInsertionPoint function")
	}
	if !strings.Contains(code, "function(ctx, insertion)") {
		t.Error("expected ctx+insertion function signature for per_insertion_point")
	}
}

func TestGenerateSnippetDefaultSeverity(t *testing.T) {
	snip := Snippet{
		ID:   "test",
		Scan: "per_request",
		Body: "return null;",
	}

	exts := GenerateSnippetExtensions([]Snippet{snip})
	if len(exts) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(exts))
	}

	if !strings.Contains(exts[0].Code, `severity: "medium"`) {
		t.Error("expected default severity 'medium'")
	}
}

func TestGenerateSnippetEmptyBody(t *testing.T) {
	snip := Snippet{
		ID:   "empty",
		Scan: "per_request",
		Body: "",
	}

	exts := GenerateSnippetExtensions([]Snippet{snip})
	if len(exts) != 0 {
		t.Errorf("expected 0 extensions for empty body, got %d", len(exts))
	}
}

func TestGenerateSnippetMissingID(t *testing.T) {
	snip := Snippet{
		Scan: "per_request",
		Body: "return null;",
	}

	exts := GenerateSnippetExtensions([]Snippet{snip})
	if len(exts) != 0 {
		t.Errorf("expected 0 extensions for missing id, got %d", len(exts))
	}
}
