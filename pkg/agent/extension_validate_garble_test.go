package agent

import (
	"strings"
	"testing"
)

func TestIsGarbled_CleanCode(t *testing.T) {
	code := `module.exports = {
  id: "custom-check",
  name: "Custom security check",
  type: "active",
  severity: "high",
  scanTypes: ["per_request"],
  tags: ["agent-generated"],
  scanPerRequest: function(ctx) {
    var resp = vigolium.http.sendRequest(ctx.request);
    if (resp.statusCode === 200) {
      ctx.addFinding("Found issue");
    }
  }
};`
	if isGarbled(code) {
		t.Error("clean code should not be classified as garbled")
	}
}

func TestIsGarbled_MinorSyntaxError(t *testing.T) {
	// Missing comma — fixable, not garbled
	code := `module.exports = {
  id: "custom-check"
  name: "Custom security check",
  type: "active",
  severity: "high",
  scanTypes: ["per_request"],
};`
	if isGarbled(code) {
		t.Error("minor syntax error should not be classified as garbled")
	}
}

func TestIsGarbled_InterleavedFields(t *testing.T) {
	// Real example from user's lint output
	code := `module..pubexports = {
  id:easure-bypass",
   "agent-lfi-dataklist bypass inname: "LFI bloc POST /dataerasure layout param (encryptionkeys traversal)",
  type: "active",
  severity: "high",`
	if !isGarbled(code) {
		t.Error("interleaved code should be classified as garbled")
	}
}

func TestIsGarbled_MergedIdentifiers(t *testing.T) {
	code := `module.exports = {
  id: "agent-disclosure-ftp-listing",U
  name: "nauthenticated directory listing at /ftp (serveIndex enabled)",
  type: "active",
  scanTypes: ["",`
	if !isGarbled(code) {
		t.Error("code with stray characters and merged text should be garbled")
	}
}

func TestIsGarbled_SevereFieldMixing(t *testing.T) {
	code := `module.exports = {
  id-pubkey",
  name: "agent-disclosure-jwt public key exposed: "RS256 JWT at /encryptionkeys/jwt.pub",
  type: "active",`
	if !isGarbled(code) {
		t.Error("code with field mixing should be garbled")
	}
}

func TestIsGarbled_MultipleMergedValues(t *testing.T) {
	code := `module.exports = {
  id: "agent-disclosure-metrics",
  name: "Unauthenticated at /metrics",
  type Prometheus metrics endpoint: "active",
  severity: "low",
  scanTypes: ["per_request"],`
	if !isGarbled(code) {
		t.Error("code with values merged into keys should be garbled")
	}
}

func TestIsGarbled_Empty(t *testing.T) {
	if !isGarbled("") {
		t.Error("empty code should be classified as garbled")
	}
}

func TestIsGarbledLine_DoubleDot(t *testing.T) {
	if !isGarbledLine("module..pubexports = {") {
		t.Error("double dot should be garbled")
	}
}

func TestIsGarbledLine_SpreadOperator(t *testing.T) {
	// Triple dot (spread) is valid JS, should NOT be garbled
	if isGarbledLine("  var merged = {...obj1, ...obj2};") {
		t.Error("spread operator should not be garbled")
	}
}

func TestIsGarbledLine_NormalLines(t *testing.T) {
	normals := []string{
		`  id: "custom-check",`,
		`  name: "SQL Injection in /api/users",`,
		`  type: "active",`,
		`  severity: "high",`,
		`  scanTypes: ["per_request"],`,
		`  tags: ["sqli", "agent-generated"],`,
		`module.exports = {`,
		`};`,
		``,
	}
	for _, line := range normals {
		if isGarbledLine(line) {
			t.Errorf("normal line should not be garbled: %q", line)
		}
	}
}

func TestExtractIntentFromGarbled(t *testing.T) {
	code := `module.exports = {
  id: "agent-sqli-search-error",
  name: "SQL Injection in /rest/products/search q param (error-based)",
  type: "active",
  scanTypes: ["per_requestseverity: "high",`

	intent := extractIntentFromGarbled(code, "agent-sqli-search-error.js", "Detects SQL injection")
	if !strings.Contains(intent, "agent-sqli-search-error") {
		t.Error("should extract ID from garbled code")
	}
	if !strings.Contains(intent, "SQL Injection") {
		t.Error("should extract name/description from garbled code")
	}
	if !strings.Contains(intent, "Detects SQL injection") {
		t.Error("should include reason")
	}
}

func TestExtractGarbledField(t *testing.T) {
	code := `module.exports = {
  id: "agent-disclosure-metrics",
  name: "Unauthenticated at /metrics",
  type: "active",`

	id := extractGarbledField(code, "id")
	if id != "agent-disclosure-metrics" {
		t.Errorf("expected 'agent-disclosure-metrics', got %q", id)
	}

	name := extractGarbledField(code, "name")
	if name != "Unauthenticated at /metrics" {
		t.Errorf("expected 'Unauthenticated at /metrics', got %q", name)
	}
}

func TestBuildRegeneratePrompt_HasContext(t *testing.T) {
	inv := InvalidExtension{
		Extension: GeneratedExtension{
			Filename: "agent-sqli-check.js",
			Code:     "garbled code here",
			Reason:   "Detect SQL injection",
		},
	}
	cfg := RepairConfig{
		TargetURL:  "http://localhost:3000",
		FocusAreas: []string{"SQL injection", "auth bypass"},
		ModuleTags: []string{"sqli", "auth"},
	}

	prompt := buildRegeneratePrompt(inv, cfg)
	if !strings.Contains(prompt, "REGENERATE") {
		t.Error("regenerate prompt should mention REGENERATE")
	}
	if !strings.Contains(prompt, "http://localhost:3000") {
		t.Error("regenerate prompt should include target URL")
	}
	if !strings.Contains(prompt, "SQL injection") {
		t.Error("regenerate prompt should include focus areas")
	}
	if !strings.Contains(prompt, "module.exports") {
		t.Error("regenerate prompt should include extension template")
	}
}
