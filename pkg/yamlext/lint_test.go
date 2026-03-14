package yamlext

import (
	"strings"
	"testing"
)

func TestLintYAML_ValidPassive(t *testing.T) {
	source := `
id: sensitive-header-leak
name: Sensitive Header Leak
type: passive
severity: info
confidence: certain
scope: response
scan_types:
  - per_request

rules:
  - match:
      response_header: X-Powered-By
    finding:
      name: X-Powered-By header exposed
      description: "Server technology revealed"
      matched: "{{matched}}"
      severity: info
`
	result := LintYAML(source, "test.vgm.yaml")
	if result.HasErrors() {
		t.Fatalf("valid passive extension should not have errors, got: %+v", result.Issues)
	}
}

func TestLintYAML_ValidActive(t *testing.T) {
	source := `
id: ssti-check
type: active
severity: high
payloads:
  - "{{7*7}}"
  - "${7*7}"
matchers:
  - type: body
    contains: "49"
`
	result := LintYAML(source, "test.vgm.yaml")
	if result.HasErrors() {
		t.Fatalf("valid active extension should not have errors, got: %+v", result.Issues)
	}
}

func TestLintYAML_ValidPreHook(t *testing.T) {
	source := `
id: add-auth
type: pre_hook
add_headers:
  Authorization: "Bearer token123"
`
	result := LintYAML(source, "test.vgm.yaml")
	if result.HasErrors() {
		t.Fatalf("valid pre_hook should not have errors, got: %+v", result.Issues)
	}
}

func TestLintYAML_ValidPostHook(t *testing.T) {
	source := `
id: critical-tagger
type: post_hook
escalate:
  when_url_contains:
    - payment
    - admin
  tag: CRITICAL
  bump_severity: true
`
	result := LintYAML(source, "test.vgm.yaml")
	if result.HasErrors() {
		t.Fatalf("valid post_hook should not have errors, got: %+v", result.Issues)
	}
}

func TestLintYAML_InvalidYAMLSyntax(t *testing.T) {
	source := `
id: broken
type: active
  invalid indentation here
`
	result := LintYAML(source, "test.vgm.yaml")
	if !result.HasErrors() {
		t.Fatal("expected YAML parse error")
	}
}

func TestLintYAML_MissingType(t *testing.T) {
	source := `
id: no-type
severity: high
`
	result := LintYAML(source, "test.vgm.yaml")
	if !result.HasErrors() {
		t.Fatal("expected error for missing type")
	}
}

func TestLintYAML_InvalidType(t *testing.T) {
	source := `
id: bad-type
type: scanner
`
	result := LintYAML(source, "test.vgm.yaml")
	if !result.HasErrors() {
		t.Fatal("expected error for invalid type")
	}
}

func TestLintYAML_InvalidRegex(t *testing.T) {
	source := `
id: bad-regex
type: passive
severity: info
scope: response
rules:
  - match:
      body_regex: "[invalid(regex"
    finding:
      name: test
`
	result := LintYAML(source, "test.vgm.yaml")
	if !result.HasErrors() {
		t.Fatal("expected error for invalid regex")
	}
	found := false
	for _, iss := range result.Issues {
		if strings.Contains(iss.Message, "invalid regex") {
			found = true
		}
	}
	if !found {
		t.Error("expected regex error message")
	}
}

func TestLintYAML_InvalidMatcherRegex(t *testing.T) {
	source := `
id: bad-matcher-regex
type: active
severity: high
payloads:
  - test
matchers:
  - type: body
    regex: "+++invalid"
`
	result := LintYAML(source, "test.vgm.yaml")
	if !result.HasErrors() {
		t.Fatal("expected error for invalid matcher regex")
	}
}

func TestLintYAML_EmptyPreHook(t *testing.T) {
	source := `
id: empty-hook
type: pre_hook
`
	result := LintYAML(source, "test.vgm.yaml")
	found := false
	for _, iss := range result.Issues {
		if strings.Contains(iss.Message, "won't do anything") {
			found = true
		}
	}
	if !found {
		t.Error("expected warning about empty pre_hook")
	}
}

func TestLintYAML_ActiveNoPayloads(t *testing.T) {
	source := `
id: no-payloads
type: active
severity: medium
`
	result := LintYAML(source, "test.vgm.yaml")
	found := false
	for _, iss := range result.Issues {
		if strings.Contains(iss.Message, "no payloads") {
			found = true
		}
	}
	if !found {
		t.Error("expected warning about missing payloads")
	}
}

func TestLintYAML_InvalidSeverity(t *testing.T) {
	source := `
id: bad-sev
type: active
severity: ultra
payloads:
  - test
matchers:
  - contains: "test"
`
	result := LintYAML(source, "test.vgm.yaml")
	found := false
	for _, iss := range result.Issues {
		if strings.Contains(iss.Message, "unknown severity") {
			found = true
		}
	}
	if !found {
		t.Error("expected warning about unknown severity")
	}
}

func TestLintYAML_HeaderMatcherMissingName(t *testing.T) {
	source := `
id: header-missing-name
type: passive
severity: info
scope: response
matchers:
  - type: header
    contains: "nginx"
`
	result := LintYAML(source, "test.vgm.yaml")
	found := false
	for _, iss := range result.Issues {
		if strings.Contains(iss.Message, "missing 'name'") {
			found = true
		}
	}
	if !found {
		t.Error("expected warning about missing header name")
	}
}

func TestLintYAML_InvalidPassiveScope(t *testing.T) {
	source := `
id: bad-scope
type: passive
severity: info
scope: everything
rules:
  - match:
      body_contains: test
    finding:
      name: test
`
	result := LintYAML(source, "test.vgm.yaml")
	found := false
	for _, iss := range result.Issues {
		if strings.Contains(iss.Message, "unknown scope") {
			found = true
		}
	}
	if !found {
		t.Error("expected warning about invalid scope")
	}
}
