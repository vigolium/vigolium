package extensions

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

func TestLintQuickCheck_Valid(t *testing.T) {
	qc := agenttypes.QuickCheck{
		ID:       "ssti-jinja2",
		Severity: "high",
		Scan:     "per_insertion_point",
		Payloads: []string{"{{7*7}}", "${7*7}"},
		Match:    agenttypes.QuickCheckMatch{BodyContains: "49"},
	}
	issues := LintQuickCheck(qc)
	for _, iss := range issues {
		if iss.Severity == "error" {
			t.Errorf("unexpected error: %s", iss.Message)
		}
	}
}

func TestLintQuickCheck_MissingID(t *testing.T) {
	qc := agenttypes.QuickCheck{
		Scan:     "per_request",
		Requests: []agenttypes.QuickCheckRequest{{Path: "/.env"}},
		Match:    agenttypes.QuickCheckMatch{Status: 200},
	}
	issues := LintQuickCheck(qc)
	found := false
	for _, iss := range issues {
		if strings.Contains(iss.Message, "missing required field 'id'") {
			found = true
		}
	}
	if !found {
		t.Error("expected error about missing id")
	}
}

func TestLintQuickCheck_InvalidScan(t *testing.T) {
	qc := agenttypes.QuickCheck{
		ID:   "test",
		Scan: "per_page",
		Match: agenttypes.QuickCheckMatch{BodyContains: "test"},
	}
	issues := LintQuickCheck(qc)
	found := false
	for _, iss := range issues {
		if strings.Contains(iss.Message, "invalid scan type") {
			found = true
		}
	}
	if !found {
		t.Error("expected error about invalid scan type")
	}
}

func TestLintQuickCheck_NoMatchConditions(t *testing.T) {
	qc := agenttypes.QuickCheck{
		ID:       "test",
		Scan:     "per_insertion_point",
		Payloads: []string{"test"},
		Match:    agenttypes.QuickCheckMatch{},
	}
	issues := LintQuickCheck(qc)
	found := false
	for _, iss := range issues {
		if strings.Contains(iss.Message, "no conditions") {
			found = true
		}
	}
	if !found {
		t.Error("expected error about empty match")
	}
}

func TestLintQuickCheck_InvalidRegex(t *testing.T) {
	qc := agenttypes.QuickCheck{
		ID:       "test-regex",
		Scan:     "per_insertion_point",
		Payloads: []string{"test"},
		Match:    agenttypes.QuickCheckMatch{BodyRegex: "[invalid(regex"},
	}
	issues := LintQuickCheck(qc)
	found := false
	for _, iss := range issues {
		if strings.Contains(iss.Message, "invalid regex") {
			found = true
		}
	}
	if !found {
		t.Error("expected error about invalid regex")
	}
}

func TestLintQuickCheck_MissingPayloads(t *testing.T) {
	qc := agenttypes.QuickCheck{
		ID:   "test",
		Scan: "per_insertion_point",
		Match: agenttypes.QuickCheckMatch{BodyContains: "test"},
	}
	issues := LintQuickCheck(qc)
	found := false
	for _, iss := range issues {
		if strings.Contains(iss.Message, "requires 'payloads'") {
			found = true
		}
	}
	if !found {
		t.Error("expected error about missing payloads")
	}
}

func TestLintQuickCheck_MissingRequests(t *testing.T) {
	qc := agenttypes.QuickCheck{
		ID:   "test",
		Scan: "per_host",
		Match: agenttypes.QuickCheckMatch{Status: 200},
	}
	issues := LintQuickCheck(qc)
	found := false
	for _, iss := range issues {
		if strings.Contains(iss.Message, "requires 'requests'") {
			found = true
		}
	}
	if !found {
		t.Error("expected error about missing requests")
	}
}

func TestLintQuickCheck_BadSlugID(t *testing.T) {
	qc := agenttypes.QuickCheck{
		ID:       "SSTI_Jinja2",
		Scan:     "per_insertion_point",
		Payloads: []string{"test"},
		Match:    agenttypes.QuickCheckMatch{BodyContains: "test"},
	}
	issues := LintQuickCheck(qc)
	found := false
	for _, iss := range issues {
		if strings.Contains(iss.Message, "should be lowercase") {
			found = true
		}
	}
	if !found {
		t.Error("expected warning about id format")
	}
}

func TestLintSnippet_Valid(t *testing.T) {
	snip := agenttypes.Snippet{
		ID:       "idor-check",
		Severity: "high",
		Scan:     "per_request",
		Body:     `return null;`,
	}
	issues := LintSnippet(snip)
	for _, iss := range issues {
		if iss.Severity == "error" {
			t.Errorf("unexpected error: %s", iss.Message)
		}
	}
}

func TestLintSnippet_MissingBody(t *testing.T) {
	snip := agenttypes.Snippet{
		ID:   "test",
		Scan: "per_request",
	}
	issues := LintSnippet(snip)
	found := false
	for _, iss := range issues {
		if strings.Contains(iss.Message, "missing required field 'body'") {
			found = true
		}
	}
	if !found {
		t.Error("expected error about missing body")
	}
}

func TestLintSnippet_InvalidBody(t *testing.T) {
	snip := agenttypes.Snippet{
		ID:   "bad-js",
		Scan: "per_request",
		Body: `var x = {{{invalid`,
	}
	issues := LintSnippet(snip)
	found := false
	for _, iss := range issues {
		if strings.Contains(iss.Message, "syntax error") {
			found = true
		}
	}
	if !found {
		t.Error("expected error about JS syntax")
	}
}
