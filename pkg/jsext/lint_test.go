package jsext

import (
	"strings"
	"testing"
)

func TestLintSource_SyntaxError(t *testing.T) {
	source := `var x = {
		foo: "bar"
		baz: "qux"
	}`

	result := LintSource(source, "test.js")
	if !result.HasErrors() {
		t.Fatal("expected syntax error")
	}
	if len(result.Issues) == 0 {
		t.Fatal("expected at least one issue")
	}
	issue := result.Issues[0]
	if issue.Severity != LintError {
		t.Errorf("expected error severity, got %s", issue.Severity)
	}
	if issue.Line == 0 {
		t.Error("expected line number in syntax error")
	}
}

func TestLintSource_UnknownAPI(t *testing.T) {
	source := `
var x = vigolium.log.info("hello");
var y = vigolium.utils.nonExistentFunc("test");
var z = vigolium.fakeNamespace.something();
`

	result := LintSource(source, "test.js")
	if result.HasErrors() {
		t.Fatal("did not expect hard errors")
	}

	// Should have warnings for unknown APIs
	var unknownMessages []string
	for _, issue := range result.Issues {
		if strings.Contains(issue.Message, "unknown API reference") {
			unknownMessages = append(unknownMessages, issue.Message)
		}
	}

	if len(unknownMessages) == 0 {
		t.Fatal("expected warnings for unknown API calls")
	}

	// vigolium.log.info should NOT be flagged
	for _, msg := range unknownMessages {
		if strings.Contains(msg, "vigolium.log.info") {
			t.Error("vigolium.log.info should not be flagged as unknown")
		}
	}

	// vigolium.utils.nonExistentFunc should be flagged
	found := false
	for _, msg := range unknownMessages {
		if strings.Contains(msg, "nonExistentFunc") {
			found = true
		}
	}
	if !found {
		t.Error("vigolium.utils.nonExistentFunc should be flagged as unknown")
	}
}

func TestLintSource_ValidExtension(t *testing.T) {
	source := `
module.exports = {
	id: "test-ext",
	name: "Test Extension",
	type: "passive",
	severity: "info",
	scope: "response",
	scanTypes: ["per_request"],
	scanPerRequest: function(ctx) {
		vigolium.log.info("scanning");
		return null;
	}
};
`
	result := LintSource(source, "test-ext.js")
	if result.HasErrors() {
		t.Fatal("valid extension should not have errors")
	}
	// Should have no warnings either
	for _, issue := range result.Issues {
		t.Errorf("unexpected issue: %s: %s", issue.Severity, issue.Message)
	}
}

func TestLintSource_MissingHandler(t *testing.T) {
	source := `
module.exports = {
	id: "test-ext",
	type: "active",
	severity: "high",
	scanTypes: ["per_insertion_point"],
};
`
	result := LintSource(source, "test-ext.js")
	found := false
	for _, issue := range result.Issues {
		if strings.Contains(issue.Message, "scanPerInsertionPoint") {
			found = true
		}
	}
	if !found {
		t.Error("expected warning about missing scanPerInsertionPoint handler")
	}
}

func TestLintSource_InvalidSeverity(t *testing.T) {
	source := `
module.exports = {
	id: "test-ext",
	type: "active",
	severity: "superduper",
	scanPerRequest: function(ctx) { return null; }
};
`
	result := LintSource(source, "test-ext.js")
	found := false
	for _, issue := range result.Issues {
		if strings.Contains(issue.Message, "unknown severity") {
			found = true
		}
	}
	if !found {
		t.Error("expected warning about unknown severity")
	}
}

func TestLintSource_PlainScript(t *testing.T) {
	// A plain script (not an extension) should lint cleanly
	source := `var x = 1 + 2;`
	result := LintSource(source, "script.js")
	if result.HasErrors() {
		t.Fatal("plain script should not have errors")
	}
}

func TestLintSource_KnownAPIsNotFlagged(t *testing.T) {
	source := `
var r = vigolium.utils.base64Encode("hello");
var h = vigolium.utils.sha256("test");
var m = vigolium.utils.md5("test");
vigolium.log.info("test");
vigolium.log.warn("test");
vigolium.log.error("test");
vigolium.log.debug("test");
`
	result := LintSource(source, "test.js")
	for _, issue := range result.Issues {
		if strings.Contains(issue.Message, "unknown API") {
			t.Errorf("known API should not be flagged: %s", issue.Message)
		}
	}
}
