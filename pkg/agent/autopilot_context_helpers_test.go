package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/vigolium/vigolium/pkg/audit"
)

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "   ", "x", "y"); got != "x" {
		t.Errorf("firstNonEmpty = %q, want x", got)
	}
	if got := firstNonEmpty("", "  "); got != "" {
		t.Errorf("all-blank should yield empty, got %q", got)
	}
}

func TestCompactStrings(t *testing.T) {
	got := compactStrings([]string{"a", " a ", "", "  ", "b", "a"})
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("compactStrings = %v, want %v", got, want)
	}
}

func TestInferFindingAction(t *testing.T) {
	cases := map[string]string{
		"critical": "exploit",
		"HIGH":     "exploit",
		"medium":   "investigate",
		"low":      "ignore",
		"info":     "ignore",
		"":         "ignore",
	}
	for sev, want := range cases {
		f := &audit.Finding{Severity: sev}
		if got := inferFindingAction(f); got != want {
			t.Errorf("inferFindingAction(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestInferFindingKind(t *testing.T) {
	cases := map[string]string{
		"Reflected XSS in search":    "xss",
		"SQLi via id parameter":      "sqli",
		"IDOR on /users/{id}":        "idor",
		"Broken auth flow":           "auth",
		"Server-Side Request (SSRF)": "ssrf",
		"nothing relevant here":      "",
	}
	for text, want := range cases {
		if got := inferFindingKind(text); got != want {
			t.Errorf("inferFindingKind(%q) = %q, want %q", text, got, want)
		}
	}
}

func TestInferRouteFromFinding(t *testing.T) {
	t.Run("from locations", func(t *testing.T) {
		f := &audit.Finding{Locations: []string{"handlers.go:/api/users"}}
		if got := inferRouteFromFinding(f); got != "/api/users" {
			t.Errorf("route = %q, want /api/users", got)
		}
	})

	t.Run("from body when no location route", func(t *testing.T) {
		f := &audit.Finding{Body: "vulnerable endpoint /admin/panel. exploit it."}
		if got := inferRouteFromFinding(f); got != "/admin/panel." && got != "/admin/panel" {
			t.Errorf("route = %q, want /admin/panel", got)
		}
	})

	t.Run("none found", func(t *testing.T) {
		f := &audit.Finding{Body: "no slashes at start of any token"}
		if got := inferRouteFromFinding(f); got != "" {
			t.Errorf("route = %q, want empty", got)
		}
	})
}

func TestContainsProtectedHint(t *testing.T) {
	withHint := []AutopilotFindingSummary{
		{Title: "Public page"},
		{Title: "Login bypass", Route: "/auth/session"},
	}
	if !containsProtectedHint(withHint) {
		t.Error("expected protected hint from auth/login route")
	}

	noHint := []AutopilotFindingSummary{{Title: "Open redirect", Route: "/go"}}
	if containsProtectedHint(noHint) {
		t.Error("did not expect protected hint")
	}
}

func TestHasEvidence(t *testing.T) {
	evDir := t.TempDir()

	t.Run("inline evidence field", func(t *testing.T) {
		if !hasEvidence(map[string]any{"evidence": "PoC here"}, evDir) {
			t.Error("expected evidence detected from inline field")
		}
	})

	t.Run("evidence_files array", func(t *testing.T) {
		item := map[string]any{"evidence_files": []any{"a.txt"}}
		if !hasEvidence(item, evDir) {
			t.Error("expected evidence detected from evidence_files")
		}
	})

	t.Run("falls back to non-empty evidence dir", func(t *testing.T) {
		// Write a file into evDir so the directory scan reports evidence.
		if err := os.WriteFile(filepath.Join(evDir, "ev.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if !hasEvidence(map[string]any{"title": "no inline ev"}, evDir) {
			t.Error("expected evidence from non-empty dir fallback")
		}
	})

	t.Run("empty dir + no inline evidence", func(t *testing.T) {
		empty := t.TempDir()
		if hasEvidence(map[string]any{"title": "nothing"}, empty) {
			t.Error("did not expect evidence with empty dir and no fields")
		}
	})
}

func TestCountEvidenceBackedFindings(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		n, note := countEvidenceBackedFindings("", "")
		if n != 0 || note != "" {
			t.Errorf("empty path => (0,\"\"), got (%d,%q)", n, note)
		}
	})

	t.Run("missing artifact", func(t *testing.T) {
		n, note := countEvidenceBackedFindings(filepath.Join(t.TempDir(), "nope.json"), "")
		if n != 0 || note == "" {
			t.Errorf("missing file should report a note, got (%d,%q)", n, note)
		}
	})

	t.Run("counts array entries with no evidence requirement", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "findings.json")
		arr := []map[string]any{{"title": "a"}, {"title": "b"}}
		data, _ := json.Marshal(arr)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		// evidenceDir empty → count all entries.
		n, _ := countEvidenceBackedFindings(p, "")
		if n != 2 {
			t.Errorf("count = %d, want 2", n)
		}
	})

	t.Run("wrapper object form", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "findings.json")
		wrapper := map[string]any{"findings": []map[string]any{{"title": "a", "evidence": "poc"}}}
		data, _ := json.Marshal(wrapper)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		evDir := t.TempDir() // empty dir, so only inline evidence counts
		n, _ := countEvidenceBackedFindings(p, evDir)
		if n != 1 {
			t.Errorf("count = %d, want 1 (inline evidence)", n)
		}
	})

	t.Run("unparseable artifact", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(p, []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		n, note := countEvidenceBackedFindings(p, "")
		if n != 0 || note == "" {
			t.Errorf("unparseable should report (0, note), got (%d,%q)", n, note)
		}
	})
}
