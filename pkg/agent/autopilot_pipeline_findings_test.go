package agent

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/audit"
)

func TestExploitabilityScore(t *testing.T) {
	// Best-case finding: confirmed PoC, promoted, high confidence.
	best := &audit.Finding{
		PoCStatus:  "confirmed",
		Provenance: "",
		Confidence: "high",
	}
	// Worst-case finding: theoretical, draft provenance, low confidence.
	worst := &audit.Finding{
		PoCStatus:  "theoretical",
		Provenance: "draft",
		Confidence: "low",
	}
	bs, ws := exploitabilityScore(best), exploitabilityScore(worst)
	if bs >= ws {
		t.Errorf("best finding should score lower than worst, got best=%d worst=%d", bs, ws)
	}
	if bs != 0 {
		t.Errorf("ideal finding (confirmed + promoted + high) should score 0, got %d", bs)
	}

	// Mid-range: pending PoC dominates other signals when severity ties.
	pending := &audit.Finding{PoCStatus: "pending", Provenance: "", Confidence: "high"}
	theoretical := &audit.Finding{PoCStatus: "theoretical", Provenance: "", Confidence: "high"}
	if exploitabilityScore(pending) >= exploitabilityScore(theoretical) {
		t.Errorf("pending should beat theoretical")
	}
}

func TestFormatFindingsExploitabilityTiebreaker(t *testing.T) {
	// Two findings with identical severity but different exploitability —
	// the confirmed PoC must appear first in the rendered output.
	findings := []*audit.Finding{
		{
			FindingID:  "P7-001",
			Title:      "Theoretical SQLi",
			Severity:   "high",
			PoCStatus:  "theoretical",
			Confidence: "low",
		},
		{
			FindingID:  "P7-002",
			Title:      "Confirmed SQLi",
			Severity:   "high",
			PoCStatus:  "confirmed",
			Confidence: "high",
		},
	}
	out := formatFindings(findings)
	confirmedIdx := strings.Index(out, "Confirmed SQLi")
	theoreticalIdx := strings.Index(out, "Theoretical SQLi")
	if confirmedIdx < 0 || theoreticalIdx < 0 {
		t.Fatalf("formatFindings dropped a finding:\n%s", out)
	}
	if confirmedIdx > theoreticalIdx {
		t.Errorf("confirmed-PoC finding should appear before theoretical at same severity; got confirmed@%d > theoretical@%d", confirmedIdx, theoreticalIdx)
	}
}

func TestFormatFindingsSeverityStillPrimary(t *testing.T) {
	// A high-severity theoretical must still beat a critical-severity
	// confirmed only on exploitability — severity remains the primary
	// sort key. Crit > high regardless of tiebreaker.
	findings := []*audit.Finding{
		{
			FindingID:  "P7-001",
			Title:      "Theoretical critical",
			Severity:   "critical",
			PoCStatus:  "theoretical",
			Confidence: "low",
		},
		{
			FindingID:  "P7-002",
			Title:      "Confirmed high",
			Severity:   "high",
			PoCStatus:  "confirmed",
			Confidence: "high",
		},
	}
	out := formatFindings(findings)
	critIdx := strings.Index(out, "Theoretical critical")
	highIdx := strings.Index(out, "Confirmed high")
	if critIdx < 0 || highIdx < 0 {
		t.Fatalf("missing finding in:\n%s", out)
	}
	if critIdx > highIdx {
		t.Errorf("critical must outrank high regardless of exploitability; got crit@%d > high@%d", critIdx, highIdx)
	}
}
