package agent

import (
	"context"
	"strings"
	"sync"

	otool "github.com/vigolium/vigolium/pkg/olium/tool"
)

// verdictSink captures the structured verdict the skeptic verifier emits via
// submit_verdict. One per verifier run; guarded by a mutex because the tool
// executes on the engine's dispatch goroutine while the run loop reads it.
type verdictSink struct {
	mu      sync.Mutex
	set     bool
	verdict string
	reason  string
	grade   string
}

func (s *verdictSink) store(verdict, reason, grade string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// First verdict wins — a well-behaved verifier calls submit_verdict once.
	if s.set {
		return
	}
	s.set = true
	s.verdict = verdict
	s.reason = reason
	s.grade = grade
}

func (s *verdictSink) done() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.set
}

func (s *verdictSink) get() (verdict, reason, grade string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verdict, s.reason, s.grade, s.set
}

// validVerdicts / validGrades are the closed sets the tool accepts.
var (
	validVerdicts = map[string]string{
		"confirmed":      "confirmed",
		"rejected":       "rejected",
		"needs_evidence": "needs_evidence",
	}
	validGrades = map[string]bool{"strong": true, "moderate": true, "weak": true}
)

// newSubmitVerdictTool builds the submit_verdict tool bound to a sink. It is the
// verifier's structured-output channel (mirrors halt_scan / report_finding):
// the skeptic investigates with the read-only tools, then calls this once.
func newSubmitVerdictTool(sink *verdictSink) otool.Tool {
	return &submitVerdictTool{sink: sink}
}

type submitVerdictTool struct{ sink *verdictSink }

func (*submitVerdictTool) Name() string     { return "submit_verdict" }
func (*submitVerdictTool) Label() string    { return "Submit verdict" }
func (*submitVerdictTool) Category() string { return otool.CategoryVigolium }
func (*submitVerdictTool) IsReadOnly() bool { return false }
func (*submitVerdictTool) Description() string {
	return "Submit your final verification verdict for the candidate. Call this exactly once, only after you have " +
		"independently investigated. verdict must be one of: confirmed (evidence clearly meets the gate), rejected " +
		"(evidence contradicts it or is explainable by normal behavior), needs_evidence (you could not obtain the " +
		"evidence the gate requires). Include a concise reason citing the concrete evidence you observed."
}

func (*submitVerdictTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"verdict": map[string]any{
				"type":        "string",
				"enum":        []string{"confirmed", "rejected", "needs_evidence"},
				"description": "Your judgment against the evidence gate.",
			},
			"reason": map[string]any{
				"type":        "string",
				"description": "One–two sentences citing the specific evidence you reproduced (record ids, status codes, OAST hits, browser result).",
			},
			"evidence_grade": map[string]any{
				"type":        "string",
				"enum":        []string{"strong", "moderate", "weak"},
				"description": "How strong the evidence is.",
			},
		},
		"required": []string{"verdict", "reason"},
	}
}

func (t *submitVerdictTool) Execute(_ context.Context, args map[string]any, _ otool.UpdateFn) (otool.Result, error) {
	verdict, _ := args["verdict"].(string)
	verdict = strings.ToLower(strings.TrimSpace(verdict))
	canonical, ok := validVerdicts[verdict]
	if !ok {
		return otool.Result{
			Content: "submit_verdict: 'verdict' must be one of confirmed | rejected | needs_evidence",
			IsError: true,
		}, nil
	}
	reason, _ := args["reason"].(string)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return otool.Result{
			Content: "submit_verdict: 'reason' is required — cite the concrete evidence you observed",
			IsError: true,
		}, nil
	}
	grade, _ := args["evidence_grade"].(string)
	grade = strings.ToLower(strings.TrimSpace(grade))
	if !validGrades[grade] {
		grade = "moderate"
	}
	t.sink.store(canonical, reason, grade)
	return otool.Result{Content: "Verdict recorded: " + canonical + " (" + grade + ")"}, nil
}
