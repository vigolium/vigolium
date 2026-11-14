package core

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// A Tentative finding above Suspect is clamped to Suspect at emit time, with
// the module's claim kept in Metadata; a waived module and a Firm finding are
// untouched.
func TestEmitResult_ClampsTentative(t *testing.T) {
	var got []*output.ResultEvent
	e, _ := newTestExecutor(ExecutorConfig{}, nil)
	e.cfg.OnResult = func(r *output.ResultEvent) { got = append(got, r) }

	emit := func(module string, sev severity.Severity, conf severity.Confidence) *output.ResultEvent {
		r := &output.ResultEvent{ModuleID: module, URL: "https://x.test/" + module,
			Info: output.Info{Name: module, Severity: sev, Confidence: conf}}
		e.emitResult(context.Background(), r, nil, nil)
		return r
	}

	r := emit("some-module", severity.High, severity.Tentative)
	if r.Info.Severity != severity.Suspect {
		t.Fatalf("severity = %v, want Suspect", r.Info.Severity)
	}
	if r.Metadata["claimed_severity"] != "high" {
		t.Fatalf("claimed_severity = %v, want high", r.Metadata["claimed_severity"])
	}

	if r := emit("xss-light-url-params", severity.Low, severity.Tentative); r.Info.Severity != severity.Low {
		t.Fatalf("waived module clamped to %v", r.Info.Severity)
	}
	if r := emit("other-module", severity.High, severity.Firm); r.Info.Severity != severity.High {
		t.Fatalf("Firm finding clamped to %v", r.Info.Severity)
	}
}
