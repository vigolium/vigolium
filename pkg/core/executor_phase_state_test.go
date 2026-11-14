package core

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/modules"
)

// A dynamic-assessment phase builds one executor per feedback round from one
// base config. With SharePhaseState, round 2 sees round 1's tech detections,
// param findings, WAF/content-class facts and per-host claims, instead of
// starting empty (the tech gate letting every gated module run, param dedup
// restarting and per-host modules re-firing).
func TestPhaseStateSharedAcrossRounds(t *testing.T) {
	var detected []string
	base := ExecutorConfig{
		Workers:            1,
		OnTechDetected:     func(host, tag string) { detected = append(detected, host+"="+tag) },
		ContentClassByHost: map[string]string{"api.test": "json"},
	}
	base.SharePhaseState()

	round1 := NewExecutor(base, &sliceSource{}, nil, nil)
	round1.scanCtx.TechStack.Mark("app.test", "spring")
	round1.scanCtx.ParamFindings.MarkFound("app.test/login", "user", "sqli")
	round1.caches.hostClaims.active.Add(hostClaimKey{moduleID: "m", origin: "https://app.test:443"}, struct{}{})

	round2 := NewExecutor(base, &sliceSource{}, nil, nil)
	if !round2.scanCtx.TechStack.Has("app.test", "spring") {
		t.Error("round 2 lost round 1's tech detection")
	}
	if !round2.scanCtx.ParamFindings.HasFinding("app.test/login", "user", "sqli") {
		t.Error("round 2 lost round 1's param finding (param dedup restarted)")
	}
	if !round2.caches.hostClaims.active.Contains(hostClaimKey{moduleID: "m", origin: "https://app.test:443"}) {
		t.Error("round 2 lost round 1's per-host claim")
	}
	if round2.scanCtx.WAFStack != round1.scanCtx.WAFStack {
		t.Error("WAF registry not shared")
	}
	if got := round2.scanCtx.ContentClass.Get("api.test"); got != "json" {
		t.Errorf("content class = %q, want json (seeded once)", got)
	}
	if len(detected) != 1 || detected[0] != "app.test=spring" {
		t.Errorf("OnTechDetected fired %v, want once for app.test=spring", detected)
	}

	// Without SharePhaseState every executor stays executor-local.
	solo1 := NewExecutor(ExecutorConfig{Workers: 1}, &sliceSource{}, nil, nil)
	solo1.scanCtx.TechStack.Mark("app.test", "spring")
	solo2 := NewExecutor(ExecutorConfig{Workers: 1}, &sliceSource{}, []modules.ActiveModule{}, nil)
	if solo2.scanCtx.TechStack.Has("app.test", "spring") {
		t.Error("executor-local registry leaked between executors")
	}
}
