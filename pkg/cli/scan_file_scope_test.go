package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/types"
)

func writeScopeHAR(t *testing.T) string {
	t.Helper()
	var entries []string
	for i := 0; i < 5; i++ {
		entries = append(entries, fmt.Sprintf(`{"request":{"method":"GET","url":"https://app.test/p%d"},"response":{"status":200,"content":{"text":"x"}}}`, i))
	}
	for i := 0; i < 3; i++ {
		entries = append(entries, fmt.Sprintf(`{"request":{"method":"GET","url":"https://cdn.other/s%d.js"},"response":{"status":200,"content":{"text":"x"}}}`, i))
	}
	p := filepath.Join(t.TempDir(), "capture.har")
	if err := os.WriteFile(p, []byte(`{"log":{"version":"1.2","entries":[`+strings.Join(entries, ",")+`]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// SAFE-4: `scan -i capture.har` with no -t scopes to the capture's primary
// host; the plan lists every input host with its verdict.
func TestDeriveFileInputScope_HAR(t *testing.T) {
	savedInput, savedMode, savedTargets, savedJSON := globalInput, globalInputMode, globalTargets, globalJSON
	defer func() {
		globalInput, globalInputMode, globalTargets, globalJSON = savedInput, savedMode, savedTargets, savedJSON
	}()
	globalInput = writeScopeHAR(t)
	globalInputMode = "urls"
	globalTargets = nil
	globalJSON = true

	settings := config.DefaultSettings()
	opts := types.DefaultOptions()
	deriveFileInputScope(settings, opts)
	if len(opts.ScopeTargets) != 1 || opts.ScopeTargets[0] != "app.test" {
		t.Fatalf("ScopeTargets = %v, want [app.test]", opts.ScopeTargets)
	}
	if len(opts.Targets) != 0 {
		t.Errorf("ScopeTargets must not become seeds; Targets = %v", opts.Targets)
	}

	plan, err := runner.ResolvePlan(context.Background(), runner.PlanInput{Opts: opts, Settings: settings, Targets: []string{}, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Scope.ScopeTargets; len(got) != 1 || got[0] != "app.test" {
		t.Errorf("plan scope_targets = %v", got)
	}
	verdicts := map[string]bool{}
	for _, h := range plan.Scope.InputHosts {
		verdicts[h.Host] = h.InScope
	}
	if !verdicts["app.test"] || verdicts["cdn.other"] {
		t.Errorf("input host verdicts = %v, want app.test in, cdn.other out", verdicts)
	}

	// --scope-origin all keeps every host.
	all := config.DefaultSettings()
	all.Scope.CLIOriginMode = "all"
	o2 := types.DefaultOptions()
	deriveFileInputScope(all, o2)
	if len(o2.ScopeTargets) != 0 {
		t.Errorf("--scope-origin all must not derive a scope, got %v", o2.ScopeTargets)
	}
}

// SAFE-4: `ingest --scan-on-receive` of a capture scans its primary host only.
func TestIngestScanScope_HAR(t *testing.T) {
	savedIn, savedFmt, savedTargets := ingestOpts.Input, ingestOpts.InputFormat, globalTargets
	defer func() { ingestOpts.Input, ingestOpts.InputFormat, globalTargets = savedIn, savedFmt, savedTargets }()
	ingestOpts.Input = writeScopeHAR(t)
	ingestOpts.InputFormat = "urls"
	globalTargets = nil
	scope, census := ingestScanScope(config.DefaultSettings())
	if len(scope) != 1 || scope[0] != "app.test" || census["cdn.other"] != 3 {
		t.Fatalf("scope=%v census=%v, want [app.test] with cdn.other counted", scope, census)
	}
	all := config.DefaultSettings()
	all.Scope.CLIOriginMode = "all"
	if s, _ := ingestScanScope(all); len(s) != 0 {
		t.Errorf("--scope-origin all must not derive, got %v", s)
	}
}
