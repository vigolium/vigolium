package agent

import (
	"reflect"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/piolium"
)

func TestParseModesCSV(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  ", nil},
		{"deep", []string{"deep"}},
		{"deep,refresh,confirm", []string{"deep", "refresh", "confirm"}},
		{" deep , Refresh ,CONFIRM ", []string{"deep", "refresh", "confirm"}},
		{"deep,,confirm,", []string{"deep", "confirm"}},
		{"deep,deep,confirm,deep", []string{"deep", "confirm"}}, // de-dup, order preserved
	}
	for _, tc := range cases {
		got := ParseModesCSV(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParseModesCSV(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestResolveAuditDriverIntensity_Chains(t *testing.T) {
	// deep intensity chains [deep, confirm]; Mode stays Modes[0].
	deep := ResolveAuditDriverIntensity(agenttypes.IntensityDeep, AuditDriverIntensityPreset{}, nil)
	if !reflect.DeepEqual(deep.Modes, []string{"deep", "confirm"}) {
		t.Errorf("deep.Modes = %v, want [deep confirm]", deep.Modes)
	}
	if deep.Mode != "deep" {
		t.Errorf("deep.Mode = %q, want deep (== Modes[0])", deep.Mode)
	}

	// quick / balanced stay single-mode.
	if q := ResolveAuditDriverIntensity(agenttypes.IntensityQuick, AuditDriverIntensityPreset{}, nil); !reflect.DeepEqual(q.Modes, []string{"lite"}) {
		t.Errorf("quick.Modes = %v, want [lite]", q.Modes)
	}
	if b := ResolveAuditDriverIntensity(agenttypes.IntensityBalanced, AuditDriverIntensityPreset{}, nil); !reflect.DeepEqual(b.Modes, []string{"balanced"}) {
		t.Errorf("balanced.Modes = %v, want [balanced]", b.Modes)
	}

	// Explicit --modes overrides the preset chain entirely.
	chain := ResolveAuditDriverIntensity(agenttypes.IntensityDeep,
		AuditDriverIntensityPreset{Modes: []string{"lite", "revisit"}},
		map[string]bool{"modes": true})
	if !reflect.DeepEqual(chain.Modes, []string{"lite", "revisit"}) {
		t.Errorf("explicit modes = %v, want [lite revisit]", chain.Modes)
	}
	if chain.Mode != "lite" {
		t.Errorf("explicit chain Mode = %q, want lite", chain.Mode)
	}

	// Explicit single --mode collapses the deep chain to that one mode.
	single := ResolveAuditDriverIntensity(agenttypes.IntensityDeep,
		AuditDriverIntensityPreset{Mode: "merge"},
		map[string]bool{"mode": true})
	if !reflect.DeepEqual(single.Modes, []string{"merge"}) {
		t.Errorf("explicit mode = %v, want [merge]", single.Modes)
	}
}

func TestEffectiveModes(t *testing.T) {
	if got := (AuditAgentConfig{Modes: []string{"deep", "confirm"}}).EffectiveModes(); !reflect.DeepEqual(got, []string{"deep", "confirm"}) {
		t.Errorf("Modes set: got %v", got)
	}
	if got := (AuditAgentConfig{Mode: "lite"}).EffectiveModes(); !reflect.DeepEqual(got, []string{"lite"}) {
		t.Errorf("Mode only: got %v", got)
	}
	if got := (AuditAgentConfig{}).EffectiveModes(); !reflect.DeepEqual(got, []string{"lite"}) {
		t.Errorf("neither: got %v, want default [lite]", got)
	}
}

func TestValidateAuditDriverModes(t *testing.T) {
	// driver=audit: every mode must be audit-valid; refresh is fine.
	a, p, err := ValidateAuditDriverModes(AuditDriverAudit,
		[]string{"deep", "refresh", "confirm"}, piolium.IsValidMode, IsValidAuditDriverMode)
	if err != nil {
		t.Fatalf("audit chain unexpected err: %v", err)
	}
	if !reflect.DeepEqual(a, []string{"deep", "refresh", "confirm"}) || p != nil {
		t.Errorf("audit: a=%v p=%v, want full audit chain + nil piolium", a, p)
	}

	// driver=audit with a piolium-only-ish unknown errors.
	if _, _, err := ValidateAuditDriverModes(AuditDriverAudit,
		[]string{"deep", "bogus"}, piolium.IsValidMode, IsValidAuditDriverMode); err == nil {
		t.Error("expected error for unknown mode under driver=audit")
	}

	// driver=piolium: refresh is audit-only → not all piolium-valid → error.
	if _, _, err := ValidateAuditDriverModes(AuditDriverPiolium,
		[]string{"deep", "refresh"}, piolium.IsValidMode, IsValidAuditDriverMode); err == nil {
		t.Error("expected error: refresh not supported by piolium under driver=piolium")
	}

	// driver=auto: per-driver skip. refresh runs on audit, skipped on piolium.
	a, p, err = ValidateAuditDriverModes(AuditDriverAuto,
		[]string{"deep", "refresh", "confirm"}, piolium.IsValidMode, IsValidAuditDriverMode)
	if err != nil {
		t.Fatalf("auto chain unexpected err: %v", err)
	}
	if !reflect.DeepEqual(a, []string{"deep", "refresh", "confirm"}) {
		t.Errorf("auto audit leg = %v, want full chain", a)
	}
	if !reflect.DeepEqual(p, []string{"deep", "confirm"}) {
		t.Errorf("auto piolium leg = %v, want [deep confirm] (refresh skipped)", p)
	}

	// A mode invalid for BOTH drivers is always an error (typo guard).
	if _, _, err := ValidateAuditDriverModes(AuditDriverBoth,
		[]string{"deep", "smoke"}, piolium.IsValidMode, IsValidAuditDriverMode); err == nil {
		t.Error("expected error: smoke is not an audit-pipeline mode for either driver")
	}

	// Empty chain is an error.
	if _, _, err := ValidateAuditDriverModes(AuditDriverAudit, nil, piolium.IsValidMode, IsValidAuditDriverMode); err == nil {
		t.Error("expected error for empty mode chain")
	}
}

func TestBuildAuditAgentCommand_AuditDriverBin_ModesChain(t *testing.T) {
	cfg := auditTestCfg("", "/tmp/source", AuditDriverInvocation{Agent: AuditDriverAgentClaude})
	cfg.Modes = []string{"deep", "confirm"}
	_, args, _, err := buildAuditAgentCommand(PlatformAuditBin, cfg, false)
	if err != nil {
		t.Skipf("vigolium-audit binary not embedded (run `make build-audit`): %v", err)
	}
	if got := flagValue(args, "--modes"); got != "deep,confirm" {
		t.Errorf("--modes = %q, want deep,confirm (args=%v)", got, args)
	}
	for _, a := range args {
		if a == "--mode" {
			t.Errorf("--mode must NOT be emitted for a multi-mode chain, got %v", args)
		}
	}

	// Single-mode keeps the legacy --mode form.
	cfg2 := auditTestCfg("", "/tmp/source", AuditDriverInvocation{Agent: AuditDriverAgentClaude})
	cfg2.Modes = []string{"deep"}
	_, args2, _, _ := buildAuditAgentCommand(PlatformAuditBin, cfg2, false)
	if got := flagValue(args2, "--mode"); got != "deep" {
		t.Errorf("single-mode --mode = %q, want deep (args=%v)", got, args2)
	}
	for _, a := range args2 {
		if a == "--modes" {
			t.Errorf("--modes must NOT be emitted for a single mode, got %v", args2)
		}
	}
}

func TestNewAuditRunner_PioliumChainVsSingle(t *testing.T) {
	chain := NewAuditRunner(AuditAgentConfig{
		Platform: PlatformPi,
		Modes:    []string{"deep", "confirm"},
	}, nil)
	if _, ok := chain.(*PioliumChainScanner); !ok {
		t.Errorf("piolium + multi-mode: got %T, want *PioliumChainScanner", chain)
	}

	single := NewAuditRunner(AuditAgentConfig{
		Platform: PlatformPi,
		Modes:    []string{"deep"},
	}, nil)
	if _, ok := single.(*AuditAgenticScanner); !ok {
		t.Errorf("piolium + single mode: got %T, want *AuditAgenticScanner", single)
	}

	// audit owns its own chaining (--modes passthrough) — never a chain scanner.
	arc := NewAuditRunner(AuditAgentConfig{
		Platform: PlatformAuditBin,
		Modes:    []string{"deep", "confirm"},
	}, nil)
	if _, ok := arc.(*AuditAgenticScanner); !ok {
		t.Errorf("audit + multi-mode: got %T, want *AuditAgenticScanner", arc)
	}
}

func TestPioliumChainScanner_SkipsUnsupportedModes(t *testing.T) {
	// refresh is audit-only; the chain scanner defensively drops it.
	cs := NewPioliumChainScanner(AuditAgentConfig{
		Platform: PlatformPi,
		Modes:    []string{"deep", "refresh", "confirm"},
	}, nil)
	if !reflect.DeepEqual(cs.modes, []string{"deep", "confirm"}) {
		t.Errorf("chain modes = %v, want [deep confirm] (refresh dropped)", cs.modes)
	}
}
