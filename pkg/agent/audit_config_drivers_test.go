package agent

import (
	"reflect"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

// --- ResolveAuditAgentConfig --------------------------------------------------

func TestResolveAuditAgentConfig(t *testing.T) {
	t.Run("noAudit disables", func(t *testing.T) {
		if cfg := ResolveAuditAgentConfig(true, "deep", "/src", config.AuditAgentConfig{}); cfg != nil {
			t.Fatalf("noAudit=true should return nil, got %+v", cfg)
		}
	})

	t.Run("no source disables", func(t *testing.T) {
		if cfg := ResolveAuditAgentConfig(false, "deep", "", config.AuditAgentConfig{}); cfg != nil {
			t.Fatalf("empty source should return nil, got %+v", cfg)
		}
	})

	t.Run("explicit mode wins and enables", func(t *testing.T) {
		cfg := ResolveAuditAgentConfig(false, "deep", "/src", config.AuditAgentConfig{})
		if cfg == nil {
			t.Fatal("expected enabled config")
		}
		if cfg.Mode != "deep" {
			t.Errorf("mode = %q, want deep", cfg.Mode)
		}
		if !cfg.IsEnabled() {
			t.Error("expected IsEnabled() true")
		}
	})

	t.Run("empty mode falls back to settings EffectiveMode", func(t *testing.T) {
		// settings Mode "full" → EffectiveMode "deep"
		cfg := ResolveAuditAgentConfig(false, "", "/src", config.AuditAgentConfig{Mode: "full", SyncInterval: 17})
		if cfg == nil {
			t.Fatal("expected config")
		}
		if cfg.Mode != "deep" {
			t.Errorf("mode = %q, want deep (from EffectiveMode of full)", cfg.Mode)
		}
		if cfg.SyncInterval != 17 {
			t.Errorf("SyncInterval = %d, want 17 (carried from settings)", cfg.SyncInterval)
		}
	})

	t.Run("empty everywhere defaults to lite", func(t *testing.T) {
		// settings.Mode "" → EffectiveMode "lite"
		cfg := ResolveAuditAgentConfig(false, "", "/src", config.AuditAgentConfig{})
		if cfg == nil || cfg.Mode != "lite" {
			t.Fatalf("want mode lite, got %+v", cfg)
		}
	})

	t.Run("invalid mode falls back to lite", func(t *testing.T) {
		cfg := ResolveAuditAgentConfig(false, "warp-drive", "/src", config.AuditAgentConfig{})
		if cfg == nil || cfg.Mode != "lite" {
			t.Fatalf("invalid mode should fall back to lite, got %+v", cfg)
		}
	})
}

// --- ResolvePioliumAuditConfig ------------------------------------------------

func TestResolvePioliumAuditConfig(t *testing.T) {
	t.Run("empty mode disables", func(t *testing.T) {
		if cfg := ResolvePioliumAuditConfig("", "/src"); cfg != nil {
			t.Fatalf("empty mode should return nil, got %+v", cfg)
		}
	})
	t.Run("off mode disables", func(t *testing.T) {
		if cfg := ResolvePioliumAuditConfig("off", "/src"); cfg != nil {
			t.Fatalf("off mode should return nil, got %+v", cfg)
		}
	})
	t.Run("no source disables", func(t *testing.T) {
		if cfg := ResolvePioliumAuditConfig("lite", ""); cfg != nil {
			t.Fatalf("empty source should return nil, got %+v", cfg)
		}
	})
	t.Run("valid mode enables", func(t *testing.T) {
		cfg := ResolvePioliumAuditConfig("lite", "/src")
		if cfg == nil || !cfg.IsEnabled() || cfg.Mode != "lite" {
			t.Fatalf("expected enabled lite config, got %+v", cfg)
		}
	})
}

// --- PickAuditHarness ---------------------------------------------------------

func TestPickAuditHarness(t *testing.T) {
	t.Run("piolium wins when its mode set", func(t *testing.T) {
		cfg, _ := PickAuditHarness("lite", "deep", false, "/src", config.AuditAgentConfig{})
		if cfg == nil {
			t.Fatal("expected a config")
		}
		// piolium config carries no SyncInterval (minimal), the audit one would
		// carry DefaultAuditSyncInterval via settings. Mode is the piolium mode.
		if cfg.Mode != "lite" {
			t.Errorf("mode = %q, want lite (piolium mode wins)", cfg.Mode)
		}
	})

	t.Run("falls back to audit harness when piolium off", func(t *testing.T) {
		cfg, _ := PickAuditHarness("", "deep", false, "/src", config.AuditAgentConfig{})
		if cfg == nil || cfg.Mode != "deep" {
			t.Fatalf("expected audit harness with deep mode, got %+v", cfg)
		}
	})

	t.Run("returns nil when neither runs", func(t *testing.T) {
		cfg, _ := PickAuditHarness("", "", true, "/src", config.AuditAgentConfig{})
		if cfg != nil {
			t.Fatalf("expected nil when audit disabled and piolium off, got %+v", cfg)
		}
	})
}

// --- mode validators ----------------------------------------------------------

func TestIsValidAuditDriverMode_config(t *testing.T) {
	// isValidAuditDriverMode lives in audit_agent_config.go (unexported).
	valid := []string{"lite", "balanced", "scan", "deep", "mock", "confirm", "merge", "revisit", "reinvest"}
	for _, m := range valid {
		if !isValidAuditDriverMode(m) {
			t.Errorf("isValidAuditDriverMode(%q) = false, want true", m)
		}
	}
	invalid := []string{"", "longshot", "warp", "fast"}
	for _, m := range invalid {
		if isValidAuditDriverMode(m) {
			t.Errorf("isValidAuditDriverMode(%q) = true, want false", m)
		}
	}
}

func TestIsValidAuditDriverMode_exported(t *testing.T) {
	// IsValidAuditDriverMode (audit_drivers.go) is the broader CLI-facing set.
	valid := []string{"lite", "balanced", "scan", "deep", "revisit", "reinvest", "confirm", "merge", "diff", "longshot", "refresh"}
	for _, m := range valid {
		if !IsValidAuditDriverMode(m) {
			t.Errorf("IsValidAuditDriverMode(%q) = false, want true", m)
		}
	}
	if IsValidAuditDriverMode("mock") {
		// "mock" is audit-cfg internal but not in the exported CLI mode set.
		t.Error("IsValidAuditDriverMode(mock) should be false")
	}
	if IsValidAuditDriverMode("nonsense") {
		t.Error("IsValidAuditDriverMode(nonsense) should be false")
	}
}

// --- driver classifiers -------------------------------------------------------

func TestAuditDriverClassifiers(t *testing.T) {
	if !IsValidAuditDriver("auto") || !IsValidAuditDriver("both") ||
		!IsValidAuditDriver("audit") || !IsValidAuditDriver("piolium") {
		t.Error("all four driver IDs should be valid")
	}
	if IsValidAuditDriver("") || IsValidAuditDriver("nope") {
		t.Error("empty/unknown driver should be invalid")
	}

	// IsMultiDriverAudit: only auto + both.
	for _, d := range []string{"auto", "both"} {
		if !IsMultiDriverAudit(d) {
			t.Errorf("IsMultiDriverAudit(%q) = false, want true", d)
		}
	}
	for _, d := range []string{"audit", "piolium", ""} {
		if IsMultiDriverAudit(d) {
			t.Errorf("IsMultiDriverAudit(%q) = true, want false", d)
		}
	}

	// DriverIncludesAudit: audit + auto + both.
	for _, d := range []string{"audit", "auto", "both"} {
		if !DriverIncludesAudit(d) {
			t.Errorf("DriverIncludesAudit(%q) = false, want true", d)
		}
	}
	if DriverIncludesAudit("piolium") {
		t.Error("piolium driver should not include audit")
	}

	// DriverIncludesPiolium: piolium + auto + both.
	for _, d := range []string{"piolium", "auto", "both"} {
		if !DriverIncludesPiolium(d) {
			t.Errorf("DriverIncludesPiolium(%q) = false, want true", d)
		}
	}
	if DriverIncludesPiolium("audit") {
		t.Error("audit driver should not include piolium")
	}
}

func TestIsValidAuditDriverPlatform(t *testing.T) {
	if !IsValidAuditDriverPlatform("") {
		t.Error("empty platform should be valid (inherit from olium)")
	}
	if !IsValidAuditDriverPlatform("claude") || !IsValidAuditDriverPlatform("codex") {
		t.Error("claude/codex should be valid platforms")
	}
	if IsValidAuditDriverPlatform("gpt") {
		t.Error("gpt should not be a valid platform")
	}
}

// --- mode chain helpers -------------------------------------------------------

func TestJoinModes(t *testing.T) {
	if got := JoinModes([]string{"deep", "confirm"}); got != "deep,confirm" {
		t.Errorf("JoinModes = %q, want deep,confirm", got)
	}
	if got := JoinModes(nil); got != "" {
		t.Errorf("JoinModes(nil) = %q, want empty", got)
	}
}

func TestFirstMode(t *testing.T) {
	if got := FirstMode(nil); got != "" {
		t.Errorf("FirstMode(nil) = %q, want empty", got)
	}
	if got := FirstMode([]string{"lite", "deep"}); got != "lite" {
		t.Errorf("FirstMode = %q, want lite", got)
	}
}

// --- ValidateAuditDriverMode --------------------------------------------------

func TestValidateAuditDriverMode(t *testing.T) {
	piolium := func(m string) bool { return m == "lite" || m == "longshot" }
	audit := func(m string) bool { return m == "lite" || m == "mock" }

	t.Run("both restricts to shared set", func(t *testing.T) {
		if err := ValidateAuditDriverMode("both", "lite", piolium, audit); err != nil {
			t.Errorf("lite is shared, should be valid for both: %v", err)
		}
		if err := ValidateAuditDriverMode("both", "longshot", piolium, audit); err == nil {
			t.Error("longshot is not shared, should error for driver=both")
		}
	})

	t.Run("auto also restricts to shared set", func(t *testing.T) {
		if err := ValidateAuditDriverMode("auto", "mock", piolium, audit); err == nil {
			t.Error("mock is not shared, should error for driver=auto")
		}
	})

	t.Run("single piolium uses piolium validator", func(t *testing.T) {
		if err := ValidateAuditDriverMode("piolium", "longshot", piolium, audit); err != nil {
			t.Errorf("longshot valid for piolium: %v", err)
		}
		if err := ValidateAuditDriverMode("piolium", "mock", piolium, audit); err == nil {
			t.Error("mock invalid for piolium, should error")
		}
	})

	t.Run("single audit uses audit validator", func(t *testing.T) {
		if err := ValidateAuditDriverMode("audit", "mock", piolium, audit); err != nil {
			t.Errorf("mock valid for audit: %v", err)
		}
		if err := ValidateAuditDriverMode("audit", "longshot", piolium, audit); err == nil {
			t.Error("longshot invalid for audit, should error")
		}
	})
}

// --- ValidateAuditDriverModes (chains, injected validators) -------------------
// The real-validator coverage lives in audit_modes_test.go. This variant drives
// the same function with controlled fake validators so the per-driver filtering
// and unknown-mode error paths are exercised in isolation.

func TestValidateAuditDriverModes_Injected(t *testing.T) {
	// piolium: lite, deep, longshot. audit: lite, deep, mock.
	piolium := func(m string) bool { return m == "lite" || m == "deep" || m == "longshot" }
	audit := func(m string) bool { return m == "lite" || m == "deep" || m == "mock" }

	t.Run("empty modes errors", func(t *testing.T) {
		if _, _, err := ValidateAuditDriverModes("auto", nil, piolium, audit); err == nil {
			t.Error("empty chain should error")
		}
	})

	t.Run("unknown-to-both mode is hard error", func(t *testing.T) {
		_, _, err := ValidateAuditDriverModes("auto", []string{"lite", "warp"}, piolium, audit)
		if err == nil {
			t.Fatal("expected error for mode unknown to both drivers")
		}
		if !errContains(err, "warp") {
			t.Errorf("error should name the unknown mode: %v", err)
		}
	})

	t.Run("audit single driver requires all modes audit-valid", func(t *testing.T) {
		// longshot is piolium-only — invalid in an audit-only chain.
		if _, _, err := ValidateAuditDriverModes("audit", []string{"lite", "longshot"}, piolium, audit); err == nil {
			t.Error("audit chain with piolium-only mode should error")
		}
		// all-audit chain passes; piolium chain nilled out.
		ac, pc, err := ValidateAuditDriverModes("audit", []string{"lite", "mock"}, piolium, audit)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(ac, []string{"lite", "mock"}) {
			t.Errorf("auditChain = %v, want [lite mock]", ac)
		}
		if pc != nil {
			t.Errorf("pioliumChain should be nil for driver=audit, got %v", pc)
		}
	})

	t.Run("piolium single driver requires all modes piolium-valid", func(t *testing.T) {
		if _, _, err := ValidateAuditDriverModes("piolium", []string{"lite", "mock"}, piolium, audit); err == nil {
			t.Error("piolium chain with audit-only mode should error")
		}
		ac, pc, err := ValidateAuditDriverModes("piolium", []string{"lite", "longshot"}, piolium, audit)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ac != nil {
			t.Errorf("auditChain should be nil for driver=piolium, got %v", ac)
		}
		if !reflect.DeepEqual(pc, []string{"lite", "longshot"}) {
			t.Errorf("pioliumChain = %v, want [lite longshot]", pc)
		}
	})

	t.Run("auto/both filter per-driver", func(t *testing.T) {
		// lite valid for both, longshot piolium-only, mock audit-only.
		ac, pc, err := ValidateAuditDriverModes("both", []string{"lite", "longshot", "mock"}, piolium, audit)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// audit leg drops longshot; piolium leg drops mock.
		if !reflect.DeepEqual(ac, []string{"lite", "mock"}) {
			t.Errorf("auditChain = %v, want [lite mock]", ac)
		}
		if !reflect.DeepEqual(pc, []string{"lite", "longshot"}) {
			t.Errorf("pioliumChain = %v, want [lite longshot]", pc)
		}
	})

	t.Run("invalid driver errors", func(t *testing.T) {
		if _, _, err := ValidateAuditDriverModes("nonsense", []string{"lite"}, piolium, audit); err == nil {
			t.Error("invalid driver should error")
		}
	})
}

// --- BuildAuditDriverCfg ------------------------------------------------------

func TestBuildAuditDriverCfg(t *testing.T) {
	in := AuditDriverCfgInput{
		Mode:                  "deep",
		Modes:                 []string{"deep", "confirm"},
		SourcePath:            "/src",
		SessionDir:            "/tmp/sess",
		ProjectUUID:           "proj-1",
		ScanUUID:              "scan-1",
		ParentAgenticScanUUID: "parent-1",
		Invocation:            AuditDriverInvocation{Agent: AuditDriverAgentCodex},
		Stream:                true,
		ShowThinking:          true,
		KeepRaw:               true,
	}
	cfg := BuildAuditDriverCfg(in)

	if cfg.Mode != "deep" {
		t.Errorf("Mode = %q, want deep", cfg.Mode)
	}
	if !reflect.DeepEqual(cfg.Modes, []string{"deep", "confirm"}) {
		t.Errorf("Modes = %v, want [deep confirm]", cfg.Modes)
	}
	if cfg.SourcePath != "/src" || cfg.SessionDir != "/tmp/sess" {
		t.Error("source/session paths not threaded through")
	}
	if cfg.ProjectUUID != "proj-1" || cfg.ScanUUID != "scan-1" || cfg.ParentAgenticScanUUID != "parent-1" {
		t.Error("UUIDs not threaded through")
	}
	if cfg.AuditDriverInvocation.Agent != AuditDriverAgentCodex {
		t.Error("invocation agent not threaded through")
	}
	if cfg.Platform != PlatformAuditBin {
		t.Errorf("Platform = %q, want %q", cfg.Platform, PlatformAuditBin)
	}
	if cfg.SyncInterval != DefaultAuditSyncInterval {
		t.Errorf("SyncInterval = %v, want %v", cfg.SyncInterval, DefaultAuditSyncInterval)
	}
	if !cfg.Stream || !cfg.ShowThinking || !cfg.KeepRaw {
		t.Error("Stream/ShowThinking/KeepRaw flags not threaded through")
	}
}

func errContains(err error, sub string) bool {
	return err != nil && strings.Contains(err.Error(), sub)
}
