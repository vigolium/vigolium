package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/public"
)

// `module disable` adds to a deny-list: the [all] allow-list and every comment
// of the file survive, and the module (only it) reads as disabled. `module
// enable` takes it back off.
func TestModuleDisableUsesDenyList(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, "cfg.yaml")
	if err := os.WriteFile(cfg, public.DefaultConfigYAML, 0o600); err != nil {
		t.Fatal(err)
	}
	withGlobalConfig(t, cfg)
	prevExact, prevForce := moduleExactID, globalForce
	moduleExactID, globalForce = true, false
	t.Cleanup(func() { moduleExactID, globalForce = prevExact, prevForce })

	ids := modules.GetActiveModulesID()
	target := ids[0]
	if err := runModuleDisable(nil, []string{target}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(cfg)
	for _, line := range strings.Split(string(public.DefaultConfigYAML), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") && !strings.Contains(string(got), line) {
			t.Fatalf("comment lost: %q", line)
		}
	}
	s, err := config.LoadSettings(cfg)
	if err != nil {
		t.Fatal(err)
	}
	em := s.DynamicAssessment.EnabledModules
	if !config.AllowsAll(em.ActiveModules) {
		t.Fatalf("allow-list changed: %q", em.ActiveModules)
	}
	if em.ActiveEnabled(target) || !em.ActiveEnabled(ids[1]) {
		t.Fatalf("disabled=%q: %v; other=%v", target, em.ActiveEnabled(target), em.ActiveEnabled(ids[1]))
	}

	if err := runModuleEnable(nil, []string{target}); err != nil {
		t.Fatal(err)
	}
	s, _ = config.LoadSettings(cfg)
	if !s.DynamicAssessment.EnabledModules.ActiveEnabled(target) {
		t.Fatal("module enable did not take it off the deny-list")
	}
}

// A fuzzy term that matches more than five modules needs --force.
func TestModuleToggleBroadTermNeedsForce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, "cfg.yaml")
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withGlobalConfig(t, cfg)
	prevExact, prevForce := moduleExactID, globalForce
	moduleExactID, globalForce = false, false
	t.Cleanup(func() { moduleExactID, globalForce = prevExact, prevForce })

	if n := len(findMatchingModules("a", false)); n <= maxModuleToggleWithoutForce {
		t.Skipf("only %d modules match", n)
	}
	err := runModuleDisable(nil, []string{"a"})
	var usage clicommon.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("disable a = %v, want a usage error", err)
	}
	if got, _ := os.ReadFile(cfg); string(got) != "{}\n" {
		t.Fatalf("config written without --force: %q", got)
	}
	globalForce = true
	if err := runModuleDisable(nil, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	s, _ := config.LoadSettings(cfg)
	if !config.AllowsAll(s.DynamicAssessment.EnabledModules.ActiveModules) || len(s.DynamicAssessment.EnabledModules.DisabledActiveModules) == 0 {
		t.Fatalf("enabled_modules = %+v", s.DynamicAssessment.EnabledModules)
	}
}
