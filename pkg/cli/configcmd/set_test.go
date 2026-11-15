package configcmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/public"
)

// A malformed `config set` command line and a key that names no setting are
// both mistakes on the command line (exit 2), not failures to write the config.
func TestConfigSetUsageErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, "cfg.yaml")
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := Deps{ConfigFlag: func() string { return cfg }}

	for name, args := range map[string][]string{
		"empty key=value":    {"=value"},
		"three args no '='":  {"a", "b", "c"},
		"single bare key":    {"notify.enabled"},
		"unknown key":        {"no_such_section.no_such_key", "1"},
		"unparseable list":   {"scope.host.include", `["a",`},
		"wrong element type": {"scope.host.include", `[1,2]`},
		"empty element":      {"scope.host.include", `a,,b`},
		"scheme in host":     {"scope.host.include", `["https://a.example"]`},
		"add residue":        {"scope.host.exclude.add", `"x"`},
	} {
		t.Run(name, func(t *testing.T) {
			err := runConfigSet(nil, deps, args, false)
			var usage clicommon.UsageError
			if !errors.As(err, &usage) {
				t.Fatalf("runConfigSet(%q) = %v, want a UsageError", args, err)
			}
		})
	}
}

// A refused value leaves the file byte-for-byte unchanged; an accepted JSON
// list lands as a real list.
func TestConfigSetStructuredValueFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, "cfg.yaml")
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := Deps{ConfigFlag: func() string { return cfg }}

	if err := runConfigSet(nil, deps, []string{"scope.host.include", `["a.example","*.b.example"]`}, false); err != nil {
		t.Fatal(err)
	}
	settings, err := config.LoadSettings(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := settings.Scope.Host.Include; len(got) != 2 || got[0] != "a.example" || got[1] != "*.b.example" {
		t.Fatalf("include = %q", got)
	}

	before, _ := os.ReadFile(cfg)
	if err := runConfigSet(nil, deps, []string{"scope.host.include", `["a.example",`}, false); err == nil {
		t.Fatal("broken list accepted")
	}
	after, _ := os.ReadFile(cfg)
	if string(before) != string(after) {
		t.Fatalf("refused value changed the file:\n%s\n---\n%s", before, after)
	}
}

// `config set` edits the raw file: every ${VAR} placeholder and every comment
// of the shipped template survives, and no expanded secret is written, even
// though the settings it validates against were loaded with the variables set.
func TestConfigSetKeepsPlaceholdersAndComments(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	secrets := map[string]string{
		"VIGOLIUM_STORAGE_SECRET_KEY": "s3cr3t-storage-value",
		"VIGOLIUM_STORAGE_ACCESS_KEY": "access-key-value-xyz",
		"VIGOLIUM_OAST_TOKEN":         "oast-token-value-xyz",
		"TELEGRAM_BOT_TOKEN":          "telegram-bot-token-xyz",
		"VIGOLIUM_OAST_DOMAIN":        "oast.private.example",
	}
	for k, v := range secrets {
		t.Setenv(k, v)
	}
	cfg := filepath.Join(home, "cfg.yaml")
	src := public.DefaultConfigYAML
	if err := os.WriteFile(cfg, src, 0o600); err != nil {
		t.Fatal(err)
	}
	deps := Deps{ConfigFlag: func() string { return cfg }}

	for _, args := range [][]string{
		{"notify.enabled", "true"},
		{"scope.host.exclude.add", "x.example"},
		{"server.service_port", "9100"},
		{"notify.telegram.chat_id", "12345"},
		{"scope.host.exclude.clear"},
	} {
		if err := runConfigSet(nil, deps, args, false); err != nil {
			t.Fatalf("config set %q: %v", args, err)
		}
	}
	got, _ := os.ReadFile(cfg)
	for _, v := range secrets {
		if strings.Contains(string(got), v) {
			t.Errorf("expanded secret %q written to the config", v)
		}
	}
	for _, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "chat_id:") {
			continue // the one placeholder this test replaced on purpose
		}
		if (strings.HasPrefix(trimmed, "#") || strings.Contains(line, "${")) && !strings.Contains(string(got), line) {
			t.Errorf("line lost: %q", line)
		}
	}
	settings, err := config.LoadSettings(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !settings.Notify.Enabled || settings.Server.ServicePort != 9100 || len(settings.Scope.Host.Exclude) != 0 {
		t.Fatalf("values not stored: enabled=%v port=%d exclude=%q", settings.Notify.Enabled, settings.Server.ServicePort, settings.Scope.Host.Exclude)
	}
}

// A non-boolean for a boolean and a non-integer for an integer are usage
// errors and leave the file alone, instead of storing false or a string.
func TestConfigSetStrictScalars(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, "cfg.yaml")
	if err := os.WriteFile(cfg, []byte("notify:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := Deps{ConfigFlag: func() string { return cfg }}
	for _, args := range [][]string{
		{"notify.enabled", "yes"},
		{"notify.enabled", "on"},
		{"notify.enabled", "maybe"},
		{"server.service_port", "12ab"},
		{"server.service_port", "1.5"},
	} {
		err := runConfigSet(nil, deps, args, false)
		var usage clicommon.UsageError
		if !errors.As(err, &usage) {
			t.Errorf("config set %q = %v, want a usage error", args, err)
		}
	}
	if got, _ := os.ReadFile(cfg); string(got) != "notify:\n  enabled: false\n" {
		t.Fatalf("refused value changed the file: %q", got)
	}
	if err := runConfigSet(nil, deps, []string{"notify.enabled", "1"}, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(cfg); string(got) != "notify:\n  enabled: true\n" {
		t.Fatalf("file = %q", got)
	}
}

// The -j result echoes the value read back from the file.
func TestConfigSetEchoesStoredValue(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, "cfg.yaml")
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var items []configSetResult
	deps := Deps{
		ConfigFlag: func() string { return cfg },
		JSON:       func() bool { return true },
		WriteMutation: func(_ *cobra.Command, it any, _ bool, _ string, _ map[string]any) error {
			items = it.([]configSetResult)
			return nil
		},
	}
	if err := runConfigSet(nil, deps, []string{"notify.enabled", "T"}, false); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Value != "true" {
		t.Fatalf("items = %+v", items)
	}
	if err := runConfigSet(nil, deps, []string{"scope.host.include", "a.example, b.example"}, false); err != nil {
		t.Fatal(err)
	}
	if items[0].Value != "[a.example, b.example]" {
		t.Fatalf("items = %+v", items)
	}
}
