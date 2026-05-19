package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestDefaultScanningStrategy_HTTPUserAgentEmpty(t *testing.T) {
	cfg := DefaultScanningStrategyConfig()
	if cfg.HTTP.UserAgent != "" {
		t.Fatalf("default scanning_strategy.http.user_agent should be empty, got %q", cfg.HTTP.UserAgent)
	}
}

// LoadSettings must read the nested scanning_strategy.http.user_agent key and
// install it as the process-global User-Agent (with {version} expansion).
func TestLoadSettings_NestedUserAgentWired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vigolium-configs.yaml")
	yaml := "scanning_strategy:\n" +
		"  default_strategy: balanced\n" +
		"  http:\n" +
		"    user_agent: \"Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)\"\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	httpmsg.SetBuildVersion("v9.9.9")
	s, err := LoadSettings(path)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}

	const want = "Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)"
	if s.ScanningStrategy.HTTP.UserAgent != want {
		t.Fatalf("config value: got %q, want %q", s.ScanningStrategy.HTTP.UserAgent, want)
	}

	const resolved = "Mozilla/5.0 (compatible; Vigolium/v9.9.9; +https://github.com/vigolium/vigolium)"
	if got := httpmsg.DefaultUserAgent(); got != resolved {
		t.Fatalf("resolved UA: got %q, want %q", got, resolved)
	}
}
