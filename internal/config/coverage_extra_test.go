package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// --- notify.go ---------------------------------------------------------------

func TestWebhookConfig_EffectiveTimeout(t *testing.T) {
	tests := []struct {
		name string
		cfg  *WebhookConfig
		want int
	}{
		{"nil falls back to 10", nil, 10},
		{"zero falls back to 10", &WebhookConfig{}, 10},
		{"negative falls back to 10", &WebhookConfig{TimeoutSec: -3}, 10},
		{"positive is kept", &WebhookConfig{TimeoutSec: 42}, 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.EffectiveTimeout(); got != tt.want {
				t.Errorf("EffectiveTimeout() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNotifyChannels_IsConfigured(t *testing.T) {
	if (&WebhookConfig{}).IsConfigured() {
		t.Error("empty webhook should not be configured")
	}
	if !(&WebhookConfig{URL: "https://x"}).IsConfigured() {
		t.Error("webhook with URL should be configured")
	}
	if (&WebhookConfig{URL: "   "}).IsConfigured() {
		t.Error("whitespace-only webhook URL should not be configured")
	}

	if (&TelegramConfig{BotToken: "t"}).IsConfigured() {
		t.Error("telegram without chat_id should not be configured")
	}
	if !(&TelegramConfig{BotToken: "t", ChatID: "c"}).IsConfigured() {
		t.Error("telegram with token+chat should be configured")
	}

	if (&DiscordConfig{}).IsConfigured() {
		t.Error("empty discord should not be configured")
	}
	if !(&DiscordConfig{WebhookURL: "https://x"}).IsConfigured() {
		t.Error("discord with webhook should be configured")
	}
}

func TestNotifyConfig_IsProviderActive(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *NotifyConfig
		provider string
		want     bool
	}{
		{"nil", nil, NotifyProviderWebhook, false},
		{"disabled", &NotifyConfig{Enabled: false}, NotifyProviderWebhook, false},
		{"enabled empty selector allows all", &NotifyConfig{Enabled: true}, NotifyProviderTelegram, true},
		{"selector matches", &NotifyConfig{Enabled: true, Provider: "telegram"}, NotifyProviderTelegram, true},
		{"selector matches case-insensitively", &NotifyConfig{Enabled: true, Provider: " Telegram "}, NotifyProviderTelegram, true},
		{"selector excludes others", &NotifyConfig{Enabled: true, Provider: "telegram"}, NotifyProviderDiscord, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsProviderActive(tt.provider); got != tt.want {
				t.Errorf("IsProviderActive(%q) = %v, want %v", tt.provider, got, tt.want)
			}
		})
	}
}

func TestNotifyConfig_IsWebhookActive(t *testing.T) {
	// routed + configured -> active
	active := &NotifyConfig{Enabled: true, Provider: NotifyProviderWebhook, Webhook: WebhookConfig{URL: "https://x"}}
	if !active.IsWebhookActive() {
		t.Error("expected webhook active when routed and configured")
	}
	// routed but not configured -> inactive
	noURL := &NotifyConfig{Enabled: true, Provider: NotifyProviderWebhook}
	if noURL.IsWebhookActive() {
		t.Error("expected webhook inactive when URL missing")
	}
	// configured but routed elsewhere -> inactive
	wrongRoute := &NotifyConfig{Enabled: true, Provider: NotifyProviderTelegram, Webhook: WebhookConfig{URL: "https://x"}}
	if wrongRoute.IsWebhookActive() {
		t.Error("expected webhook inactive when provider routed to telegram")
	}
}

// --- agent.go ----------------------------------------------------------------

func TestOliumConfig_EffectiveCallTimeout(t *testing.T) {
	tests := []struct {
		name string
		secs int
		want time.Duration
	}{
		{"zero -> 10m default", 0, 10 * time.Minute},
		{"positive seconds", 30, 30 * time.Second},
		{"negative -> no enforced timeout", -1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &OliumConfig{CallTimeoutSec: tt.secs}
			if got := c.EffectiveCallTimeout(); got != tt.want {
				t.Errorf("EffectiveCallTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOliumConfig_EffectiveMaxConcurrent(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{"zero -> default 4", 0, 4},
		{"positive kept", 8, 8},
		{"negative -> unbounded (0)", -1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &OliumConfig{MaxConcurrent: tt.in}
			if got := c.EffectiveMaxConcurrent(); got != tt.want {
				t.Errorf("EffectiveMaxConcurrent() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestContextLimits_Effective(t *testing.T) {
	// zero values fall back to documented defaults
	zero := &ContextLimits{}
	if got := zero.EffectiveMaxFindings(); got != 50 {
		t.Errorf("EffectiveMaxFindings default = %d, want 50", got)
	}
	if got := zero.EffectiveMaxEndpoints(); got != 100 {
		t.Errorf("EffectiveMaxEndpoints default = %d, want 100", got)
	}
	if got := zero.EffectiveMaxHighRisk(); got != 20 {
		t.Errorf("EffectiveMaxHighRisk default = %d, want 20", got)
	}
	if got := zero.EffectiveMinRiskScore(); got != 50 {
		t.Errorf("EffectiveMinRiskScore default = %d, want 50", got)
	}

	// explicit positive values override
	set := &ContextLimits{MaxFindings: 5, MaxEndpoints: 6, MaxHighRisk: 7, MinRiskScore: 8}
	if got := set.EffectiveMaxFindings(); got != 5 {
		t.Errorf("EffectiveMaxFindings = %d, want 5", got)
	}
	if got := set.EffectiveMaxEndpoints(); got != 6 {
		t.Errorf("EffectiveMaxEndpoints = %d, want 6", got)
	}
	if got := set.EffectiveMaxHighRisk(); got != 7 {
		t.Errorf("EffectiveMaxHighRisk = %d, want 7", got)
	}
	if got := set.EffectiveMinRiskScore(); got != 8 {
		t.Errorf("EffectiveMinRiskScore = %d, want 8", got)
	}
}

func TestBrowserConfig_IsEnabledAndPath(t *testing.T) {
	tr, fa := true, false
	if (&BrowserConfig{}).IsEnabled() {
		t.Error("nil Enable should be disabled")
	}
	if (&BrowserConfig{Enable: &fa}).IsEnabled() {
		t.Error("explicit false should be disabled")
	}
	if !(&BrowserConfig{Enable: &tr}).IsEnabled() {
		t.Error("explicit true should be enabled")
	}

	if got := (&BrowserConfig{}).EffectiveBinaryPath(); got != "agent-browser" {
		t.Errorf("default binary path = %q, want agent-browser", got)
	}
	if got := (&BrowserConfig{BinaryPath: "/usr/local/bin/ab"}).EffectiveBinaryPath(); got != "/usr/local/bin/ab" {
		t.Errorf("binary path = %q, want override", got)
	}
}

func TestAuditAgentConfig(t *testing.T) {
	tr := true
	if (&AuditAgentConfig{}).IsEnabled() {
		t.Error("nil Enable should be disabled")
	}
	if !(&AuditAgentConfig{Enable: &tr}).IsEnabled() {
		t.Error("explicit true should be enabled")
	}

	modes := map[string]string{
		"deep":     "deep",
		"full":     "deep",
		"balanced": "balanced",
		"scan":     "balanced",
		"mock":     "mock",
		"":         "lite",
		"garbage":  "lite",
	}
	for in, want := range modes {
		if got := (&AuditAgentConfig{Mode: in}).EffectiveMode(); got != want {
			t.Errorf("EffectiveMode(%q) = %q, want %q", in, got, want)
		}
	}

	if got := (&AuditAgentConfig{}).EffectiveSyncInterval(); got != 30 {
		t.Errorf("EffectiveSyncInterval default = %d, want 30", got)
	}
	if got := (&AuditAgentConfig{SyncInterval: 15}).EffectiveSyncInterval(); got != 15 {
		t.Errorf("EffectiveSyncInterval = %d, want 15", got)
	}
}

func TestAgentConfig_SessionsDirStreamMetaValidate(t *testing.T) {
	// EffectiveSessionsDir: default expands under ~/.vigolium; override is expanded too.
	if got := (&AgentConfig{}).EffectiveSessionsDir(); !strings.Contains(got, "agent-sessions") {
		t.Errorf("default sessions dir = %q, want it to contain agent-sessions", got)
	}
	if got := (&AgentConfig{SessionsDir: "/tmp/vig-sessions"}).EffectiveSessionsDir(); got != "/tmp/vig-sessions" {
		t.Errorf("sessions dir = %q, want /tmp/vig-sessions", got)
	}

	// StreamEnabled: nil -> true (default on), explicit values respected.
	tr, fa := true, false
	if !(&AgentConfig{}).StreamEnabled() {
		t.Error("nil Stream should default to enabled")
	}
	if !(&AgentConfig{Stream: &tr}).StreamEnabled() {
		t.Error("explicit true should be enabled")
	}
	if (&AgentConfig{Stream: &fa}).StreamEnabled() {
		t.Error("explicit false should be disabled")
	}

	// BackendMeta: nil receiver -> empty pair; otherwise label + model.
	var nilCfg *AgentConfig
	if proto, model := nilCfg.BackendMeta(); proto != "" || model != "" {
		t.Errorf("nil BackendMeta() = (%q,%q), want empty", proto, model)
	}
	cfg := &AgentConfig{Olium: OliumConfig{Model: "gpt-5.5"}}
	if proto, model := cfg.BackendMeta(); proto != AgentProtocolLabel || model != "gpt-5.5" {
		t.Errorf("BackendMeta() = (%q,%q), want (%q,gpt-5.5)", proto, model, AgentProtocolLabel)
	}

	// Validate: empty default_agent fails, set passes.
	if err := (&AgentConfig{}).Validate(); err == nil {
		t.Error("expected error for empty default_agent")
	}
	if err := (&AgentConfig{DefaultAgent: "olium"}).Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCustomProviderConfig_ExtraHeadersMap(t *testing.T) {
	// empty list -> nil
	if m := (&CustomProviderConfig{}).ExtraHeadersMap(); m != nil {
		t.Errorf("empty extra_headers should map to nil, got %v", m)
	}

	// well-formed, malformed (skipped), empty-name (skipped), duplicate (last wins)
	c := &CustomProviderConfig{ExtraHeaders: ExtraHeaderList{
		"X-Foo: bar",
		"  ", // blank, skipped
		"NoColonHere",
		" : empty-name",
		"Dup: 1",
		"Dup: 2",
	}}
	m := c.ExtraHeadersMap()
	if m["X-Foo"] != "bar" {
		t.Errorf("X-Foo = %q, want bar", m["X-Foo"])
	}
	if m["Dup"] != "2" {
		t.Errorf("Dup = %q, want 2 (last wins)", m["Dup"])
	}
	if _, ok := m["NoColonHere"]; ok {
		t.Error("malformed entry should be skipped")
	}
	if len(m) != 2 {
		t.Errorf("expected 2 valid headers, got %d: %v", len(m), m)
	}

	// all-malformed -> nil
	if m := (&CustomProviderConfig{ExtraHeaders: ExtraHeaderList{"bad", "alsobad"}}).ExtraHeadersMap(); m != nil {
		t.Errorf("all-malformed should map to nil, got %v", m)
	}
}

func TestExtraHeaderList_UnmarshalYAML(t *testing.T) {
	type holder struct {
		H ExtraHeaderList `yaml:"h"`
	}

	// sequence of strings
	var seq holder
	if err := yaml.Unmarshal([]byte("h:\n  - \"A: 1\"\n  - \"B: 2\"\n"), &seq); err != nil {
		t.Fatalf("sequence unmarshal: %v", err)
	}
	if len(seq.H) != 2 || seq.H[0] != "A: 1" {
		t.Errorf("sequence = %v, want [A: 1 B: 2]", seq.H)
	}

	// null -> nil
	var null holder
	if err := yaml.Unmarshal([]byte("h: null\n"), &null); err != nil {
		t.Fatalf("null unmarshal: %v", err)
	}
	if null.H != nil {
		t.Errorf("null = %v, want nil", null.H)
	}

	// empty mapping -> nil
	var empty holder
	if err := yaml.Unmarshal([]byte("h: {}\n"), &empty); err != nil {
		t.Fatalf("empty map unmarshal: %v", err)
	}
	if empty.H != nil {
		t.Errorf("empty map = %v, want nil", empty.H)
	}

	// non-empty mapping -> error
	var badMap holder
	if err := yaml.Unmarshal([]byte("h:\n  Key: Value\n"), &badMap); err == nil {
		t.Error("expected error for non-empty map form")
	}

	// scalar string -> error
	var badScalar holder
	if err := yaml.Unmarshal([]byte("h: justastring\n"), &badScalar); err == nil {
		t.Error("expected error for scalar form")
	}
}

// --- database.go -------------------------------------------------------------

func TestDatabaseConfig_Validate(t *testing.T) {
	t.Run("disabled is always valid", func(t *testing.T) {
		if err := (&DatabaseConfig{Enabled: false, Driver: "garbage"}).Validate(); err != nil {
			t.Errorf("disabled config should validate, got %v", err)
		}
	})

	t.Run("default sqlite is valid", func(t *testing.T) {
		if err := DefaultDatabaseConfig().Validate(); err != nil {
			t.Errorf("default config should validate, got %v", err)
		}
	})

	t.Run("invalid driver", func(t *testing.T) {
		c := DefaultDatabaseConfig()
		c.Driver = "mysql"
		if err := c.Validate(); err == nil {
			t.Error("expected error for invalid driver")
		}
	})

	sqliteCases := []struct {
		name   string
		mutate func(*DatabaseConfig)
	}{
		{"empty path", func(c *DatabaseConfig) { c.SQLite.Path = "" }},
		{"negative busy_timeout", func(c *DatabaseConfig) { c.SQLite.BusyTimeout = -1 }},
		{"bad journal_mode", func(c *DatabaseConfig) { c.SQLite.JournalMode = "NOPE" }},
		{"bad synchronous", func(c *DatabaseConfig) { c.SQLite.Synchronous = "NOPE" }},
	}
	for _, tt := range sqliteCases {
		t.Run("sqlite "+tt.name, func(t *testing.T) {
			c := DefaultDatabaseConfig()
			tt.mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}

	t.Run("postgres valid", func(t *testing.T) {
		c := DefaultDatabaseConfig()
		c.Driver = "postgres"
		if err := c.Validate(); err != nil {
			t.Errorf("default postgres should validate, got %v", err)
		}
	})

	pgCases := []struct {
		name   string
		mutate func(*DatabaseConfig)
	}{
		{"empty host", func(c *DatabaseConfig) { c.Postgres.Host = "" }},
		{"bad port", func(c *DatabaseConfig) { c.Postgres.Port = 0 }},
		{"port too high", func(c *DatabaseConfig) { c.Postgres.Port = 70000 }},
		{"empty user", func(c *DatabaseConfig) { c.Postgres.User = "" }},
		{"empty database", func(c *DatabaseConfig) { c.Postgres.Database = "" }},
		{"max_open_conns < 1", func(c *DatabaseConfig) { c.Postgres.MaxOpenConns = 0 }},
		{"negative max_idle_conns", func(c *DatabaseConfig) { c.Postgres.MaxIdleConns = -1 }},
		{"bad conn_max_lifetime", func(c *DatabaseConfig) { c.Postgres.ConnMaxLifetime = "notaduration" }},
	}
	for _, tt := range pgCases {
		t.Run("postgres "+tt.name, func(t *testing.T) {
			c := DefaultDatabaseConfig()
			c.Driver = "postgres"
			tt.mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

// --- discovery.go ------------------------------------------------------------

func TestDiscoveryConfig_EngineTimeoutParsed(t *testing.T) {
	if got := (&DiscoveryConfig{}).EngineTimeoutParsed(); got != 10*time.Second {
		t.Errorf("empty timeout = %v, want 10s", got)
	}
	c := DefaultDiscoveryConfig()
	c.Engine.Timeout = "45s"
	if got := c.EngineTimeoutParsed(); got != 45*time.Second {
		t.Errorf("parsed = %v, want 45s", got)
	}
	c.Engine.Timeout = "not-a-duration"
	if got := c.EngineTimeoutParsed(); got != 10*time.Second {
		t.Errorf("bad timeout fallback = %v, want 10s", got)
	}
}

func TestDiscoveryConfig_Validate(t *testing.T) {
	t.Run("default is valid", func(t *testing.T) {
		if err := DefaultDiscoveryConfig().Validate(); err != nil {
			t.Errorf("default discovery should validate, got %v", err)
		}
	})

	cases := []struct {
		name    string
		mutate  func(*DiscoveryConfig)
		wantErr bool
	}{
		{"bad mode", func(c *DiscoveryConfig) { c.Mode = "weird" }, true},
		{"bad scope_mode", func(c *DiscoveryConfig) { c.ScopeMode = "weird" }, true},
		{"recursion depth zero when enabled", func(c *DiscoveryConfig) { c.Recursion.Enabled = true; c.Recursion.MaxDepth = 0 }, true},
		{"engine timeout out of range", func(c *DiscoveryConfig) { c.Engine.Timeout = "500s" }, true},
		{"engine timeout invalid", func(c *DiscoveryConfig) { c.Engine.Timeout = "bogus" }, true},
		{"bad case_sensitivity", func(c *DiscoveryConfig) { c.Engine.CaseSensitivity = "weird" }, true},
		{"valid in-range timeout", func(c *DiscoveryConfig) { c.Engine.Timeout = "30s" }, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultDiscoveryConfig()
			tt.mutate(c)
			err := c.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for %s: %v", tt.name, err)
			}
		})
	}
}

// --- extensions.go -----------------------------------------------------------

func TestExtensionsConfig_ExecTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
		want    int
	}{
		{"empty -> 30", "", 30},
		{"invalid -> 30", "abc", 30},
		{"valid 45s", "45s", 45},
		{"cap at 120", "5m", 120},
		{"non-positive -> 30", "0s", 30},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ExtensionsConfig{Limits: ScriptLimits{Timeout: tt.timeout}}
			if got := c.ExecTimeout(); got != tt.want {
				t.Errorf("ExecTimeout() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestScriptLimits_TimeoutDuration(t *testing.T) {
	if got := (&ScriptLimits{}).TimeoutDuration(); got != 30*time.Second {
		t.Errorf("empty = %v, want 30s", got)
	}
	if got := (&ScriptLimits{Timeout: "abc"}).TimeoutDuration(); got != 30*time.Second {
		t.Errorf("invalid = %v, want 30s", got)
	}
	if got := (&ScriptLimits{Timeout: "2m"}).TimeoutDuration(); got != 2*time.Minute {
		t.Errorf("parsed = %v, want 2m", got)
	}
}

func TestExtensionsConfig_Validate(t *testing.T) {
	t.Run("disabled is valid", func(t *testing.T) {
		if err := (&ExtensionsConfig{Enabled: false}).Validate(); err != nil {
			t.Errorf("disabled should validate, got %v", err)
		}
	})
	t.Run("default extension dir (may not exist) is valid", func(t *testing.T) {
		c := DefaultExtensionsConfig()
		c.Enabled = true
		if err := c.Validate(); err != nil {
			t.Errorf("default enabled should validate, got %v", err)
		}
	})
	t.Run("missing custom_dir path errors", func(t *testing.T) {
		c := &ExtensionsConfig{Enabled: true, CustomDir: []string{"/no/such/file/here.js"}}
		if err := c.Validate(); err == nil {
			t.Error("expected error for missing custom_dir path")
		}
	})
	t.Run("invalid timeout errors", func(t *testing.T) {
		c := &ExtensionsConfig{Enabled: true, Limits: ScriptLimits{Timeout: "bogus"}}
		if err := c.Validate(); err == nil {
			t.Error("expected error for invalid timeout duration")
		}
	})
	t.Run("negative memory errors", func(t *testing.T) {
		c := &ExtensionsConfig{Enabled: true, Limits: ScriptLimits{MaxMemoryMB: -1}}
		if err := c.Validate(); err == nil {
			t.Error("expected error for negative max_memory_mb")
		}
	})
	t.Run("extension_dir pointing at a file errors", func(t *testing.T) {
		f := t.TempDir() + "/not-a-dir.txt"
		if err := writeFileForTest(f, "x"); err != nil {
			t.Fatal(err)
		}
		c := &ExtensionsConfig{Enabled: true, ExtensionDir: f}
		if err := c.Validate(); err == nil {
			t.Error("expected error when extension_dir is a file")
		}
	})
}

// --- known_issue_scan.go -----------------------------------------------------

func TestKnownIssueScanConfig_Validate(t *testing.T) {
	if err := DefaultKnownIssueScanConfig().Validate(); err != nil {
		t.Errorf("default should validate, got %v", err)
	}
	if err := (&KnownIssueScanConfig{Severities: []string{"high", "low"}}).Validate(); err != nil {
		t.Errorf("valid severities should pass, got %v", err)
	}
	if err := (&KnownIssueScanConfig{Severities: []string{"super-bad"}}).Validate(); err == nil {
		t.Error("expected error for invalid severity")
	}
}

// --- external_harvester.go ---------------------------------------------------

func TestExternalHarvesterConfig_Validate(t *testing.T) {
	if err := DefaultExternalHarvesterConfig().Validate(); err != nil {
		t.Errorf("default should validate, got %v", err)
	}
	if err := (&ExternalHarvesterConfig{Sources: []string{"made-up"}}).Validate(); err == nil {
		t.Error("expected error for unknown source")
	}
	// key-required source without key
	if err := (&ExternalHarvesterConfig{Sources: []string{"urlscan"}}).Validate(); err == nil {
		t.Error("expected error: urlscan requires an api key")
	}
	if err := (&ExternalHarvesterConfig{Sources: []string{"virustotal"}}).Validate(); err == nil {
		t.Error("expected error: virustotal requires an api key")
	}
	// key-required source WITH key passes
	cfg := &ExternalHarvesterConfig{Sources: []string{"urlscan", "virustotal"}}
	cfg.APIKeys.URLScan = "k1"
	cfg.APIKeys.VirusTotal = "k2"
	if err := cfg.Validate(); err != nil {
		t.Errorf("with keys should validate, got %v", err)
	}
}

// --- mutation_strategy.go ----------------------------------------------------

func TestFieldTypeDefaults_ToMap(t *testing.T) {
	f := DefaultMutationStrategyConfig().FieldTypeDefaults
	m := f.ToMap()
	// spot-check a few keys round-trip from the struct
	for _, key := range []string{"string", "uuid", "email", "file_upload"} {
		if len(m[key]) == 0 {
			t.Errorf("ToMap()[%q] is empty, expected defaults", key)
		}
	}
	if got, want := m["string"], f.String; len(got) != len(want) {
		t.Errorf("string entries = %d, want %d", len(got), len(want))
	}
	if len(m) != 21 {
		t.Errorf("ToMap() produced %d keys, want 21", len(m))
	}
}

// writeFileForTest is a tiny helper to drop a file for path-validation tests.
func writeFileForTest(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
