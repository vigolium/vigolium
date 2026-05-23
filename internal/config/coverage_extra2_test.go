package config

import (
	"testing"
	"time"
)

// --- storage.go --------------------------------------------------------------

func TestStorageConfig_IsEnabled_EnvOverride(t *testing.T) {
	tr := true
	cfg := &StorageConfig{Enabled: &tr}

	// env truthy/falsy overrides win over YAML
	t.Setenv(StorageEnabledEnvVar, "off")
	if cfg.IsEnabled() {
		t.Error("env 'off' should force-disable even when YAML enabled")
	}
	t.Setenv(StorageEnabledEnvVar, "1")
	if !(&StorageConfig{}).IsEnabled() {
		t.Error("env '1' should force-enable even when YAML unset")
	}
	// unrecognized env value falls through to YAML
	t.Setenv(StorageEnabledEnvVar, "maybe")
	if !cfg.IsEnabled() {
		t.Error("unrecognized env should fall back to YAML enabled=true")
	}
}

func TestStorageConfig_Effective(t *testing.T) {
	if got := (&StorageConfig{}).EffectiveDriver(); got != "gcs" {
		t.Errorf("default driver = %q, want gcs", got)
	}
	if got := (&StorageConfig{Driver: "s3"}).EffectiveDriver(); got != "s3" {
		t.Errorf("driver = %q, want s3", got)
	}
	if got := (&StorageConfig{Driver: "minio"}).EffectiveDriver(); got != "minio" {
		t.Errorf("driver = %q, want minio", got)
	}

	if got := (&StorageConfig{}).EffectiveEndpoint(); got != "storage.googleapis.com" {
		t.Errorf("gcs endpoint = %q", got)
	}
	if got := (&StorageConfig{Driver: "s3"}).EffectiveEndpoint(); got != "s3.amazonaws.com" {
		t.Errorf("s3 endpoint = %q", got)
	}
	if got := (&StorageConfig{Driver: "minio"}).EffectiveEndpoint(); got != "" {
		t.Errorf("minio endpoint should be empty without explicit config, got %q", got)
	}
	if got := (&StorageConfig{Endpoint: "custom:9000"}).EffectiveEndpoint(); got != "custom:9000" {
		t.Errorf("explicit endpoint = %q", got)
	}

	if !(&StorageConfig{}).EffectiveUseSSL() {
		t.Error("UseSSL should default to true")
	}
	fa := false
	if (&StorageConfig{UseSSL: &fa}).EffectiveUseSSL() {
		t.Error("explicit UseSSL=false should be honored")
	}
	if (&StorageConfig{}).EffectivePathStyle() {
		t.Error("PathStyle should default to false")
	}
	tr := true
	if !(&StorageConfig{PathStyle: &tr}).EffectivePathStyle() {
		t.Error("explicit PathStyle=true should be honored")
	}
}

func TestStorageConfig_Validate(t *testing.T) {
	// Validate()->IsEnabled() reads VIGOLIUM_STORAGE_ENABLED; pin it empty so an
	// env var set on the dev box / CI runner can't flip the "disabled" cases.
	t.Setenv(StorageEnabledEnvVar, "")

	// disabled -> always valid
	if err := (&StorageConfig{}).Validate(); err != nil {
		t.Errorf("disabled storage should validate, got %v", err)
	}

	tr := true
	base := func() *StorageConfig {
		return &StorageConfig{Enabled: &tr, Bucket: "b", AccessKey: "a", SecretKey: "s", Driver: "s3"}
	}
	if err := base().Validate(); err != nil {
		t.Errorf("complete config should validate, got %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*StorageConfig)
	}{
		{"missing bucket", func(c *StorageConfig) { c.Bucket = "" }},
		{"missing access key", func(c *StorageConfig) { c.AccessKey = "" }},
		{"missing secret key", func(c *StorageConfig) { c.SecretKey = "" }},
		{"minio without endpoint", func(c *StorageConfig) { c.Driver = "minio"; c.Endpoint = "" }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			tt.mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

// --- spidering.go ------------------------------------------------------------

func TestSpideringConfig_MaxDurationParsed(t *testing.T) {
	if got := (&SpideringConfig{}).MaxDurationParsed(); got != 30*time.Minute {
		t.Errorf("empty = %v, want 30m", got)
	}
	if got := (&SpideringConfig{MaxDuration: "5m"}).MaxDurationParsed(); got != 5*time.Minute {
		t.Errorf("parsed = %v, want 5m", got)
	}
	if got := (&SpideringConfig{MaxDuration: "garbage"}).MaxDurationParsed(); got != 30*time.Minute {
		t.Errorf("invalid fallback = %v, want 30m", got)
	}
}

func TestSpideringConfig_Validate(t *testing.T) {
	if err := DefaultSpideringConfig().Validate(); err != nil {
		t.Errorf("default should validate, got %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*SpideringConfig)
	}{
		{"negative max_depth", func(c *SpideringConfig) { c.MaxDepth = -1 }},
		{"negative max_states", func(c *SpideringConfig) { c.MaxStates = -1 }},
		{"negative consecutive fails", func(c *SpideringConfig) { c.MaxConsecutiveFails = -1 }},
		{"negative browser_count", func(c *SpideringConfig) { c.BrowserCount = -1 }},
		{"invalid duration", func(c *SpideringConfig) { c.MaxDuration = "bogus" }},
		{"invalid strategy", func(c *SpideringConfig) { c.Strategy = "weird" }},
		{"invalid engine", func(c *SpideringConfig) { c.BrowserEngine = "weird" }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultSpideringConfig()
			tt.mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

// --- scan.go -----------------------------------------------------------------

func TestScanLogsConfig(t *testing.T) {
	if (&ScanLogsConfig{}).IsPersistLogsEnabled() {
		t.Error("nil PersistLogs should be disabled")
	}
	tr := true
	if !(&ScanLogsConfig{PersistLogs: &tr}).IsPersistLogsEnabled() {
		t.Error("explicit true should be enabled")
	}

	if got := (&ScanLogsConfig{}).EffectiveSessionsDir(); got == "" {
		t.Error("default sessions dir should be non-empty")
	}
	if got := (&ScanLogsConfig{SessionsDir: "/tmp/native"}).EffectiveSessionsDir(); got != "/tmp/native" {
		t.Errorf("sessions dir = %q, want /tmp/native", got)
	}
}
