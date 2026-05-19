package cli

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

func TestApplyGlobalExtFlagsAppendsScriptsAndEnables(t *testing.T) {
	settings := &config.Settings{}
	settings.DynamicAssessment.Extensions.CustomDir = []string{"already-loaded.js"}

	// Set the package-global flags as cobra would.
	t.Cleanup(func() {
		globalExtScripts = nil
		globalExtDir = ""
	})
	globalExtScripts = []string{"a.js", "b.js"}

	applyGlobalExtFlagsToSettings(settings)

	ext := settings.DynamicAssessment.Extensions
	if !ext.Enabled {
		t.Error("Extensions should be enabled when --ext is set")
	}
	if len(ext.CustomDir) != 3 {
		t.Errorf("CustomDir should keep existing + add 2, got %d entries: %v", len(ext.CustomDir), ext.CustomDir)
	}
	if ext.CustomDir[0] != "already-loaded.js" {
		t.Errorf("existing entries should not be reordered, got %q", ext.CustomDir[0])
	}
}

func TestApplyGlobalExtFlagsSetsExtDir(t *testing.T) {
	settings := &config.Settings{}
	t.Cleanup(func() {
		globalExtScripts = nil
		globalExtDir = ""
	})
	globalExtDir = "/tmp/myext"

	applyGlobalExtFlagsToSettings(settings)

	if !settings.DynamicAssessment.Extensions.Enabled {
		t.Error("Extensions should be enabled when --ext-dir is set")
	}
	if settings.DynamicAssessment.Extensions.ExtensionDir != "/tmp/myext" {
		t.Errorf("ExtensionDir = %q, want /tmp/myext", settings.DynamicAssessment.Extensions.ExtensionDir)
	}
}

func TestApplyGlobalExtFlagsNoop(t *testing.T) {
	settings := &config.Settings{}
	t.Cleanup(func() {
		globalExtScripts = nil
		globalExtDir = ""
	})

	applyGlobalExtFlagsToSettings(settings)
	if settings.DynamicAssessment.Extensions.Enabled {
		t.Error("Extensions should remain disabled when no flags set")
	}
}

func TestApplyGlobalExtFlagsNilSettingsSafe(t *testing.T) {
	// Defensive — should not panic.
	applyGlobalExtFlagsToSettings(nil)
}
