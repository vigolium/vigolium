package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// TestConfigWatcher_HotReloadsStorage covers the path that previously caused
// audit runs to fail with "storage is not enabled in config" after the user
// edited the YAML to enable storage post-startup. The watcher used to drop
// storage edits on the floor (storage was missing from reloadableSections).
func TestConfigWatcher_HotReloadsStorage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vigolium-configs.yaml")

	initial := `storage:
    enabled: false
    driver: gcs
    bucket: vigolium-artifact-dev
    region: asia-southeast1
`
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatalf("write initial: %v", err)
	}

	settings, err := LoadSettings(path)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if settings.Storage.IsEnabled() {
		t.Fatalf("expected storage disabled at start")
	}

	cw, err := NewConfigWatcher(path, settings)
	if err != nil {
		t.Fatalf("NewConfigWatcher: %v", err)
	}
	defer func() { _ = cw.Close() }()

	reloaded := make(chan []string, 1)
	cw.OnReload(func(changed []string) {
		select {
		case reloaded <- changed:
		default:
		}
	})
	cw.Start()

	updated := `storage:
    enabled: true
    driver: gcs
    bucket: vigolium-artifact-dev
    region: asia-southeast1
`
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatalf("write updated: %v", err)
	}

	select {
	case changed := <-reloaded:
		if !slices.Contains(changed, "storage") {
			t.Fatalf("storage not in reloaded sections: %v", changed)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for hot reload")
	}

	if !settings.Storage.IsEnabled() {
		t.Fatalf("storage still disabled after hot reload")
	}
}

// TestConfigWatcher_HotReloadsAgentOlium covers `vigolium config set
// agent.olium.*` while the server is running: switching provider/model/
// oauth_cred_path must land in the shared Settings pointer so the next agent
// run picks up the new olium settings without a restart. The cached agent
// engine reads settings.Agent.Olium fresh on every run, so updating the
// pointer is all that's required.
func TestConfigWatcher_HotReloadsAgentOlium(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vigolium-configs.yaml")

	initial := `agent:
    olium:
        provider: openai-compatible
        model: gemma4:latest
`
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatalf("write initial: %v", err)
	}

	settings, err := LoadSettings(path)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if got := settings.Agent.Olium.Provider; got != "openai-compatible" {
		t.Fatalf("unexpected initial provider: %q", got)
	}

	cw, err := NewConfigWatcher(path, settings)
	if err != nil {
		t.Fatalf("NewConfigWatcher: %v", err)
	}
	defer func() { _ = cw.Close() }()

	reloaded := make(chan []string, 1)
	cw.OnReload(func(changed []string) {
		select {
		case reloaded <- changed:
		default:
		}
	})
	cw.Start()

	updated := `agent:
    olium:
        provider: openai-codex-oauth
        model: gpt-5.5
        oauth_cred_path: ~/.codex/auth.json
`
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatalf("write updated: %v", err)
	}

	select {
	case changed := <-reloaded:
		if !slices.Contains(changed, "agent") {
			t.Fatalf("agent not in reloaded sections: %v", changed)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for hot reload")
	}

	if got := settings.Agent.Olium.Provider; got != "openai-codex-oauth" {
		t.Fatalf("provider not hot-reloaded: got %q", got)
	}
	if got := settings.Agent.Olium.Model; got != "gpt-5.5" {
		t.Fatalf("model not hot-reloaded: got %q", got)
	}
}
