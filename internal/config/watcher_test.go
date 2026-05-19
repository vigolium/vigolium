package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestConfigWatcher_HotReloadsStorage covers the path that previously caused
// archon runs to fail with "storage is not enabled in config" after the user
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
		var sawStorage bool
		for _, s := range changed {
			if s == "storage" {
				sawStorage = true
			}
		}
		if !sawStorage {
			t.Fatalf("storage not in reloaded sections: %v", changed)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for hot reload")
	}

	if !settings.Storage.IsEnabled() {
		t.Fatalf("storage still disabled after hot reload")
	}
}
