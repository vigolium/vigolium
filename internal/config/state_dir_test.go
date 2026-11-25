package config

import (
	"path/filepath"
	"testing"
)

// TestExpandPathFollowsStateDir: every default spelled ~/.vigolium/... (the
// config file, the default database, native-sessions, the active project)
// lands under VIGOLIUM_STATE_DIR, and a path that is not vigolium state still
// expands under HOME.
func TestExpandPathFollowsStateDir(t *testing.T) {
	home, state := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("VIGOLIUM_STATE_DIR", state)

	for in, want := range map[string]string{
		homeConfigFile:                             filepath.Join(state, "vigolium-configs.yaml"),
		DefaultDatabaseConfig().SQLite.Path:        filepath.Join(state, "database-vgnm.sqlite"),
		(&ScanLogsConfig{}).EffectiveSessionsDir(): filepath.Join(state, "native-sessions"),
		"~/nuclei-templates":                       filepath.Join(state, "nuclei-templates"),
		"~/work/app":                               filepath.Join(home, "work", "app"),
	} {
		if got := filepath.Clean(ExpandPath(in)); got != want {
			t.Errorf("ExpandPath(%q) = %q, want %q", in, got, want)
		}
	}
	if got := ActiveProjectFilePath(); got != filepath.Join(state, "active-project") {
		t.Errorf("ActiveProjectFilePath = %q, want it under the state dir", got)
	}
}
