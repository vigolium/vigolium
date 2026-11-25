package config

import "testing"

// No open migrates an outdated store by default; VIGOLIUM_AUTO_MIGRATE
// overrides auto_migrate_on_read in both directions.
func TestDatabaseMigratesImplicitly(t *testing.T) {
	t.Setenv(AutoMigrateEnvVar, "")
	cfg := DefaultDatabaseConfig()
	if cfg.AutoMigrateOnRead || cfg.MigratesImplicitly() {
		t.Fatal("the default configuration migrates implicitly")
	}
	for env, want := range map[string]bool{"1": true, "true": true, "on": true, "0": false, "off": false, "maybe": false} {
		t.Setenv(AutoMigrateEnvVar, env)
		if got := cfg.MigratesImplicitly(); got != want {
			t.Errorf("VIGOLIUM_AUTO_MIGRATE=%s: MigratesImplicitly = %v, want %v", env, got, want)
		}
	}
	cfg.AutoMigrateOnRead = true
	t.Setenv(AutoMigrateEnvVar, "0")
	if cfg.MigratesImplicitly() {
		t.Error("VIGOLIUM_AUTO_MIGRATE=0 did not override auto_migrate_on_read: true")
	}
	t.Setenv(AutoMigrateEnvVar, "")
	if !cfg.MigratesImplicitly() {
		t.Error("auto_migrate_on_read: true without the variable must migrate")
	}
}
