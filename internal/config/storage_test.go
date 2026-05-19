package config

import "testing"

func TestStorageIsEnabledEnvOverride(t *testing.T) {
	enabledTrue := true
	enabledFalse := false

	cases := []struct {
		name   string
		cfg    *StorageConfig
		env    string
		envSet bool
		want   bool
	}{
		{name: "yaml false, no env", cfg: &StorageConfig{Enabled: &enabledFalse}, want: false},
		{name: "yaml true, no env", cfg: &StorageConfig{Enabled: &enabledTrue}, want: true},
		{name: "yaml nil, no env", cfg: &StorageConfig{}, want: false},

		{name: "env=true overrides yaml false", cfg: &StorageConfig{Enabled: &enabledFalse}, env: "true", envSet: true, want: true},
		{name: "env=1 overrides yaml false", cfg: &StorageConfig{Enabled: &enabledFalse}, env: "1", envSet: true, want: true},
		{name: "env=YES overrides yaml false", cfg: &StorageConfig{Enabled: &enabledFalse}, env: "YES", envSet: true, want: true},
		{name: "env=on with whitespace overrides yaml false", cfg: &StorageConfig{Enabled: &enabledFalse}, env: " on ", envSet: true, want: true},

		{name: "env=false overrides yaml true", cfg: &StorageConfig{Enabled: &enabledTrue}, env: "false", envSet: true, want: false},
		{name: "env=0 overrides yaml true", cfg: &StorageConfig{Enabled: &enabledTrue}, env: "0", envSet: true, want: false},

		{name: "unrecognized env value falls back to yaml", cfg: &StorageConfig{Enabled: &enabledTrue}, env: "maybe", envSet: true, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envSet {
				t.Setenv(StorageEnabledEnvVar, tc.env)
			} else {
				// t.Setenv with "" still sets it; explicitly clear via Unsetenv via Setenv to "" is fine
				// because IsEnabled checks v != "" before consulting it.
				t.Setenv(StorageEnabledEnvVar, "")
			}
			if got := tc.cfg.IsEnabled(); got != tc.want {
				t.Errorf("IsEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}
