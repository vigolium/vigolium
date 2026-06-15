package config

import "testing"

func TestKnownIssueScanConfig_Validate_SeverityOverrides(t *testing.T) {
	tests := []struct {
		name    string
		cfg     KnownIssueScanConfig
		wantErr bool
	}{
		{
			name:    "valid override",
			cfg:     KnownIssueScanConfig{SeverityOverrides: map[string]string{"config-json-exposure-fuzz": "medium"}},
			wantErr: false,
		},
		{
			name:    "valid override mixed case + spaces",
			cfg:     KnownIssueScanConfig{SeverityOverrides: map[string]string{"some-template": " HIGH "}},
			wantErr: false,
		},
		{
			name:    "invalid override severity",
			cfg:     KnownIssueScanConfig{SeverityOverrides: map[string]string{"some-template": "spicy"}},
			wantErr: true,
		},
		{
			name:    "nil overrides ok",
			cfg:     KnownIssueScanConfig{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultKnownIssueScanConfig_ConfigJSONIsMedium(t *testing.T) {
	cfg := DefaultKnownIssueScanConfig()
	if got := cfg.SeverityOverrides["config-json-exposure-fuzz"]; got != "medium" {
		t.Errorf("default config-json-exposure-fuzz override = %q, want %q", got, "medium")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("default config must validate: %v", err)
	}
}

func TestDefaultFindingGrouping_GroupsSourcemapByModule(t *testing.T) {
	gc := DefaultKnownIssueScanConfig().ResolveGroupByValue()
	if !gc.Enabled || !gc.PerHost {
		t.Fatalf("default grouping should be enabled per-host, got %+v", gc)
	}
	set := make(map[string]bool, len(gc.ByModule))
	for _, m := range gc.ByModule {
		set[m] = true
	}
	// sourcemap-detect plus the per-asset source-analysis / hygiene family collapse
	// to one finding per host regardless of per-URL value.
	for _, want := range []string{
		"sourcemap-detect",
		"unsafe-html-sink",
		"dom-xss-taint",
		"cookie-security-detect",
		"server-action-auth",
	} {
		if !set[want] {
			t.Errorf("default ByModule should include %q, got %v", want, gc.ByModule)
		}
	}
	// Secret-bearing modules stay value-grouped so distinct leaked secrets remain
	// distinct findings — they must NOT collapse by module.
	if set["env-secret-exposure"] {
		t.Errorf("env-secret-exposure must not be in default ByModule (value is signal), got %v", gc.ByModule)
	}
}
