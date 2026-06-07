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
