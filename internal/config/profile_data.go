package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ApplyProfileData overlays a profile document held in memory (an embedded
// overlay such as public/presets/overlays/safe.yaml) onto settings, with the
// same key-preserving rules as LoadProfile + ApplyProfile. source names the
// document in errors.
func ApplyProfileData(settings *Settings, data []byte, source string) error {
	content := ExpandEnvVars(string(data))
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return fmt.Errorf("failed to parse profile %s: %w", source, err)
	}
	var profile ProfileSettings
	if err := doc.Decode(&profile); err != nil {
		return fmt.Errorf("failed to parse profile %s: %w", source, err)
	}
	profile.raw = topLevelSectionNodes(&doc)
	return ApplyProfile(settings, &profile)
}
