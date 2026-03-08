package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ConfigEntry represents a single flattened config key-value pair
type ConfigEntry struct {
	Key       string
	Value     string
	Sensitive bool
}

// sensitiveKeysSuffixes are key suffixes that should be masked in display
var sensitiveKeysSuffixes = []string{"password", "bot_token", "webhook_url", "chat_id", "api_key"}

// FlattenSettings converts a Settings struct into a flat list of dot-notation key-value pairs
func FlattenSettings(settings *Settings) []ConfigEntry {
	// Marshal to YAML then unmarshal into a generic map to walk the structure
	data, err := yaml.Marshal(settings)
	if err != nil {
		return nil
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}

	var entries []ConfigEntry
	flattenMap("", raw, &entries)
	return entries
}

func flattenMap(prefix string, m map[string]any, entries *[]ConfigEntry) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}

		switch val := v.(type) {
		case map[string]any:
			flattenMap(key, val, entries)
		case []any:
			// Format slices as bracket-wrapped comma-separated values
			parts := make([]string, 0, len(val))
			for _, item := range val {
				parts = append(parts, fmt.Sprintf("%v", item))
			}
			*entries = append(*entries, ConfigEntry{
				Key:       key,
				Value:     "[" + strings.Join(parts, ", ") + "]",
				Sensitive: isSensitiveKey(key),
			})
		default:
			*entries = append(*entries, ConfigEntry{
				Key:       key,
				Value:     fmt.Sprintf("%v", val),
				Sensitive: isSensitiveKey(key),
			})
		}
	}
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, suffix := range sensitiveKeysSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}
