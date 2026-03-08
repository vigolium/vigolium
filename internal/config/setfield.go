package config

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// SetField updates a field in the Settings struct using dot-notation key and string value.
// It round-trips through a map[string]any to handle arbitrary nesting.
func SetField(settings *Settings, key string, value string) error {
	// Marshal settings to YAML, then unmarshal into generic map
	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	// Split key into parts and navigate to the leaf
	parts := strings.Split(key, ".")
	if len(parts) == 0 {
		return fmt.Errorf("empty key")
	}

	// Navigate to the parent map
	current := raw
	for i := 0; i < len(parts)-1; i++ {
		child, ok := current[parts[i]]
		if !ok {
			return fmt.Errorf("key %q not found (unknown segment %q)", key, parts[i])
		}
		childMap, ok := child.(map[string]any)
		if !ok {
			return fmt.Errorf("key %q is not a map (at segment %q)", key, parts[i])
		}
		current = childMap
	}

	// Check the leaf key exists
	leafKey := parts[len(parts)-1]
	existing, ok := current[leafKey]
	if !ok {
		return fmt.Errorf("key %q not found (unknown segment %q)", key, leafKey)
	}

	// Coerce value to match the existing type
	current[leafKey] = coerceValue(value, existing)

	// Marshal map back to YAML, then unmarshal into Settings
	newData, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("failed to marshal updated config: %w", err)
	}

	if err := yaml.Unmarshal(newData, settings); err != nil {
		return fmt.Errorf("failed to unmarshal updated config: %w", err)
	}

	return nil
}

// coerceValue converts a string value to match the type of the existing value
func coerceValue(value string, existing any) any {
	switch existing.(type) {
	case bool:
		return strings.EqualFold(value, "true") || value == "1"
	case int:
		if n, err := strconv.Atoi(value); err == nil {
			return n
		}
		return value
	case float64:
		if n, err := strconv.ParseFloat(value, 64); err == nil {
			return n
		}
		return value
	case []any:
		// Split comma-separated values
		parts := strings.Split(value, ",")
		result := make([]any, len(parts))
		for i, p := range parts {
			result[i] = strings.TrimSpace(p)
		}
		return result
	default:
		return value
	}
}
