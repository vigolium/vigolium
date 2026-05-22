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

	// List-op suffix: `<list_path>.add <value>` appends; `<list_path>.clear`
	// resets to an empty list. Only fires when the parent path resolves to a
	// list (`[]any`) — otherwise fall through to normal scalar handling so a
	// legitimate scalar field literally named `add` or `clear` still works.
	if len(parts) >= 2 {
		last := parts[len(parts)-1]
		if last == "add" || last == "clear" {
			parentPath := parts[:len(parts)-1]
			parentMap, listKey, err := navigateToParent(raw, parentPath)
			if err == nil {
				if list, isList := parentMap[listKey].([]any); isList || parentMap[listKey] == nil {
					switch last {
					case "add":
						parentMap[listKey] = append(list, value)
					case "clear":
						parentMap[listKey] = []any{}
					}
					return marshalBack(raw, settings)
				}
			}
		}
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

	return marshalBack(raw, settings)
}

// navigateToParent walks `raw` along `parts[:len(parts)-1]` and returns the
// terminal parent map plus the final segment, so the caller can read or
// rewrite parent[final].
func navigateToParent(raw map[string]any, parts []string) (map[string]any, string, error) {
	if len(parts) == 0 {
		return nil, "", fmt.Errorf("empty path")
	}
	current := raw
	for i := 0; i < len(parts)-1; i++ {
		child, ok := current[parts[i]]
		if !ok {
			return nil, "", fmt.Errorf("unknown segment %q", parts[i])
		}
		childMap, ok := child.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("segment %q is not a map", parts[i])
		}
		current = childMap
	}
	return current, parts[len(parts)-1], nil
}

// marshalBack writes the mutated `raw` map back into `settings` via YAML.
func marshalBack(raw map[string]any, settings *Settings) error {
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
