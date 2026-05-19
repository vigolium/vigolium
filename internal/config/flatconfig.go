package config

import (
	"fmt"
	"regexp"
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

// sensitiveKeyWords match a whole token of a (lowercased) key after splitting
// on ".", "_", and "-". Whole-word matching avoids false positives like
// "max_tokens" (a count) being treated as a credential.
var sensitiveKeyWords = map[string]struct{}{
	"key":           {},
	"token":         {},
	"secret":        {},
	"authorization": {},
}

// sensitiveKeyPathContains marks an entry sensitive when one of the listed
// parent path tokens appears AND the leaf is `url`. This catches webhook
// URLs whose key path is `notify.webhook.url` — the suffix-based list
// can't match because plain `.url` would over-redact every config field
// that happens to end in `url` (e.g. `oast.server.url`, `storage.gcs.url`).
var sensitiveKeyPathContains = map[string]struct{}{
	"webhook": {},
	"hook":    {},
}

// keyWordSeparators splits dot-notation keys into atomic words.
var keyWordSeparators = func(r rune) bool {
	return r == '.' || r == '_' || r == '-'
}

// envRefPattern matches values that interpolate an environment variable, e.g.
// "${API_KEY}" or "${HOME}/path". Such values are treated as sensitive because
// they typically resolve to credentials at runtime.
var envRefPattern = regexp.MustCompile(`\$\{[^}]+\}`)

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
			value := "[" + strings.Join(parts, ", ") + "]"
			*entries = append(*entries, ConfigEntry{
				Key:       key,
				Value:     value,
				Sensitive: isSensitiveEntry(key, value),
			})
		default:
			value := fmt.Sprintf("%v", val)
			*entries = append(*entries, ConfigEntry{
				Key:       key,
				Value:     value,
				Sensitive: isSensitiveEntry(key, value),
			})
		}
	}
}

// isSensitiveEntry reports whether a config entry should be redacted in
// human-readable output. A key is sensitive if it ends with a known
// credential-shaped suffix, contains "key" / "token" / "secret" anywhere, or
// if the value interpolates an environment variable (e.g. "${API_KEY}").
func isSensitiveEntry(key, value string) bool {
	if isSensitiveKey(key) {
		return true
	}
	return envRefPattern.MatchString(value)
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, suffix := range sensitiveKeysSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	words := strings.FieldsFunc(lower, keyWordSeparators)
	for _, word := range words {
		if _, ok := sensitiveKeyWords[word]; ok {
			return true
		}
	}
	// "webhook.*.url" / "*.hook.*.url" pattern — the leaf is `url` AND a
	// hook-shaped token appears earlier in the path. Catches per-channel
	// webhook URLs whose tokens often live in the URL itself (Slack,
	// Discord, Teams) without over-redacting unrelated `*.url` entries.
	if len(words) >= 2 && words[len(words)-1] == "url" {
		for _, w := range words[:len(words)-1] {
			if _, ok := sensitiveKeyPathContains[w]; ok {
				return true
			}
		}
	}
	return false
}
