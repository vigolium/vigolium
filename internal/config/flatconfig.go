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

// credentialLeafWords are leaf-name words that make a string setting a
// credential. A whole word of the leaf, split on "_" and "-": "token" matches
// bot_token but not max_tokens, and "secret" matches secret_key. A boolean like
// disable_secret_scan matches too, which is why callers classify string
// settings only.
var credentialLeafWords = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true, "key": true, "apikey": true,
	"credential": true, "credentials": true, "authorization": true, "cookie": true,
}

// credentialLeafPairs are two-word leaf names that are credentials as a pair.
var credentialLeafPairs = []string{"auth_header", "chat_id", "webhook_url"}

// envRefInValue matches ${NAME}, ${NAME:-default} and $NAME references, the
// forms ExpandEnvVars fills in.
var envRefInValue = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-[^}]*)?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

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
			*entries = append(*entries, ConfigEntry{Key: key, Value: "[" + strings.Join(parts, ", ") + "]"})
		case string:
			*entries = append(*entries, ConfigEntry{Key: key, Value: val, Sensitive: IsSensitiveEntry(key, val)})
		default:
			*entries = append(*entries, ConfigEntry{Key: key, Value: fmt.Sprintf("%v", val)})
		}
	}
}

// IsSensitiveEntry reports whether a string setting's value must be redacted
// for display: its key names a credential, or the value interpolates an
// environment variable ("${API_KEY}"), which typically resolves to one. It is
// the one classifier behind `config ls`, `config set` and GET /api/config; a
// caller applies it to string settings only, so a boolean such as
// disable_secret_scan is never withheld.
func IsSensitiveEntry(key, value string) bool {
	return isCredentialKey(key) || envRefInValue.MatchString(value)
}

// isCredentialKey reports whether a dotted settings key names a credential:
// any key under a parent named api_keys, a leaf whose words include a
// credential word, or a webhook URL.
func isCredentialKey(key string) bool {
	parts := strings.Split(strings.ToLower(key), ".")
	parents, leaf := parts[:len(parts)-1], parts[len(parts)-1]
	for _, p := range parents {
		if p == "api_keys" {
			return true
		}
	}
	for _, pair := range credentialLeafPairs {
		if leaf == pair || strings.HasSuffix(leaf, "_"+pair) || strings.HasPrefix(leaf, pair+"_") {
			return true
		}
	}
	for _, w := range strings.FieldsFunc(leaf, func(r rune) bool { return r == '_' || r == '-' }) {
		if credentialLeafWords[w] {
			return true
		}
	}
	// A webhook URL carries its token in the path (Slack, Discord, Teams);
	// other *.url settings (oast.server_url, storage.gcs.url) are not secret.
	if leaf == "url" {
		for _, p := range parents {
			if p == "webhook" || p == "hook" || strings.HasSuffix(p, "_webhook") {
				return true
			}
		}
	}
	return false
}
