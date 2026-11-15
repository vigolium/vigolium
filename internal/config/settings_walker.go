package config

import (
	"reflect"
	"sort"
	"strings"
	"time"
)

// SettingEntry is one settable key of Settings with its typed value.
//
// Value and Default are JSON-ready: bool, int64, float64, string, []any or
// map[string]any (a time.Duration renders as its string form, "30s"). A key
// set to false, 0 or "" is still an entry, so "set to false" and "no such key"
// are different answers.
type SettingEntry struct {
	Key     string
	Value   any
	Default any
	// Type is bool, int, float, string, duration, list or map.
	Type string
	// Sensitive marks a string credential: redact its value for display.
	Sensitive bool
}

// SettingEntries walks settings by reflection and returns every settable
// leaf key, sorted, with the default from DefaultSettings(). Struct fields
// recurse; maps of scalars expand into one entry per map key (an empty map is
// one entry); slices are leaves.
func SettingEntries(settings *Settings) []SettingEntry {
	if settings == nil {
		settings = DefaultSettings()
	}
	values := map[string]reflect.Value{}
	walkSettings("", reflect.ValueOf(settings).Elem(), values)
	defaults := map[string]reflect.Value{}
	walkSettings("", reflect.ValueOf(DefaultSettings()).Elem(), defaults)

	entries := make([]SettingEntry, 0, len(values))
	for key, v := range values {
		e := SettingEntry{Key: key, Value: plainValue(v), Type: settingType(v.Type())}
		if d, ok := defaults[key]; ok {
			e.Default = plainValue(d)
		}
		e.Sensitive = e.Type == "string" && IsCredentialKey(key)
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries
}

// walkSettings records every leaf under v, keyed by its dotted yaml path.
func walkSettings(prefix string, v reflect.Value, out map[string]reflect.Value) {
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			// A nil pointer to a struct still names its keys, with the zero
			// value: the key exists and is unset.
			if v.Kind() == reflect.Pointer && v.Type().Elem().Kind() == reflect.Struct {
				walkSettings(prefix, reflect.New(v.Type().Elem()).Elem(), out)
				return
			}
			if prefix != "" {
				out[prefix] = v
			}
			return
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			out[prefix] = v
			return
		}
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			tag := f.Tag.Get("yaml")
			if tag == "-" {
				continue
			}
			name, opts, _ := strings.Cut(tag, ",")
			if strings.Contains(opts, "inline") {
				walkSettings(prefix, v.Field(i), out)
				continue
			}
			if name == "" {
				name = strings.ToLower(f.Name)
			}
			walkSettings(joinKey(prefix, name), v.Field(i), out)
		}
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String || v.Len() == 0 || !scalarKind(v.Type().Elem()) {
			out[prefix] = v
			return
		}
		for _, k := range v.MapKeys() {
			out[joinKey(prefix, k.String())] = v.MapIndex(k)
		}
	default:
		out[prefix] = v
	}
}

func joinKey(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

func scalarKind(t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Bool, reflect.String, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

// settingType names a leaf's type for SettingEntry.Type.
func settingType(t reflect.Type) string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeOf(time.Duration(0)) {
		return "duration"
	}
	switch t.Kind() {
	case reflect.Bool:
		return "bool"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "int"
	case reflect.Float32, reflect.Float64:
		return "float"
	case reflect.Slice, reflect.Array:
		return "list"
	case reflect.Map, reflect.Struct, reflect.Interface:
		return "map"
	}
	return "string"
}

// plainValue converts a leaf to a JSON-ready value.
func plainValue(v reflect.Value) any {
	if !v.IsValid() {
		return nil
	}
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Type() == reflect.TypeOf(time.Duration(0)) {
		return time.Duration(v.Int()).String()
	}
	if v.Type() == reflect.TypeOf(time.Time{}) {
		t := v.Interface().(time.Time)
		if t.IsZero() {
			return ""
		}
		return t.Format(time.RFC3339)
	}
	switch v.Kind() {
	case reflect.Bool:
		return v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int64(v.Uint())
	case reflect.Float32, reflect.Float64:
		return v.Float()
	case reflect.String:
		return v.String()
	case reflect.Slice, reflect.Array:
		out := make([]any, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			out = append(out, plainValue(v.Index(i)))
		}
		return out
	case reflect.Map:
		out := make(map[string]any, v.Len())
		for _, k := range v.MapKeys() {
			out[k.String()] = plainValue(v.MapIndex(k))
		}
		return out
	case reflect.Struct:
		inner := map[string]reflect.Value{}
		walkSettings("", v, inner)
		out := make(map[string]any, len(inner))
		for k, iv := range inner {
			out[k] = plainValue(iv)
		}
		return out
	}
	return v.Interface()
}

// credentialLeafWords are leaf-name words that make a string setting a
// credential. A whole word of the leaf, split on "_" and "-": "token" matches
// bot_token but not max_tokens, and "secret" matches secret_key but a
// boolean like disable_secret_scan is never a string.
var credentialLeafWords = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true, "apikey": true,
	"credential": true, "credentials": true, "authorization": true, "cookie": true,
}

// credentialLeafPairs are two-word leaf names that are credentials as a pair.
var credentialLeafPairs = []string{"api_key", "access_key", "secret_key", "private_key", "auth_header", "chat_id", "webhook_url"}

// IsCredentialKey reports whether a dotted settings key names a credential:
// any key under a parent named api_keys, a leaf whose words include a
// credential word, or a webhook URL. It classifies the key alone; callers
// apply it to string settings only.
func IsCredentialKey(key string) bool {
	lower := strings.ToLower(key)
	parts := strings.Split(lower, ".")
	for _, p := range parts[:len(parts)-1] {
		if p == "api_keys" {
			return true
		}
	}
	leaf := parts[len(parts)-1]
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
	// A webhook URL carries its token in the path (Slack, Discord, Teams).
	if leaf == "url" {
		for _, p := range parts[:len(parts)-1] {
			if p == "webhook" || p == "hook" || strings.HasSuffix(p, "_webhook") {
				return true
			}
		}
	}
	return false
}

// LookupSetting returns the entry for one key (exact match), for a reader
// that wants a single typed value (`config get`).
func LookupSetting(settings *Settings, key string) (SettingEntry, bool) {
	for _, e := range SettingEntries(settings) {
		if e.Key == key {
			return e, true
		}
	}
	return SettingEntry{}, false
}
