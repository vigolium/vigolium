package config

import (
	"encoding/json"
	"fmt"
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
	// Sensitive marks a string credential (see IsSensitiveEntry): redact its
	// value for display.
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
		if str, ok := e.Value.(string); ok && e.Type == "string" {
			e.Sensitive = IsSensitiveEntry(key, str)
		}
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
			name, inline, ok := yamlKey(t.Field(i))
			switch {
			case !ok:
			case inline:
				walkSettings(prefix, v.Field(i), out)
			default:
				walkSettings(joinKey(prefix, name), v.Field(i), out)
			}
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

// DisplaySettingValue renders a SettingEntry value as one line of text: lists
// as "[a, b]", objects as JSON, everything else with fmt.
func DisplaySettingValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			parts = append(parts, DisplaySettingValue(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		raw, err := json.Marshal(x)
		if err != nil {
			return fmt.Sprint(x)
		}
		return string(raw)
	}
	return fmt.Sprint(v)
}
