package config

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ErrUnknownKey marks a SetField key that does not name a setting. It is a
// mistake on the caller's command line, not a failure to write the config, so
// `config set` reports it as a usage error (exit 2).
var ErrUnknownKey = errors.New("unknown config key")

// ErrInvalidValue marks a SetField value that cannot be stored under its key: a
// list or map that does not parse, an element of the wrong type, an empty or
// JSON-residue list element, or a value that would introduce an error-level
// validation issue (see ValidateSettings). Like ErrUnknownKey it is a mistake on
// the caller's command line, so `config set` reports it as a usage error.
var ErrInvalidValue = errors.New("invalid config value")

// SetField updates a field in the Settings struct using dot-notation key and string value.
// It round-trips through a map[string]any to handle arbitrary nesting.
//
// List and map fields accept a JSON or YAML flow value (`["a","b"]`, `[a, b]`,
// `{"k":"v"}`), decoded against the field's declared type so `[1,2]` into a list
// of strings is refused rather than stringified. The legacy comma form (`a,b`)
// still works for lists, with every element checked. A value that would add an
// error-level ValidateSettings issue at key is refused and settings is left
// untouched.
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
		return fmt.Errorf("empty key: %w", ErrUnknownKey)
	}

	// List-op suffix: `<list_path>.add <value>` appends; `<list_path>.clear`
	// resets to an empty list. Only fires when the parent path resolves to a
	// list — otherwise fall through to normal scalar handling so a legitimate
	// scalar field literally named `add` or `clear` still works.
	if len(parts) >= 2 {
		last := parts[len(parts)-1]
		if last == "add" || last == "clear" {
			parentPath := parts[:len(parts)-1]
			listPath := strings.Join(parentPath, ".")
			parentMap, listKey, err := navigateToParent(raw, parentPath)
			if err == nil {
				declared, _ := resolveSettingType(listPath)
				list, isList := parentMap[listKey].([]any)
				if isList || (parentMap[listKey] == nil && isListType(declared)) {
					switch last {
					case "add":
						items, err := parseListAddition(listPath, value, declared)
						if err != nil {
							return err
						}
						parentMap[listKey] = append(list, items...)
					case "clear":
						parentMap[listKey] = []any{}
					}
					return commitRaw(raw, settings, listPath)
				}
			}
		}
	}

	// Navigate to the parent map, creating containers for segments that the
	// omitempty YAML round-trip dropped (an unset field like notify.telegram is
	// absent from `raw`). A missing segment is only created after the full key
	// validates against the Settings struct schema, so typos still error.
	current := raw
	for i := 0; i < len(parts)-1; i++ {
		child, ok := current[parts[i]]
		if !ok {
			if _, valid := resolveSettingKind(key); !valid {
				return fmt.Errorf("key %q not found (unknown segment %q): %w", key, parts[i], ErrUnknownKey)
			}
			newMap := map[string]any{}
			current[parts[i]] = newMap
			current = newMap
			continue
		}
		childMap, ok := child.(map[string]any)
		if !ok {
			return fmt.Errorf("key %q is not a map (at segment %q): %w", key, parts[i], ErrUnknownKey)
		}
		current = childMap
	}

	// Set the leaf. Lists and maps are parsed against the field's declared
	// type. Scalars that already exist in the round-tripped map coerce against
	// their present value; ones dropped by omitempty coerce against the field's
	// declared kind (validating the key on the way).
	leafKey := parts[len(parts)-1]
	declared, valid := resolveSettingType(key)
	existing, exists := current[leafKey]
	if !exists && !valid {
		return fmt.Errorf("key %q not found (unknown segment %q): %w", key, leafKey, ErrUnknownKey)
	}
	switch {
	case isContainerType(declared) || isContainerValue(existing):
		v, err := parseContainerValue(key, value, declared, existing)
		if err != nil {
			return err
		}
		current[leafKey] = v
	case valid && declared.Kind() != reflect.Interface:
		// The declared type decides, strictly: `yes` for a bool or `1.5` for
		// an int is refused instead of being stored as false or a string.
		v, err := coerceValueForType(key, value, declared)
		if err != nil {
			return err
		}
		current[leafKey] = v
	default:
		current[leafKey] = coerceValue(value, existing)
	}

	return commitRaw(raw, settings, key)
}

// commitRaw decodes the mutated raw map into a scratch Settings, refuses the
// write when it introduces an error-level validation issue at key, and only
// then replaces *settings. Decoding into a fresh value rather than on top of
// settings also means a replaced map is replaced: yaml.v3 merges a mapping into
// an existing map, so `{"x":"high"}` would otherwise keep every old entry.
func commitRaw(raw map[string]any, settings *Settings, key string) error {
	newData, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("failed to marshal updated config: %w", err)
	}
	var candidate Settings
	if err := yaml.Unmarshal(newData, &candidate); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInvalidValue, key, err)
	}
	if introduced := introducedErrors(ValidateSettings(settings), ValidateSettings(&candidate), key); len(introduced) > 0 {
		msgs := make([]string, 0, len(introduced))
		for _, is := range introduced {
			m := is.Message
			if is.Fix != "" {
				m += " (fix: " + is.Fix + ")"
			}
			msgs = append(msgs, m)
		}
		return fmt.Errorf("%w: %s", ErrInvalidValue, strings.Join(msgs, "; "))
	}
	carryUnserialized(reflect.ValueOf(&candidate).Elem(), reflect.ValueOf(settings).Elem())
	*settings = candidate
	return nil
}

// introducedErrors returns the error-level issues in after that were not in
// before and that concern key (the key itself, or something beneath it). A
// pre-existing problem elsewhere must not block an unrelated edit — that edit
// may be the first step of fixing it — and neither may a section-level rule
// that only a later `config set` can satisfy (storage.enabled before
// storage.bucket).
func introducedErrors(before, after []Issue, key string) []Issue {
	seen := make(map[Issue]bool, len(before))
	for _, is := range before {
		seen[is] = true
	}
	var out []Issue
	for _, is := range after {
		if is.Severity != SeverityError || seen[is] {
			continue
		}
		if is.Key == key || strings.HasPrefix(is.Key, key+".") || strings.HasPrefix(is.Key, key+"[") {
			out = append(out, is)
		}
	}
	return out
}

// carryUnserialized copies every `yaml:"-"` field from src into dst, walking
// nested structs. Those fields are runtime state (DatabaseConfig.ReadIntent)
// that the YAML round-trip cannot carry, and replacing *settings wholesale must
// not reset them.
func carryUnserialized(dst, src reflect.Value) {
	for i := 0; i < dst.NumField(); i++ {
		f := dst.Type().Field(i)
		if !f.IsExported() {
			continue
		}
		if f.Tag.Get("yaml") == "-" {
			dst.Field(i).Set(src.Field(i))
			continue
		}
		if f.Type.Kind() == reflect.Struct {
			carryUnserialized(dst.Field(i), src.Field(i))
		}
	}
}

// resolveSettingType walks the Settings struct type along the dot-notation key,
// following yaml tag names, and returns the declared type of the leaf (pointers
// stripped). ok is false when any segment names a field that does not exist (a
// typo). Descending through a map[string]X consumes one segment as a dynamic
// key and continues into X, so arbitrary keys under maps (e.g.
// known_issue_scan.severity_overrides.<code>) validate.
func resolveSettingType(key string) (reflect.Type, bool) {
	t := reflect.TypeOf(Settings{})
	for _, seg := range strings.Split(key, ".") {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		switch t.Kind() {
		case reflect.Struct:
			ft, ok := yamlFieldType(t, seg)
			if !ok {
				return nil, false
			}
			t = ft
		case reflect.Map:
			// seg is a dynamic map key; descend into the element type.
			t = t.Elem()
		default:
			// More segments remain but the current type is a scalar/slice.
			return nil, false
		}
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t, true
}

// resolveSettingKind is resolveSettingType reduced to the leaf's reflect.Kind.
func resolveSettingKind(key string) (reflect.Kind, bool) {
	t, ok := resolveSettingType(key)
	if !ok {
		return reflect.Invalid, false
	}
	return t.Kind(), true
}

// yamlFieldType returns the type of the struct field whose yaml tag name matches
// name. Fields tagged `yaml:"-"` are skipped; an empty tag name falls back to
// the yaml default (the lowercased field name).
func yamlFieldType(t reflect.Type, name string) (reflect.Type, bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		if tag == "-" {
			continue
		}
		tagName, _, _ := strings.Cut(tag, ",")
		if tagName == "" {
			tagName = strings.ToLower(f.Name)
		}
		if tagName == name {
			return f.Type, true
		}
	}
	return nil, false
}

// coerceValueForType converts value to the concrete type of a struct field.
// Booleans take strconv.ParseBool's spellings only and integers must parse
// exactly; anything else is ErrInvalidValue rather than a silent false, zero or
// string. A time.Duration also accepts a duration string ("30s").
func coerceValueForType(key, value string, t reflect.Type) (any, error) {
	if t == reflect.TypeOf(time.Duration(0)) {
		if _, err := time.ParseDuration(value); err == nil {
			return value, nil
		}
	}
	switch t.Kind() {
	case reflect.Bool:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("%w: %s expects true or false, got %q", ErrInvalidValue, key, value)
		}
		return b, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(strings.TrimSpace(value), 10, t.Bits())
		if err != nil {
			return nil, fmt.Errorf("%w: %s expects an integer, got %q", ErrInvalidValue, key, value)
		}
		return n, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, t.Bits())
		if err != nil {
			return nil, fmt.Errorf("%w: %s expects a non-negative integer, got %q", ErrInvalidValue, key, value)
		}
		return n, nil
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(strings.TrimSpace(value), t.Bits())
		if err != nil {
			return nil, fmt.Errorf("%w: %s expects a number, got %q", ErrInvalidValue, key, value)
		}
		return f, nil
	default:
		return value, nil
	}
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

// coerceValue converts a string value to match the type of the existing value.
// When existing is nil — which happens for pointer fields (e.g. *bool) whose
// initial value marshals to YAML null — the value's shape is sniffed:
// "true"/"false" → bool, integers → int, decimals → float64, otherwise the
// raw string is returned. The sniff is conservative: only unambiguous shapes
// coerce; anything else falls through unchanged.
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
	case nil:
		// Pointer field (e.g. *bool) whose initial value is nil — round-tripped
		// through YAML as null. Infer the type from the value's shape.
		// ParseBool is tried first because *bool is the only pointer scalar
		// in use today; if a *int or *float64 field is ever added, this
		// ordering must be revisited — values like "0" / "1" would coerce
		// to bool rather than the intended numeric type.
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
		if n, err := strconv.Atoi(value); err == nil {
			return n
		}
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return f
		}
		return value
	default:
		return value
	}
}
