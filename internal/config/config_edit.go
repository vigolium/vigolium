package config

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/vigolium/vigolium/internal/config/yamledit"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// RawEdit changes a raw (unexpanded) config document. Writers build one from
// the change they made to an in-memory Settings and apply it with
// EditConfigFile or EditProjectOverlay, so the file keeps its comments and
// every `${VAR}` placeholder: an in-memory Settings holds expanded values, and
// marshalling it back would write each secret in clear.
type RawEdit func(*yamledit.Doc) error

// EditConfigFile applies edits to the config file at path in place. The result
// is decoded with environment expansion on top of the defaults before it is
// written, and a result that would not load is refused with ErrInvalidValue. A
// missing file is created holding only the edited keys. It reports whether the
// file changed.
func EditConfigFile(path string, edits ...RawEdit) (bool, error) {
	path = ExpandPath(path)
	res, err := yamledit.EditFile(path, applyAll(edits), yamledit.Options{Validate: validateRawSettings})
	warnReencoded(path, res)
	return res.Changed, err
}

// EditProjectOverlay applies edits to a project's config overlay in place, the
// same way EditConfigFile does for the global file, and returns its path.
func EditProjectOverlay(projectUUID string, edits ...RawEdit) (string, error) {
	if strings.TrimSpace(projectUUID) == "" {
		return "", fmt.Errorf("project overlay: no project selected")
	}
	path := ProjectConfigPath(projectUUID)
	res, err := yamledit.EditFile(path, applyAll(edits), yamledit.Options{Validate: func(data []byte) error {
		if _, err := parseProfile(data, path); err != nil {
			return fmt.Errorf("%w: the edited project config would not load: %w", ErrInvalidValue, err)
		}
		return nil
	}})
	warnReencoded(path, res)
	if err != nil {
		return "", err
	}
	InvalidateProjectOverlay(projectUUID)
	return path, nil
}

// warnReencoded tells the operator when an edit could not be spliced into the
// file and rewrote it whole, which may reflow its blank lines and formatting.
func warnReencoded(path string, res yamledit.Result) {
	if res.Reencoded {
		zap.L().Warn("Could not edit the config file in place; rewrote it whole (comments kept, blank lines and formatting may change)",
			zap.String("file", ContractPath(path)))
	}
}

func applyAll(edits []RawEdit) func(*yamledit.Doc) error {
	return func(d *yamledit.Doc) error {
		for _, e := range edits {
			if e == nil {
				continue
			}
			if err := e(d); err != nil {
				return err
			}
		}
		return nil
	}
}

func validateRawSettings(data []byte) error {
	settings := *DefaultSettings()
	if err := yaml.Unmarshal([]byte(ExpandEnvVars(string(data))), &settings); err != nil {
		return fmt.Errorf("%w: the edited config would not load: %w", ErrInvalidValue, err)
	}
	return nil
}

// SetFieldEdit applies SetField(settings, key, value) and returns the RawEdit
// that stores the same change in a file. Only the setting key names is
// written, and its value is the one the caller supplied, never one read back
// from the expanded settings:
//   - `<list>.clear` writes `[]`;
//   - `<list>.add` appends just the new elements to the list in the file, or,
//     when the file does not hold that list (it came from the defaults or
//     another layer), writes the whole resulting list;
//   - anything else writes the parsed value at key.
func SetFieldEdit(settings *Settings, key, value string) (RawEdit, error) {
	path := SettingPath(key)
	op := ""
	if path != key {
		op = key[len(path)+1:]
	}
	oldLen := 0
	if op == "add" {
		if v, ok := settingValue(settings, path); ok && v.Kind() == reflect.Slice {
			oldLen = v.Len()
		}
	}
	if err := SetField(settings, key, value); err != nil {
		return nil, err
	}
	v, ok := settingValue(settings, path)
	if !ok {
		return nil, fmt.Errorf("key %q: %w", key, ErrUnknownKey)
	}
	parts := strings.Split(path, ".")
	full := v.Interface()
	switch op {
	case "remove":
		drop := removedListItems(path, value)
		return listEditOrSet(parts, full, func(d *yamledit.Doc) error {
			_, err := d.RemoveItems(parts, drop...)
			return err
		}), nil
	case "clear":
		return func(d *yamledit.Doc) error {
			return d.Set(parts, &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle})
		}, nil
	case "add":
		var added []*yaml.Node
		if v.Kind() == reflect.Slice && oldLen <= v.Len() {
			for i := oldLen; i < v.Len(); i++ {
				n, err := yamledit.Node(v.Index(i).Interface())
				if err != nil {
					return nil, err
				}
				added = append(added, n)
			}
		}
		return listEditOrSet(parts, full, func(d *yamledit.Doc) error {
			_, err := d.AppendUnique(parts, added...)
			return err
		}), nil
	default:
		n, err := yamledit.Node(full)
		if err != nil {
			return nil, err
		}
		return func(d *yamledit.Doc) error { return d.Set(parts, n) }, nil
	}
}

// listEditOrSet applies inPlace when the file holds the list at parts, and
// otherwise (the list's value came from the defaults or another layer) writes
// full, the whole resulting list.
func listEditOrSet(parts []string, full any, inPlace RawEdit) RawEdit {
	return func(d *yamledit.Doc) error {
		if cur := d.Get(parts); cur != nil && cur.Kind == yaml.SequenceNode {
			return inPlace(d)
		}
		n, err := yamledit.Node(full)
		if err != nil {
			return err
		}
		return d.Set(parts, n)
	}
}

// SetPathEdit returns a RawEdit that writes value at the dot-notation key.
func SetPathEdit(key string, value any) RawEdit {
	return func(d *yamledit.Doc) error {
		n, err := yamledit.Node(value)
		if err != nil {
			return err
		}
		return d.Set(strings.Split(key, "."), n)
	}
}

// SettingValue returns the value settings holds at the dot-notation key.
func SettingValue(settings *Settings, key string) (any, bool) {
	v, ok := settingValue(settings, key)
	if !ok {
		return nil, false
	}
	return v.Interface(), true
}

// SettingDisplay renders the value at key on one line, the way `config ls`
// shows it (DisplaySettingValue). ok is false for a key that names no setting.
func SettingDisplay(settings *Settings, key string) (string, bool) {
	v, ok := settingValue(settings, key)
	if !ok {
		return "", false
	}
	return DisplaySettingValue(plainValue(v)), true
}

// IsSensitiveSetting is IsSensitiveEntry for the setting at key: a string
// setting is withheld when its key names a credential or one of values (the
// supplied and the stored text) interpolates an environment variable; any
// other type never is.
func IsSensitiveSetting(settings *Settings, key string, values ...string) bool {
	v, ok := settingValue(settings, key)
	if !ok || v.Kind() != reflect.String {
		return false
	}
	for _, val := range values {
		if IsSensitiveEntry(key, val) {
			return true
		}
	}
	return false
}

// settingValue walks settings along the dot-notation key by yaml tag names. A
// nil pointer or a missing map entry yields the zero value of its type.
func settingValue(settings *Settings, key string) (reflect.Value, bool) {
	v := reflect.ValueOf(settings).Elem()
	for _, seg := range strings.Split(key, ".") {
		for v.Kind() == reflect.Pointer {
			if v.IsNil() {
				v = reflect.Zero(v.Type().Elem())
			} else {
				v = v.Elem()
			}
		}
		switch v.Kind() {
		case reflect.Struct:
			idx, ok := yamlFieldIndex(v.Type(), seg)
			if !ok {
				return reflect.Value{}, false
			}
			v = v.FieldByIndex(idx)
		case reflect.Map:
			mv := v.MapIndex(reflect.ValueOf(seg).Convert(v.Type().Key()))
			if !mv.IsValid() {
				mv = reflect.Zero(v.Type().Elem())
			}
			v = mv
		default:
			return reflect.Value{}, false
		}
	}
	for v.Kind() == reflect.Pointer && !v.IsNil() {
		v = v.Elem()
	}
	return v, true
}
