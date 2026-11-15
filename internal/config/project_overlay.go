package config

import (
	"fmt"
	"reflect"
	"strings"
)

// SettingPath returns the setting a SetField key writes: the key itself, or the
// list path for a `<list>.add` / `<list>.clear` op.
func SettingPath(key string) string {
	parent, last, ok := cutLast(key)
	if ok && (last == "add" || last == "clear" || last == "remove") {
		if t, valid := resolveSettingType(parent); valid && isListType(t) {
			return parent
		}
	}
	return key
}

func cutLast(key string) (string, string, bool) {
	i := strings.LastIndex(key, ".")
	if i < 0 {
		return "", key, false
	}
	return key[:i], key[i+1:], true
}

// SetProjectOverlayValue writes the value settings holds at key into the
// project's overlay file (ProjectConfigPath) and returns the file path. See
// SetProjectOverlayEdit.
func SetProjectOverlayValue(projectUUID, key string, settings *Settings) (string, error) {
	key = SettingPath(key)
	v, ok := SettingValue(settings, key)
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownKey, key)
	}
	return SetProjectOverlayEdit(projectUUID, key, SetPathEdit(key, v))
}

// SetProjectOverlayEdit applies edit, which changes the setting key, to the
// project's overlay file and returns the file path.
//
// Only that one key is written, not the whole section: copying the effective
// section would freeze the global values of every sibling key into the
// project, so a later global change would stop applying to it. The file is
// edited in place, so its comments and placeholders survive. An overlay that
// exists but does not parse is refused rather than replaced — overwriting it
// would discard whatever the operator had in it. The write is atomic.
func SetProjectOverlayEdit(projectUUID, key string, edit RawEdit) (string, error) {
	if strings.TrimSpace(projectUUID) == "" {
		return "", fmt.Errorf("project overlay: no project selected")
	}
	key = SettingPath(key)
	section, _, _ := strings.Cut(key, ".")
	if _, ok := yamlFieldType(reflect.TypeOf(ProfileSettings{}), section); !ok {
		return "", fmt.Errorf("%w: %q cannot be set in a project config (allowed sections are the scanning-profile ones)", ErrUnknownKey, section)
	}
	path, err := EditProjectOverlay(projectUUID, edit)
	if err != nil {
		return "", fmt.Errorf("project config %s: %w", ContractPath(ProjectConfigPath(projectUUID)), err)
	}
	return path, nil
}
