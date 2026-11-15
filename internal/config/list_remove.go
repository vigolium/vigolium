package config

import (
	"fmt"
	"strings"
)

// removeListItems drops every element of list equal (as text) to one of drop.
func removeListItems(list []any, drop []any) []any {
	gone := map[string]bool{}
	for _, d := range drop {
		gone[fmt.Sprint(d)] = true
	}
	out := make([]any, 0, len(list))
	for _, item := range list {
		if !gone[fmt.Sprint(item)] {
			out = append(out, item)
		}
	}
	return out
}

// removedListItems is the text of the elements a `<list>.remove <value>`
// names, for the raw-file edit (yamledit.RemoveItems matches scalars by text).
func removedListItems(listPath, value string) []string {
	declared, _ := resolveSettingType(listPath)
	items, err := parseListAddition(listPath, value, declared)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, strings.TrimSpace(fmt.Sprint(it)))
	}
	return out
}
