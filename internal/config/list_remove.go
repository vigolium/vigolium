package config

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/pathglob"
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

// RejectDetail is RejectReason plus the pattern responsible: the exclude
// pattern that matched, the include list that admitted nothing, the origin
// mode, or the static extension. Both are "" when host/path is in scope.
func (m *ScopeMatcher) RejectDetail(host, path string) (rule, pattern string) {
	rule = m.RejectReason(host, path)
	if m == nil || rule == "" {
		return rule, ""
	}
	lower := func(s string) string { return strings.ToLower(s) }
	switch rule {
	case ScopeRuleHostExclude:
		for _, p := range m.cfg.Host.Exclude {
			if globMatch(lower(host), lower(p)) {
				return rule, p
			}
		}
	case ScopeRuleHostInclude:
		return rule, strings.Join(m.cfg.Host.Include, ", ")
	case ScopeRuleCLIOriginMode:
		return rule, m.cfg.CLIOriginMode
	case ScopeRulePathExclude:
		for _, p := range m.cfg.Path.Exclude {
			if pathGlobMatch(lower(pathglob.ScopePath(path)), lower(p)) {
				return rule, p
			}
		}
	case ScopeRulePathInclude:
		return rule, strings.Join(m.cfg.Path.Include, ", ")
	case ScopeRuleStaticFile:
		if i := strings.LastIndex(pathglob.ScopePath(path), "."); i >= 0 {
			return rule, pathglob.ScopePath(path)[i:]
		}
	}
	return rule, ""
}
