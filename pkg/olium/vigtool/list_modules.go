package vigtool

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

const defaultModuleListLimit = 200

// NewListModulesTool returns the list_modules tool — a read-only enumeration
// of the built-in active/passive module registry with filtering. Gives the
// agent a concrete catalog so run_scan/run_module aren't guessing at names.
func NewListModulesTool() tool.Tool {
	return &listModulesTool{}
}

type listModulesTool struct{}

func (*listModulesTool) Name() string     { return "list_modules" }
func (*listModulesTool) Label() string    { return "List scanner modules" }
func (*listModulesTool) Category() string { return tool.CategoryVigolium }
func (*listModulesTool) IsReadOnly() bool { return true }
func (*listModulesTool) Description() string {
	return "List vigolium's built-in scanner modules (active + passive) with their tags, severity, and " +
		"scan scope. Use this before run_scan / run_module to pick exact module IDs or tags — module " +
		"names are not stable across versions, so list and filter rather than guessing. Supports " +
		"filters by kind ('active'|'passive'), tag (e.g. 'xss', 'spring'), severity, and substring " +
		"match on id/name."
}

func (*listModulesTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"kind": map[string]any{
				"type":        "string",
				"enum":        []string{"active", "passive", "all"},
				"description": "Restrict by module kind. Default 'all'.",
			},
			"tag": map[string]any{
				"type":        "string",
				"description": "Filter to modules carrying this tag (case-insensitive). e.g. 'xss', 'spring', 'light'.",
			},
			"severity": map[string]any{
				"type":        "string",
				"description": "Filter by severity (critical/high/medium/low/info). Case-insensitive.",
			},
			"search": map[string]any{
				"type":        "string",
				"description": "Substring match against module id and name (case-insensitive).",
			},
			"limit": map[string]any{
				"type":        "integer",
				"description": fmt.Sprintf("Max modules to return. Default and cap %d.", defaultModuleListLimit),
			},
		},
	}
}

type moduleEntry struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"` // "active" | "passive"
	Severity   string   `json:"severity,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Scope      string   `json:"scope,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Short      string   `json:"short,omitempty"`
}

func (l *listModulesTool) Execute(_ context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	kind := strings.ToLower(argsString(args, "kind"))
	if kind == "" {
		kind = "all"
	}
	tag := strings.ToLower(argsString(args, "tag"))
	sev := strings.ToLower(argsString(args, "severity"))
	search := strings.ToLower(argsString(args, "search"))
	limit := argsInt(args, "limit")
	if limit <= 0 || limit > defaultModuleListLimit {
		limit = defaultModuleListLimit
	}

	entries := make([]moduleEntry, 0, 128)

	if kind == "all" || kind == "active" {
		for _, m := range modules.DefaultRegistry.GetActiveModules() {
			e := moduleEntry{
				ID:         m.ID(),
				Name:       m.Name(),
				Kind:       "active",
				Severity:   m.Severity().String(),
				Confidence: m.Confidence().String(),
				Scope:      m.ScanScopes().String(),
				Tags:       m.Tags(),
				Short:      m.ShortDescription(),
			}
			if matchesModule(e, tag, sev, search) {
				entries = append(entries, e)
			}
		}
	}
	if kind == "all" || kind == "passive" {
		for _, m := range modules.DefaultRegistry.GetPassiveModules() {
			e := moduleEntry{
				ID:         m.ID(),
				Name:       m.Name(),
				Kind:       "passive",
				Severity:   m.Severity().String(),
				Confidence: m.Confidence().String(),
				Tags:       m.Tags(),
				Short:      m.ShortDescription(),
			}
			if matchesModule(e, tag, sev, search) {
				entries = append(entries, e)
			}
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind < entries[j].Kind
		}
		return entries[i].ID < entries[j].ID
	})

	total := len(entries)
	truncated := false
	if total > limit {
		entries = entries[:limit]
		truncated = true
	}

	out := struct {
		Total     int           `json:"total_matching"`
		Returned  int           `json:"returned"`
		Truncated bool          `json:"truncated,omitempty"`
		Modules   []moduleEntry `json:"modules"`
	}{
		Total:     total,
		Returned:  len(entries),
		Truncated: truncated,
		Modules:   entries,
	}
	body, _ := json.Marshal(out)
	return tool.Result{
		Content: string(body),
		Details: map[string]any{
			"total":    total,
			"returned": len(entries),
		},
	}, nil
}

// matchesModule returns true when the entry passes every supplied filter.
// Filters with empty values are no-ops.
func matchesModule(e moduleEntry, tag, sev, search string) bool {
	if tag != "" {
		hit := false
		for _, t := range e.Tags {
			if strings.ToLower(t) == tag {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if sev != "" && !strings.EqualFold(e.Severity, sev) {
		return false
	}
	if search != "" {
		if !strings.Contains(strings.ToLower(e.ID), search) &&
			!strings.Contains(strings.ToLower(e.Name), search) {
			return false
		}
	}
	return true
}
