package skill

import (
	"context"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// NewLoadTool returns the load_skill tool, bound to reg. The tool serves
// skill bodies from the in-memory registry — which is necessary for
// embedded skills (whose "paths" point inside the binary's embed FS and
// aren't reachable via read_file) and desirable for disk-based skills
// (the registry already parsed them once at startup).
func NewLoadTool(reg *Registry) tool.Tool {
	return &loadTool{reg: reg}
}

type loadTool struct{ reg *Registry }

func (*loadTool) Name() string     { return "load_skill" }
func (*loadTool) Label() string    { return "Load skill" }
func (*loadTool) Category() string { return tool.CategoryBuiltin }
func (*loadTool) IsReadOnly() bool { return true }
func (*loadTool) Description() string {
	return "Fetch a skill's full body text by name. Use this for any skill listed in <available_skills>; prefer it over read_file, since embedded skills don't have filesystem paths and disk-based skills are already parsed into memory."
}

func (*loadTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{
				"type":        "string",
				"description": "The skill name as listed in <available_skills> (e.g. 'audit-auth').",
			},
		},
		"required": []string{"name"},
	}
}

func (t *loadTool) Execute(_ context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	rawName, _ := args["name"].(string)
	name := strings.TrimSpace(rawName)
	if name == "" {
		return tool.Result{
			Content: "load_skill: name is required",
			IsError: true,
		}, nil
	}
	if t.reg == nil {
		return tool.Result{
			Content: fmt.Sprintf("load_skill: no skill registry available (requested %q)", name),
			IsError: true,
		}, nil
	}
	s := t.reg.Get(name)
	if s == nil {
		available := skillNames(t.reg)
		return tool.Result{
			Content: fmt.Sprintf("load_skill: unknown skill %q. Available: %s", name, strings.Join(available, ", ")),
			IsError: true,
		}, nil
	}
	// Frame the body so the model treats it as instructional input rather
	// than something to quote verbatim in its reply.
	var b strings.Builder
	fmt.Fprintf(&b, "<skill name=\"%s\" source=\"%s\">\n", s.Name, s.Source)
	b.WriteString(s.Body)
	if !strings.HasSuffix(s.Body, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("</skill>")
	return tool.Result{
		Content: b.String(),
		Details: map[string]any{
			"skill":  s.Name,
			"source": string(s.Source),
			"bytes":  len(s.Body),
		},
	}, nil
}

func skillNames(reg *Registry) []string {
	all := reg.List()
	names := make([]string, 0, len(all))
	for _, s := range all {
		names = append(names, s.Name)
	}
	return names
}
