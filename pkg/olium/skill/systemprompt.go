package skill

import (
	"fmt"
	"strings"
)

// InjectIntoSystemPrompt appends an <available_skills> block listing
// every registered skill's name, description, and on-disk location.
// Returns base unchanged when no skills are registered.
//
// The format matches pi-mono / agentskills.io conventions so user-authored
// skills originally written for Claude Code or pi work with olium verbatim.
func InjectIntoSystemPrompt(base string, reg *Registry) string {
	if reg == nil || reg.Len() == 0 {
		return base
	}

	var b strings.Builder
	b.WriteString(strings.TrimRight(base, "\n"))
	b.WriteString("\n\n")
	b.WriteString("<available_skills>\n")
	b.WriteString("# Skills are instructional workflows available to you. Load a skill via the\n")
	b.WriteString("# load_skill tool when its description matches your task, then follow the\n")
	b.WriteString("# body's guidance. Skills can reference relative paths — resolve them\n")
	b.WriteString("# against the skill's own directory (listed as `location`'s parent).\n")
	for _, s := range reg.List() {
		fmt.Fprintf(&b, "  <skill>\n")
		fmt.Fprintf(&b, "    <name>%s</name>\n", s.Name)
		fmt.Fprintf(&b, "    <description>%s</description>\n", s.Description)
		fmt.Fprintf(&b, "    <location>%s</location>\n", s.Path)
		fmt.Fprintf(&b, "  </skill>\n")
	}
	b.WriteString("</available_skills>\n\n")
	b.WriteString("To invoke a skill, call load_skill with its name (NOT read_file on its\n")
	b.WriteString("location — embedded skills have no on-disk path). Follow the returned\n")
	b.WriteString("body. If no skill fits, use your own tools directly.")
	return b.String()
}

// ParseInlineInvocation recognizes the `/skill:name [args]` TUI shortcut.
// Returns (name, args, true) on match; ("", "", false) otherwise.
func ParseInlineInvocation(input string) (name, args string, ok bool) {
	const prefix = "/skill:"
	if !strings.HasPrefix(input, prefix) {
		return "", "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(input, prefix))
	if rest == "" {
		return "", "", false
	}
	parts := strings.SplitN(rest, " ", 2)
	name = parts[0]
	if len(parts) == 2 {
		args = strings.TrimSpace(parts[1])
	}
	return name, args, true
}

// ExpandInlineInvocation is used by the TUI's `/skill:name <args>` handler.
// It resolves the skill by name and returns a user-ready prompt that
// inlines the skill body plus the user's free-form args, so the model
// doesn't have to spend a tool call reading it.
//
// Returns (expanded, true) on success, ("", false) if the skill is unknown.
func ExpandInlineInvocation(reg *Registry, name, args string) (string, bool) {
	s := reg.Get(name)
	if s == nil {
		return "", false
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<skill_invocation name=\"%s\" location=\"%s\">\n", s.Name, s.Path)
	b.WriteString(s.Body)
	b.WriteString("\n</skill_invocation>\n\n")
	if strings.TrimSpace(args) != "" {
		fmt.Fprintf(&b, "Task: %s", args)
	} else {
		b.WriteString("Task: follow the skill's guidance for the current context.")
	}
	return b.String(), true
}
