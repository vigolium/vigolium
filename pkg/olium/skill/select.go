package skill

import (
	"fmt"
	"strings"
)

// SelectOptions controls which skills survive into the engine-facing registry
// when planner-driven filtering is active. The selected set is the union of
// Picks, AlwaysOn, Forced, and every skill carrying a ForcedTag.
type SelectOptions struct {
	// Picks are planner-recommended skill names (attack_plan.recommended_skills,
	// or an autopilot pre-flight selection).
	Picks []string
	// AlwaysOn names are included regardless of the planner — general-purpose
	// skills that filtering should never starve.
	AlwaysOn []string
	// Forced names come from an operator override (--skill) and bypass the
	// planner's judgement.
	Forced []string
	// ForcedTags include every registered skill carrying any of these tags
	// (--skill-tag), matched against the normalized frontmatter tags.
	ForcedTags []string
	// DisableFilter (--no-skill-filter) returns the source registry unchanged.
	DisableFilter bool
}

// Select returns a new Registry containing only the skills named in Picks,
// AlwaysOn, or Forced, plus any skill tagged with a ForcedTag — all resolved
// against r and emitted in r's stable List() order. Names that don't resolve
// to a registered skill, and tags that match nothing, are dropped and reported
// in the returned warnings.
//
// When DisableFilter is set, r is returned unchanged (the full set). A nil or
// empty registry is returned as-is. Otherwise the result is always a fresh
// Registry — never a view into r — so callers can attach a load_skill tool to
// the filtered set safely.
func (r *Registry) Select(opts SelectOptions) (*Registry, []string) {
	if r == nil || r.Len() == 0 || opts.DisableFilter {
		return r, nil
	}

	want := map[string]struct{}{}
	var warnings []string
	add := func(names []string, origin string) {
		for _, n := range names {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			if r.skills[n] == nil {
				warnings = append(warnings, fmt.Sprintf("skill: %s references unknown skill %q (ignored)", origin, n))
				continue
			}
			want[n] = struct{}{}
		}
	}
	add(opts.Picks, "planner")
	add(opts.AlwaysOn, "always-on")
	add(opts.Forced, "--skill")

	// Tag expansion: include any registered skill carrying a forced tag.
	if len(opts.ForcedTags) > 0 {
		tagSet := map[string]struct{}{}
		for _, t := range opts.ForcedTags {
			if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
				tagSet[t] = struct{}{}
			}
		}
		matched := map[string]bool{}
		for _, s := range r.List() {
			for _, t := range s.Tags {
				if _, ok := tagSet[t]; ok {
					want[s.Name] = struct{}{}
					matched[t] = true
					break
				}
			}
		}
		for t := range tagSet {
			if !matched[t] {
				warnings = append(warnings, fmt.Sprintf("skill: --skill-tag %q matched no skills (ignored)", t))
			}
		}
	}

	out := &Registry{skills: map[string]*Skill{}}
	for _, s := range r.List() { // preserve r's stable order
		if _, ok := want[s.Name]; ok {
			out.skills[s.Name] = s
			out.order = append(out.order, s.Name)
		}
	}
	return out, warnings
}
