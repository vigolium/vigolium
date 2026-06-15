package modules

import "strings"

// ContentClassAware is implemented by modules whose findings structurally
// require a specific response body class (the canonical names mirror
// modkit.ContentClass: "html", "json", "xml", "text", "binary"). The executor
// skips such a module on a record whose response is a confirmed *different*
// structured class (it fails open on unknown / text). A module that does not
// implement this interface — and carries none of the content-class tags below —
// runs against every content type.
//
// This gate is applied to PASSIVE modules only: a passive analyzer that cannot
// parse the body shape it was given produces nothing, so skipping it can never
// hide a finding it could otherwise have made. Active modules are intentionally
// not gated this way — many probe a host independently of the triggering
// record's body, where content-class gating would cause false negatives.
type ContentClassAware interface {
	RequiredContentClasses() []string
}

// contentClassByTag maps a module tag to the content classes the module is
// meaningful against. The map is intentionally tiny and conservative: it lists
// only tags whose presence unambiguously implies a body shape (clickjacking /
// UI-redress require a framable HTML document). Adding an entry here gates every
// module carrying that tag, so only structurally-certain mappings belong.
var contentClassByTag = map[string][]string{
	"clickjacking": {"html"},
	"ui-redress":   {"html"},
}

// DerivedContentClasses returns the content classes implied by a module's tags
// using contentClassByTag. Returns nil when no tag maps to a class (the module
// is content-agnostic). Used as the fallback when a module does not implement
// ContentClassAware explicitly.
func DerivedContentClasses(moduleTags []string) []string {
	if len(moduleTags) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, t := range moduleTags {
		classes, ok := contentClassByTag[strings.ToLower(strings.TrimSpace(t))]
		if !ok {
			continue
		}
		for _, c := range classes {
			if _, dup := seen[c]; dup {
				continue
			}
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	return out
}
