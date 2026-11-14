package modules

import "github.com/vigolium/vigolium/pkg/modules/modkit"

// DerivedRequiredTechs returns the intersection of moduleTags and the known
// stack-tag set (modkit/tech_tags.go). When a module does not implement
// TechAware explicitly, the executor uses this as its required-tech allowlist
// so framework-specific modules (tagged "spring", "rails", etc.) are gated
// automatically.
func DerivedRequiredTechs(moduleTags []string) []string {
	return modkit.DerivedRequiredTechs(moduleTags)
}
