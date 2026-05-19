package modules

import "strings"

// knownTechTags is the canonical set of technology-stack tags that the tech
// filter recognises. When a module declares one of these in its Tags() slice
// and does NOT implement TechAware explicitly, the executor treats the
// intersection as its required tech allowlist.
//
// Keep this list aligned with the tags published by the *_fingerprint passive
// modules and the recon agent (pkg/agent/recon/fingerprint.go). Adding a new
// stack here is the only step needed to enable filtering for it — every
// existing module tagged with that name picks the new gate up automatically.
var knownTechTags = map[string]struct{}{
	// Frameworks
	"spring":     {},
	"django":     {},
	"flask":      {},
	"fastapi":    {},
	"rails":      {},
	"laravel":    {},
	"express":    {},
	"nestjs":     {},
	"nextjs":     {},
	"nuxt":       {}, // emitted by recon/fingerprint.go and metaframework_fingerprint
	"nuxtjs":     {}, // emitted by jsframework.NuxtJS

	"remix":      {},
	"sveltekit":  {},
	"solidstart": {},
	"astro":      {},
	"qwik":       {},
	"gatsby":     {},
	"aspnet":     {},
	"firebase":   {},
	"symfony":    {},
	// CMS
	"wordpress": {},
	"drupal":    {},
	"joomla":    {},
	// API protocols
	"graphql": {},
	// Java application servers (publishes alongside "java")
	"tomcat": {},
	"jetty":  {},
	"jboss":  {},
	// Languages
	"php":        {},
	"java":       {},
	"ruby":       {},
	"python":     {},
	"nodejs":     {},
	"javascript": {},
	"dotnet":     {},
	// Servers (rarely used as a sole gate but allowed)
	"nginx":  {},
	"apache": {},
	"iis":    {},
}

// DerivedRequiredTechs returns the intersection of moduleTags and the known
// tech-tag set. When a module does not implement TechAware explicitly, the
// executor uses this as its required-tech allowlist so framework-specific
// modules (tagged "spring", "rails", etc.) are gated automatically.
func DerivedRequiredTechs(moduleTags []string) []string {
	if len(moduleTags) == 0 {
		return nil
	}
	var out []string
	for _, t := range moduleTags {
		lower := strings.ToLower(strings.TrimSpace(t))
		if lower == "" {
			continue
		}
		if _, ok := knownTechTags[lower]; ok {
			out = append(out, lower)
		}
	}
	return out
}
