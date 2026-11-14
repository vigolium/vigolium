package modkit

import "strings"

// TechCategory groups stack tags so the tech gate can tell "this host is
// positively something else" from "this host is not fully known".
type TechCategory string

const (
	// TechCategoryBackend: server-side frameworks and languages.
	TechCategoryBackend TechCategory = "backend"
	// TechCategoryPlatform: CMS and SaaS platforms.
	TechCategoryPlatform TechCategory = "platform"
	// TechCategoryMeta: JS meta-frameworks (SSR/SSG front ends).
	TechCategoryMeta TechCategory = "meta"
	// TechCategoryProtocol: API protocols.
	TechCategoryProtocol TechCategory = "protocol"
	// TechCategoryServer: web/application servers. Never excludes on its own:
	// a reverse proxy's banner says nothing about the application behind it.
	TechCategoryServer TechCategory = "server"
)

// techTagCategories is the canonical set of technology-STACK tags the tech
// gate recognises, with each tag's category. When a module declares one of
// these in its Tags() slice and does NOT implement TechAware explicitly, the
// executor treats the intersection as its required tech allowlist.
//
// Any other tag a fingerprint module publishes (spa, angular, javascript, …)
// is DESCRIPTIVE: recorded for recon output and http_records.technology, never
// used to gate. "javascript" was in this set and gated 24 passive JS modules on
// a tag only meta-framework fingerprints set (MISS-21).
//
// Keep this list aligned with the tags published by the *_fingerprint passive
// modules and the recon agent (pkg/agent/recon/fingerprint.go).
var techTagCategories = map[string]TechCategory{
	// Backend frameworks
	"spring":  TechCategoryBackend,
	"django":  TechCategoryBackend,
	"flask":   TechCategoryBackend,
	"fastapi": TechCategoryBackend,
	"rails":   TechCategoryBackend,
	"laravel": TechCategoryBackend,
	"express": TechCategoryBackend,
	"nestjs":  TechCategoryBackend,
	"aspnet":  TechCategoryBackend,
	"symfony": TechCategoryBackend,
	// Languages / runtimes
	"php":    TechCategoryBackend,
	"java":   TechCategoryBackend,
	"ruby":   TechCategoryBackend,
	"python": TechCategoryBackend,
	"nodejs": TechCategoryBackend,
	"dotnet": TechCategoryBackend,
	// Meta-frameworks
	"nextjs":     TechCategoryMeta,
	"nuxt":       TechCategoryMeta, // emitted by recon/fingerprint.go and metaframework_fingerprint
	"nuxtjs":     TechCategoryMeta, // emitted by jsframework.NuxtJS
	"remix":      TechCategoryMeta,
	"sveltekit":  TechCategoryMeta,
	"solidstart": TechCategoryMeta,
	"astro":      TechCategoryMeta,
	"qwik":       TechCategoryMeta,
	"gatsby":     TechCategoryMeta,
	// CMS / SaaS platforms
	"wordpress":  TechCategoryPlatform,
	"drupal":     TechCategoryPlatform,
	"joomla":     TechCategoryPlatform,
	"aem":        TechCategoryPlatform, // Adobe Experience Manager (Sling/CRX/Granite)
	"adobe":      TechCategoryPlatform, // published alongside "aem" by aem_fingerprint
	"firebase":   TechCategoryPlatform,
	"salesforce": TechCategoryPlatform, // Salesforce Experience Cloud / Lightning
	"lightning":  TechCategoryPlatform, // published alongside "salesforce"
	"aura":       TechCategoryPlatform, // Salesforce Aura framework
	"servicenow": TechCategoryPlatform, // ServiceNow ITSM
	"powerpages": TechCategoryPlatform, // Microsoft Power Pages / Power Apps portals
	"dataverse":  TechCategoryPlatform, // published alongside "powerpages"
	// API protocols
	"graphql": TechCategoryProtocol,
	// Servers
	"tomcat": TechCategoryServer,
	"jetty":  TechCategoryServer,
	"jboss":  TechCategoryServer,
	"nginx":  TechCategoryServer,
	"apache": TechCategoryServer,
	"iis":    TechCategoryServer,
}

// IsStackTag reports whether tag (any case) is a gating stack tag.
func IsStackTag(tag string) bool {
	_, ok := techTagCategories[strings.ToLower(strings.TrimSpace(tag))]
	return ok
}

// TechCategoryOf returns tag's category, or "" for a descriptive tag.
func TechCategoryOf(tag string) TechCategory {
	return techTagCategories[strings.ToLower(strings.TrimSpace(tag))]
}

// DerivedRequiredTechs returns the stack tags among moduleTags (lowercased),
// the module's implicit required-tech allowlist.
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
		if _, ok := techTagCategories[lower]; ok {
			out = append(out, lower)
		}
	}
	return out
}
