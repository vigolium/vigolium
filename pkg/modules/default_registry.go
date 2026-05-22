package modules

// MCP Security - Active

// JS Framework Security - Active

// WordPress Security - Active

// Drupal Security - Active

// Joomla Security - Active

// Cross-CMS Security - Active

// PHP Security - Active

// PHP Framework Security - Active

// Firebase Security - Active

// Cloud Storage Security - Active

// ASP.NET Security - Active

// Java/Spring Security - Active

// LDAP Injection - Active

// IDOR GUID - Active

// Cache Deception - Active

// Subdomain Takeover - Active

// PDF Generation Injection - Active

// Express/NestJS Security - Active

// Fastify/Hono Security - Active

// Meta-Framework Security - Active

// API Security - Active

// Common Directory Listing - Active

// Rails Security - Active

// API Spec Discovery & Ingestion - Active

// Python/Django/Flask/FastAPI Security - Active

// Auth/API Security - Active

// JS Framework Security - Passive

// Endpoint classification - Passive

// Drupal Security - Passive

// Joomla Security - Passive

// Firebase Security - Passive

// Cloud Storage Security - Passive

// Laravel Security - Passive

// Symfony - Passive

// PHP (generic) - Passive

// ASP.NET Security - Passive

// Spring/Java Security - Passive

// Express/NestJS Security - Passive

// Rails Security - Passive

// Python Security - Passive

// API Spec Detection - Passive

// API Security - Passive

// Protocol & Technology Detection - Passive

// JS Framework Source Analysis - Passive

// Security Headers Audit - Passive

// API Pagination & Error Analysis - Passive

// GraphQL Error Analysis - Passive

// Meta-Framework Fingerprinting - Passive

// Software Version Detection - Passive

// MCP Security - Passive

// Sensitive Data in Headers - Passive

// DefaultRegistry is the default registry with all built-in modules.
var DefaultRegistry = newDefaultRegistry()

// newDefaultRegistry assembles the registry of all built-in modules. The active
// and passive registrations live in default_registry_active.go and
// default_registry_passive.go respectively.
func newDefaultRegistry() *Registry {
	r := NewRegistry()
	registerActiveModules(r)
	registerPassiveModules(r)
	return r
}

// Convenience functions - delegate to DefaultRegistry

// GetActiveModules returns all registered active modules.
func GetActiveModules() []ActiveModule {
	return DefaultRegistry.GetActiveModules()
}

// GetActiveModulesID returns IDs of all registered active modules.
func GetActiveModulesID() []string {
	return DefaultRegistry.GetActiveModulesID()
}

// GetActiveModulesByIDs returns active modules matching the given IDs.
func GetActiveModulesByIDs(ids []string) []ActiveModule {
	return DefaultRegistry.GetActiveModulesByIDs(ids)
}

// GetPassiveModules returns all registered passive modules.
func GetPassiveModules() []PassiveModule {
	return DefaultRegistry.GetPassiveModules()
}

// GetPassiveModulesID returns IDs of all registered passive modules.
func GetPassiveModulesID() []string {
	return DefaultRegistry.GetPassiveModulesID()
}

// GetPassiveModulesByIDs returns passive modules matching the given IDs.
func GetPassiveModulesByIDs(ids []string) []PassiveModule {
	return DefaultRegistry.GetPassiveModulesByIDs(ids)
}

// ResolveModulePatterns resolves user-provided patterns into exact module IDs
// using fuzzy matching against module IDs and names.
func ResolveModulePatterns(patterns []string) []string {
	return DefaultRegistry.ResolveModulePatterns(patterns)
}

// ResolveModuleTags returns module IDs for all modules matching any of the given tags.
func ResolveModuleTags(tags []string) []string {
	return DefaultRegistry.ResolveModuleTags(tags)
}
