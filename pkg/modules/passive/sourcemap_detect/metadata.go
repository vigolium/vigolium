package sourcemap_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sourcemap-detect"
	ModuleName  = "Sourcemap Exposure Detect"
	ModuleShort = "Detects exposed JavaScript sourcemaps in production responses"
)

var (
	ModuleDesc = `**What it means:** A JS or CSS response advertises a sourceMappingURL, or an accessible .map file with valid sourcemap JSON was served from production. Sourcemaps map minified bundles back to original code, so leaving them reachable exposes source structure, file paths, and (with sourcesContent) full source.

**How it's exploited:** An attacker fetches the .map file to reconstruct the unminified source, revealing directory layout, internal API endpoints, and hardcoded secrets, accelerating reverse engineering.

**Fix:** Do not deploy sourcemaps to production, or restrict access to .map files; strip sourceMappingURL comments and disable sourcemap generation in production builds.`

	ModuleConfirmation = "Observation for a sourceMappingURL reference; candidate only when a valid source map is actually delivered or decoded inline, without inferring sensitive content or unauthorized access"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"javascript", "info-disclosure", "light"}
)
