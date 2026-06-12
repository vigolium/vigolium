package sourcemap_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sourcemap-detect"
	ModuleName  = "Sourcemap Exposure Detect"
	ModuleShort = "Detects exposed JavaScript sourcemaps in production responses"
)

var (
	ModuleDesc = `**What it means:** A JavaScript or CSS response advertises a sourceMappingURL, or an accessible .map file with valid sourcemap JSON was served from production. Sourcemaps are build artifacts that map minified bundles back to their original code, so leaving them reachable exposes internal source structure, original file paths, and (when sourcesContent is present) the full pre-minification source code.

**How it's exploited:** An attacker fetches the referenced .map file to reconstruct the unminified application source, revealing original file and directory layout, internal API endpoints, comments, and any hardcoded secrets, tokens, or keys embedded in the bundle. This greatly accelerates reverse engineering and helps map hidden attack surface and client-side logic that would otherwise be obfuscated.

**Fix:** Do not deploy sourcemaps to production, or restrict access to .map files; strip sourceMappingURL comments and disable sourcemap generation (or upload maps to an error-tracking service only) in production builds.`

	ModuleConfirmation = "Confirmed when response contains a sourceMappingURL reference or a valid sourcemap JSON structure is detected"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"javascript", "info-disclosure", "light"}
)
