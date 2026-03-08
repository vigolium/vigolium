package sourcemap_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-sourcemap-detect"
	ModuleName  = "Sourcemap Exposure Detect"
	ModuleShort = "Detects exposed JavaScript sourcemaps in production responses"
)

var (
	ModuleDesc = `## Description
Passively detects exposed JavaScript sourcemaps by identifying SourceMappingURL
references in JS/CSS responses and validating accessible .map files.

## Notes
- Detects sourceMappingURL comments in JavaScript and CSS responses
- Validates .map file responses by parsing sourcemap JSON structure
- Exposed sourcemaps reveal original source code, file paths, and potentially secrets

## References
- https://developer.chrome.com/docs/devtools/javascript/source-maps
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when response contains a sourceMappingURL reference or a valid sourcemap JSON structure is detected"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"javascript", "info-disclosure", "light"}
)
