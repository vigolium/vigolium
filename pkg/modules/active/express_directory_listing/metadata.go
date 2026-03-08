package express_directory_listing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-express-directory-listing"
	ModuleName  = "Express Directory Listing"
	ModuleShort = "Detects directory listing exposure via serve-index or similar middleware"
)

var (
	ModuleDesc = `## Description
Probes for directory listing exposure in Express.js applications using serve-index
or similar middleware. Directory listings reveal the full file inventory of static
directories, potentially exposing sensitive files, backup archives, configuration
files, and internal assets that should not be publicly accessible.

## Notes
- Runs once per host
- Probes common static/upload directories: /public/, /uploads/, /static/, /assets/, /files/, /media/, /images/, /dist/
- Detects serve-index, Nginx autoindex, and Apache autoindex markers
- Fingerprints 404 to avoid false positives on custom error pages

## References
- https://expressjs.com/en/resources/middleware/serve-index.html
- https://www.npmjs.com/package/serve-index`

	ModuleConfirmation = "Confirmed when a directory path responds with directory listing indicators such as serve-index markers, autoindex output, or file listing HTML"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"express", "info-disclosure", "misconfiguration", "light"}
)
