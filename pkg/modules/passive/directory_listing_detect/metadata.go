package directory_listing_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "directory-listing-detect"
	ModuleName  = "Directory Listing Detect"
	ModuleShort = "Passively detects directory listing exposure in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The web server returned an auto-generated directory listing enumerating files and subfolders instead of a real page. This recognizes the listing HTML of Apache, Nginx, IIS, Jetty, Python SimpleHTTPServer, and Express serve-index. Directory browsing is enabled, leaking files never meant to be browsable.

**How it's exploited:** An attacker reads the listing to find unlinked files - backups, source archives, config files, credentials, logs - and downloads them directly. The names also map the app's internal structure.

**Fix:** Disable directory browsing (Apache Options -Indexes, Nginx autoindex off, or the IIS setting) and serve an index file or 403.`

	ModuleConfirmation = "Confirmed when response contains server-specific directory listing indicators such as Apache Index of, Nginx autoindex, IIS directory browsing, Jetty directory, or Python directory listing markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "misconfiguration", "directory-listing", "light"}
)
