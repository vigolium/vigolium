package directory_listing_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "directory-listing-detect"
	ModuleName  = "Directory Listing Detect"
	ModuleShort = "Passively detects directory listing exposure in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The web server returned an auto-generated directory listing (an index page enumerating the files and subfolders in a directory) instead of a real page or a denial. This module passively recognizes the listing HTML produced by Apache, Nginx, IIS, Jetty, and generic servers such as Python SimpleHTTPServer or Express serve-index. A listing means directory browsing is enabled, which leaks the names and structure of files that were never meant to be publicly browsable.

**How it's exploited:** An attacker reads the listing to discover unlinked files such as backups, source archives, config files, credentials, logs, or old versions, then downloads them directly. The exposed file and folder names also map the application's internal structure, guiding further attacks.

**Fix:** Disable directory browsing on the web server (for example Apache Options -Indexes, Nginx autoindex off, or the IIS directory browsing setting) and serve an index file or a 403 instead.`

	ModuleConfirmation = "Confirmed when response contains server-specific directory listing indicators such as Apache Index of, Nginx autoindex, IIS directory browsing, Jetty directory, or Python directory listing markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "misconfiguration", "directory-listing", "light"}
)
