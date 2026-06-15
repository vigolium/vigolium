package common_directory_listing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "common-directory-listing"
	ModuleName  = "Common Directory Listing"
	ModuleShort = "Detects directory listing exposure on common web servers (Apache, Nginx, IIS, Jetty, Python)"
)

var (
	ModuleDesc = `**What it means:** A directory returns an auto-generated listing of its contents instead of a normal page, exposing its full file inventory. The check probes common paths (/uploads/, /files/, /WEB-INF/) and matches Apache, Nginx, IIS, and Jetty listing signatures, ruling out custom error pages.

**How it's exploited:** An attacker browses the listing to find unlinked files - backups, config, source code, credentials, or logs - and downloads them directly, a stepping stone to deeper compromise.

**Fix:** Disable directory listing (Apache Options -Indexes, Nginx autoindex off, IIS directory browsing off) and remove sensitive files from public directories.`

	ModuleConfirmation = "Confirmed when a directory path responds with server-specific directory listing indicators such as Apache Index of, Nginx autoindex, IIS directory browsing, Jetty directory, or Python directory listing markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "misconfiguration", "directory-listing", "light"}
)
