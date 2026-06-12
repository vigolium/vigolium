package common_directory_listing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "common-directory-listing"
	ModuleName  = "Common Directory Listing"
	ModuleShort = "Detects directory listing exposure on common web servers (Apache, Nginx, IIS, Jetty, Python)"
)

var (
	ModuleDesc = `**What it means:** A directory on the web server returns an auto-generated listing of its contents instead of a normal page, exposing the full inventory of files in that directory to anyone. This module confirms the exposure by probing common paths (root, /uploads/, /files/, /static/, /WEB-INF/, /App_Data/, and others) and matching server-specific listing signatures from Apache, Nginx, IIS, Jetty, and generic servers like Python SimpleHTTPServer or Express serve-index, after fingerprinting the 404 page to rule out custom error pages.

**How it's exploited:** An attacker browses the listing to discover files that are not linked anywhere in the application, such as backup archives, configuration files, source code, credentials, logs, or other sensitive assets, then downloads them directly. This turns an information-disclosure misconfiguration into a stepping stone for deeper compromise.

**Fix:** Disable directory listing on the web server (for example Apache Options -Indexes, Nginx autoindex off, or IIS directory browsing off) and remove any sensitive files from publicly served directories.`

	ModuleConfirmation = "Confirmed when a directory path responds with server-specific directory listing indicators such as Apache Index of, Nginx autoindex, IIS directory browsing, Jetty directory, or Python directory listing markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "misconfiguration", "directory-listing", "light"}
)
