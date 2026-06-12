package express_directory_listing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-directory-listing"
	ModuleName  = "Express Directory Listing"
	ModuleShort = "Detects directory listing exposure via serve-index or similar middleware"
)

var (
	ModuleDesc = `**What it means:** A static directory on the server returns an automatically generated file listing (an index of its contents) instead of a normal page or a 404. This module probes common static and upload paths such as /public/, /uploads/, /static/, /assets/, /files/, /media/, /images/, and /dist/, and flags one when the 2xx response body contains directory-listing markers from Express serve-index, Nginx autoindex, or Apache autoindex (fingerprinting the 404 page first to avoid false positives). It exposes the full file inventory of a directory that was meant to serve only specific assets.

**How it's exploited:** An attacker browses the exposed listing to enumerate every file present, then downloads anything sensitive that was not meant to be public, such as backup archives, configuration files, source code, credentials, or uploaded user content that has no direct link in the application.

**Fix:** Disable directory listing on static middleware (do not enable serve-index, set Nginx autoindex off / Apache Options -Indexes) and serve only explicitly intended files.`

	ModuleConfirmation = "Confirmed when a directory path responds with directory listing indicators such as serve-index markers, autoindex output, or file listing HTML"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"express", "info-disclosure", "misconfiguration", "light"}
)
