package express_directory_listing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-directory-listing"
	ModuleName  = "Express Directory Listing"
	ModuleShort = "Detects directory listing exposure via serve-index or similar middleware"
)

var (
	ModuleDesc = `**What it means:** A static directory returns an auto-generated file listing instead of a page or 404. This probes common paths like /public/, /uploads/, and /static/, flagging a 2xx body with listing markers from serve-index, Nginx autoindex, or Apache autoindex, exposing the full file inventory.

**How it's exploited:** An attacker browses the listing to enumerate every file, then downloads anything sensitive not meant to be public - backup archives, config files, source code, credentials, or unlinked uploaded content.

**Fix:** Disable directory listing on static middleware (no serve-index, Nginx autoindex off, Apache Options -Indexes) and serve only intended files.`

	ModuleConfirmation = "Confirmed when a directory path responds with directory listing indicators such as serve-index markers, autoindex output, or file listing HTML"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"express", "info-disclosure", "misconfiguration", "light"}
)
