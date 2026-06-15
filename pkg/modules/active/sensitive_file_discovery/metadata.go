package sensitive_file_discovery

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sensitive-file-discovery"
	ModuleName  = "Sensitive File Discovery"
	ModuleShort = "Probes for exposed sensitive files (.env, .git/config, dot files, log files, and more)"
)

var (
	ModuleDesc = `**What it means:** The server is serving a sensitive file or internal endpoint that should not be public - a .env or .git/config, a database backup, an .htpasswd file, a phpinfo or pprof debug page, or a metrics endpoint. Severity ranges Critical to Low.

**How it's exploited:** An attacker requests the path and reads it. A leaked .env or SQL dump hands over database passwords; an exposed .git directory reconstructs source; debug pages reveal internals.

**Fix:** Block dotfiles, VCS directories, backups, debug endpoints, and config files at the web server or proxy, and remove these artifacts from the web root.`

	ModuleConfirmation = "Marker-based: confirmed when response contains expected content markers. Generic: confirmed when response has text/plain or octet-stream Content-Type and body differs from 404 fingerprint"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"file-exposure", "info-disclosure", "moderate"}
)
