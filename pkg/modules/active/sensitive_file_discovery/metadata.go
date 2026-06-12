package sensitive_file_discovery

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sensitive-file-discovery"
	ModuleName  = "Sensitive File Discovery"
	ModuleShort = "Probes for exposed sensitive files (.env, .git/config, dot files, log files, and more)"
)

var (
	ModuleDesc = `**What it means:** The web server is serving a sensitive file or internal endpoint that should never be publicly reachable, such as a .env or .git/config file, a database backup, an .htpasswd hash file, a phpinfo or pprof debug page, a metrics or server-status endpoint, or a build manifest. Depending on the file, this leaks credentials and API keys, source code, infrastructure details, or the application's internal attack surface. Severity ranges from Critical (live credentials in .env/.htpasswd/SQL dumps) down to Low (informational manifests and API specs).

**How it's exploited:** An attacker requests the path directly and reads its contents. A leaked .env, wp-config backup, or SQL dump hands over database passwords and secrets for immediate account or data compromise; an exposed .git/.svn directory lets them reconstruct source code; debug and metrics pages reveal versions, paths, and internals that aid follow-up attacks.

**Fix:** Block access to dotfiles, VCS directories, backups, debug endpoints, and config files at the web server or reverse proxy, and remove these artifacts from the document root.`

	ModuleConfirmation = "Marker-based: confirmed when response contains expected content markers. Generic: confirmed when response has text/plain or octet-stream Content-Type and body differs from 404 fingerprint"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"file-exposure", "info-disclosure", "moderate"}
)
