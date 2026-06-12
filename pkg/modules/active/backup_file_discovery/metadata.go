package backup_file_discovery

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "backup-file-discovery"
	ModuleName  = "Backup File Discovery"
	ModuleShort = "Probes for exposed backup archives derived from hostname, common names, and year variants"
)

var (
	ModuleDesc = `**What it means:** A backup archive or database dump (such as a .zip, .tar.gz, .sql, or .bak file) is downloadable from the web server without authentication. The module guessed common backup filenames built from the hostname, common stems, and recent-year variants, then confirmed a real download by verifying the response is a genuine archive (archive magic bytes plus an archive Content-Type) or a real SQL dump (markers like CREATE TABLE / INSERT INTO), while rejecting 404 lookalikes, soft-404 wildcard pages, and HTML error shells.

**How it's exploited:** An attacker requests the same predictable URL and downloads the file directly in a browser. These backups commonly contain full source code, configuration files, database contents, password hashes, API keys, and other secrets, which can be mined offline to fully compromise the application and its users.

**Fix:** Remove backup and dump files from web-accessible directories and store them outside the document root, or deny access to backup/archive/dump extensions at the web server.`

	ModuleConfirmation = "Confirmed when response returns 200 with matching archive Content-Type, body size >1KB, and body differs from 404 fingerprint. SQL dumps additionally validated via content markers."
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"sensitive-file", "info-disclosure", "moderate"}
)
