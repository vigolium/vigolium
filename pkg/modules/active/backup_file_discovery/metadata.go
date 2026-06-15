package backup_file_discovery

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "backup-file-discovery"
	ModuleName  = "Backup File Discovery"
	ModuleShort = "Probes for exposed backup archives derived from hostname, common names, and year variants"
)

var (
	ModuleDesc = `**What it means:** A backup archive or database dump (.zip, .tar.gz, .sql, or .bak) is downloadable without authentication. The module guessed filenames from the hostname, common stems, and year variants, then confirmed via archive magic bytes or SQL markers, rejecting soft-404 shells.

**How it's exploited:** An attacker requests the same predictable URL and downloads the file directly. These backups commonly contain source code, configuration, database contents, password hashes, and API keys, mined offline to compromise the application.

**Fix:** Remove backup and dump files from web-accessible directories, or deny backup/archive/dump extensions at the web server.`

	ModuleConfirmation = "Confirmed when response returns 200 with matching archive Content-Type, body size >1KB, and body differs from 404 fingerprint. SQL dumps additionally validated via content markers."
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"sensitive-file", "info-disclosure", "moderate"}
)
