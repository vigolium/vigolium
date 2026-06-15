package laravel_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-sensitive-files"
	ModuleName  = "Laravel Sensitive Files"
	ModuleShort = "Detects Laravel-specific sensitive files: PHPUnit config, SQLite DB, storage internals, eval-stdin, and wrong document root"
)

var (
	ModuleDesc = `**What it means:** A Laravel-specific sensitive file is reachable over the web that should never be served - leaked config and dependency versions, a downloadable database, listable session storage, or PHP source served outside public/.

**How it's exploited:** An attacker downloads the asset directly: a SQLite database dumps all application data, a listable sessions directory enables session hijacking, and a vendor PHPUnit eval-stdin.php is an RCE candidate under CVE-2017-9841. composer installed.json reveals exact versions for CVE targeting.

**Fix:** Serve only the public/ directory as web root and block direct access to artisan, storage/, database files, vendor/, and config source.`

	ModuleConfirmation = "Confirmed when probed Laravel file paths return 200 with expected content markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"laravel", "php", "sensitive-file", "probe", "light"}
)
