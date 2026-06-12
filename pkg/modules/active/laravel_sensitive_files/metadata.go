package laravel_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-sensitive-files"
	ModuleName  = "Laravel Sensitive Files"
	ModuleShort = "Detects Laravel-specific sensitive files: PHPUnit config, SQLite DB, storage internals, eval-stdin, and wrong document root"
)

var (
	ModuleDesc = `**What it means:** A Laravel-specific sensitive file or directory is reachable over the web that should never be served. Depending on which path matched, this ranges from leaked configuration and dependency versions to a downloadable application database, listable session storage, exposed framework source, or a serving-from-project-root misconfiguration where PHP source and secrets sit outside the intended public/ directory.

**How it's exploited:** An attacker downloads the disclosed asset directly: a SQLite database file dumps all application data, a listable sessions directory enables session hijacking, exposed routes/config/bootstrap source reveals secrets and attack surface, and an accessible vendor PHPUnit eval-stdin.php is a remote-code-execution candidate under CVE-2017-9841. PHPUnit and composer installed.json files reveal exact dependency versions for precise CVE targeting.

**Fix:** Serve only the public/ directory as the web root and block direct access to artisan, storage/, database files, vendor/, and config/route source via server rules.`

	ModuleConfirmation = "Confirmed when probed Laravel file paths return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"laravel", "php", "sensitive-file", "probe", "light"}
)
