package php_composer_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-composer-exposure"
	ModuleName  = "PHP Composer Exposure"
	ModuleShort = "Detects exposed Composer manifests, vendor directory, and PHPUnit dev endpoints"
)

var (
	ModuleDesc = `**What it means:** The web server exposes PHP Composer dependency-management artifacts that should never be reachable over HTTP, such as composer.json and composer.lock manifests, the vendor directory listing or autoload files, Composer installed metadata, or the PHPUnit eval-stdin.php development endpoint. These files leak the application's exact third-party package versions and internal structure, and one of them is a known remote-code-execution vector.

**How it's exploited:** An attacker reads composer.lock or installed.json to learn the precise version of every dependency, then correlates those versions against public CVE databases to pick reliable, version-specific exploits and map the attack surface. The most severe case, an exposed PHPUnit eval-stdin.php (CVE-2017-9841), lets an attacker POST arbitrary PHP code that the server executes, yielding remote code execution; lower-severity manifest and vendor disclosures aid recon and may reveal private repository URLs.

**Fix:** Block public access to composer files and the entire vendor directory at the web server, disable directory listing, and remove or move dev dependencies like PHPUnit out of the web root in production.`

	ModuleConfirmation = "Confirmed when probed Composer artifacts return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"php", "file-exposure", "info-disclosure", "light"}
)
