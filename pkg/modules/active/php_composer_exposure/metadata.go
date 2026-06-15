package php_composer_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-composer-exposure"
	ModuleName  = "PHP Composer Exposure"
	ModuleShort = "Detects exposed Composer manifests, vendor directory, and PHPUnit dev endpoints"
)

var (
	ModuleDesc = `**What it means:** The web server exposes PHP Composer artifacts that should never be reachable over HTTP - composer.json/composer.lock manifests, the vendor directory, or the PHPUnit eval-stdin.php endpoint. These leak exact dependency versions, and one is an RCE vector.

**How it's exploited:** An attacker reads composer.lock to learn dependency versions, then correlates them against CVE databases for version-specific exploits. The worst case, an exposed PHPUnit eval-stdin.php (CVE-2017-9841), lets an attacker POST arbitrary PHP for remote code execution.

**Fix:** Block public access to composer files and the vendor directory, disable directory listing, and keep PHPUnit out of the web root.`

	ModuleConfirmation = "Confirmed when probed Composer artifacts return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"php", "file-exposure", "info-disclosure", "light"}
)
