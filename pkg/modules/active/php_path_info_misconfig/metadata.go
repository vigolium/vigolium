package php_path_info_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-path-info-misconfig"
	ModuleName  = "PHP PATH_INFO Misconfiguration"
	ModuleShort = "Detects cgi.fix_pathinfo routing ambiguity allowing script path manipulation"
)

var (
	ModuleDesc = `## Description
Tests for PHP-FPM/CGI PATH_INFO routing misconfiguration (cgi.fix_pathinfo=1)
where requests to non-existent PHP scripts with PATH_INFO are routed to a
different script. This can enable authorization bypass or unintended script
execution by appending arbitrary paths to valid PHP endpoints.

## Notes
- Runs once per host to avoid redundant probing
- Sends requests to deliberately invalid script paths
- Compares responses to establish if PATH_INFO rewriting is active
- Low false positive rate due to multi-step validation

## References
- https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/#passing-uncontrolled-requests-to-php
- https://www.php.net/manual/en/ini.core.php#ini.cgi.fix-pathinfo
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when requests to non-existent PHP scripts with PATH_INFO return valid responses instead of 404"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"php", "misconfiguration", "light"}
)
