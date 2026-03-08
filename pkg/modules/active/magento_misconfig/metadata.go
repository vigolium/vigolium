package magento_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-magento-misconfig"
	ModuleName  = "Magento Misconfiguration"
	ModuleShort = "Detects exposed Magento setup wizard, downloader, version files, and admin panels"
)

var (
	ModuleDesc = `## Description
Probes for Magento-specific files and endpoints that should not be publicly
accessible: setup wizard, downloader interface, version disclosure files,
exposed configuration, and admin panel paths.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to reduce false positives
- Covers both Magento 1.x and Magento 2.x paths
- Fingerprints 404 responses to detect custom error pages

## References
- https://experienceleague.adobe.com/docs/commerce-operations/configuration-guide/overview.html
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when probed Magento endpoints return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"magento", "php", "cms", "misconfiguration", "light"}
)
