package joomla_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-joomla-misconfig"
	ModuleName  = "Joomla Misconfiguration"
	ModuleShort = "Detects exposed Joomla configuration backups, log/temp directories, backup archives, and debug settings"
)

var (
	ModuleDesc = `## Description
Probes for Joomla-specific files and endpoints that should not be publicly
accessible: configuration.php backups, exposed log and temp directories,
Akeeba backup archives, debug mode artifacts, com_ajax information disclosure,
and composer metadata files.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to reduce false positives
- Fingerprints 404 responses to detect custom error pages
- Checks both frontend and administrator paths

## References
- https://docs.joomla.org/Security_Checklist
- https://developer.joomla.org/security-centre.html`

	ModuleConfirmation = "Confirmed when probed Joomla files return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"joomla", "php", "misconfiguration", "info-disclosure", "moderate"}
)
