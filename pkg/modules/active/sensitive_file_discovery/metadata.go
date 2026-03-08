package sensitive_file_discovery

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-sensitive-file-discovery"
	ModuleName  = "Sensitive File Discovery"
	ModuleShort = "Probes for exposed sensitive files (.env, .git/config, dot files, log files, and more)"
)

var (
	ModuleDesc = `## Description
Discovers sensitive files and endpoints exposed on the web server using two
validation strategies. High-confidence probes (~25 paths) use content markers
to confirm findings. Bulk probes (~1,350 paths covering dot files, extensionless
files, and log files) use Content-Type and body differencing against a 404
fingerprint.

## Notes
- Runs once per unique host
- Marker-based probes: ~25 paths with content marker validation (firm confidence)
- Generic probes: ~1,350 paths with Content-Type and body differencing (tentative confidence)
- Generic probes are skipped if the 404 page returns text/plain or octet-stream
- Fingerprints 404 responses to avoid false positives from custom error pages

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information`

	ModuleConfirmation = "Marker-based: confirmed when response contains expected content markers. Generic: confirmed when response has text/plain or octet-stream Content-Type and body differs from 404 fingerprint"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"file-exposure", "info-disclosure", "moderate"}
)
