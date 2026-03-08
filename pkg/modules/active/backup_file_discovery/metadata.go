package backup_file_discovery

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-backup-file-discovery"
	ModuleName  = "Backup File Discovery"
	ModuleShort = "Probes for exposed backup archives derived from hostname, common names, and year variants"
)

var (
	ModuleDesc = `## Description
Discovers publicly accessible backup files by generating candidate filenames
from the target hostname parts, common backup names, and year variants, then
combining them with archive and backup extensions.

## Notes
- Runs once per unique host
- Generates ~600-900 candidate paths depending on hostname complexity
- Validates using 404 fingerprinting, Content-Type, Content-Length, and body differencing
- SQL/text dumps additionally checked for content markers (CREATE TABLE, INSERT INTO, etc.)

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information`

	ModuleConfirmation = "Confirmed when response returns 200 with matching archive Content-Type, body size >1KB, and body differs from 404 fingerprint. SQL dumps additionally validated via content markers."
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"sensitive-file", "info-disclosure", "moderate"}
)
