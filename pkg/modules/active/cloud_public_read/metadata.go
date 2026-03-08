package cloud_public_read

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-cloud-public-read"
	ModuleName  = "Cloud Public Read"
	ModuleShort = "Detects publicly readable sensitive paths on cloud storage endpoints"
)

var (
	ModuleDesc = `## Description
Tests cloud storage endpoints for publicly readable sensitive directories and files.
Probes common paths like /uploads/, /backups/, /data/, /logs/, /config/ and verifies
real content is returned (not error pages).

## Notes
- Only runs on hosts identified as cloud storage endpoints
- HEAD then GET common sensitive paths
- Verifies responses contain real content (body length > 50, not error pages)
- Runs once per host with deduplication

## References
- https://owasp.org/www-project-web-security-testing-guide/
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html`

	ModuleConfirmation = "Confirmed when cloud storage endpoint returns real content for sensitive paths without authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "info-disclosure", "sensitive-file", "moderate"}
)
