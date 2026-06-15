package cloud_public_read

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-public-read"
	ModuleName  = "Cloud Public Read"
	ModuleShort = "Detects publicly readable sensitive paths on cloud storage endpoints"
)

var (
	ModuleDesc = `**What it means:** A cloud storage endpoint (AWS S3, GCS, or Azure Blob) serves a sensitive directory such as /uploads/, /backups/, /config/, or /admin/ to anyone with no authentication. A real 200/206 carrying actual content confirms private data is publicly readable.

**How it's exploited:** An attacker who guesses the storage hostname requests these paths over HTTPS and downloads what they expose - database dumps, backups, config, or user data - leaking credentials and personal data that enable follow-on compromise.

**Fix:** Make the bucket private, remove public-read ACLs and anonymous access policies, and require authenticated or signed-URL access for non-public objects.`

	ModuleConfirmation = "Confirmed when cloud storage endpoint returns real content for sensitive paths without authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "info-disclosure", "sensitive-file", "moderate"}
)
