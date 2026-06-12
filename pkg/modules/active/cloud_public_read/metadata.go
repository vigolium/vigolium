package cloud_public_read

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-public-read"
	ModuleName  = "Cloud Public Read"
	ModuleShort = "Detects publicly readable sensitive paths on cloud storage endpoints"
)

var (
	ModuleDesc = `**What it means:** A cloud storage endpoint (AWS S3, Google Cloud Storage, or Azure Blob/Web Storage) serves a sensitive directory such as /uploads/, /backups/, /config/, /private/, /dump/, or /admin/ to anyone, with no authentication. The module confirmed a real 200/206 response carrying actual content rather than an access-denied or not-found error page, meaning private data is publicly readable.

**How it's exploited:** An attacker who knows or guesses the bucket or storage hostname requests these paths directly over HTTPS and downloads whatever they expose, for example database dumps, backups, internal config, exported user data, or log files. Listable or downloadable objects can leak credentials, personal data, and source material that enable follow-on compromise, all without any prior access.

**Fix:** Make the bucket or storage container private, remove public-read ACLs and anonymous access policies, and require authenticated or signed-URL access for any object that is not intended to be public.`

	ModuleConfirmation = "Confirmed when cloud storage endpoint returns real content for sensitive paths without authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "info-disclosure", "sensitive-file", "moderate"}
)
