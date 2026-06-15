package cloud_signed_url_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-signed-url-leak"
	ModuleName  = "Cloud Signed URL Leak"
	ModuleShort = "Detects leaked cloud storage signed URLs and SAS tokens in responses"
)

var (
	ModuleDesc = `**What it means:** A cloud storage signed URL or SAS token appears in a response body - an S3 presigned URL (X-Amz-Signature), GCS signed URL (X-Goog-Signature), or Azure SAS token (sv=...sig=). Each is a self-contained credential granting object access to anyone holding the URL.

**How it's exploited:** Anyone obtaining the URL via logs, history, referrers, or caches can replay it until expiry. Severity rises to High when the token is write-capable (PUT/DELETE, Azure w/d/c/a) or long-lived (24+ hours).

**Fix:** Keep signed URLs out of cacheable responses; scope each to read-only and the shortest lifetime, and rotate any exposed token.`

	ModuleConfirmation = "Confirmed when response body contains cloud storage signed URL or SAS token parameters"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "info-disclosure", "light"}
)
