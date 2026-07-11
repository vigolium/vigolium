package cloud_signed_url_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-signed-url-leak"
	ModuleName  = "Cloud Signed URL Leak"
	ModuleShort = "Detects leaked cloud storage signed URLs and SAS tokens in responses"
)

var (
	ModuleDesc = `**What it means:** A response contains an S3, GCS, or Azure signed capability URL. This is often the intended way to deliver an object, so ordinary short-lived URLs are observations. Long lifetime, Azure write permissions, or explicit shared caching raise a candidate.

**How it's exploited:** Anyone obtaining the URL via logs, history, referrers, or caches can replay it until expiry. Severity rises to High when the token is write-capable (PUT/DELETE, Azure w/d/c/a) or long-lived (24+ hours).

**Fix:** Keep signed URLs out of cacheable responses; scope each to read-only and the shortest lifetime, and rotate any exposed token.`

	ModuleConfirmation = "Observation for ordinary signed capabilities; candidate only with long lifetime, provider-declared write permission, or explicit shared-cache context; unauthorized replay is never inferred"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "info-disclosure", "light"}
)
