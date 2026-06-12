package cloud_signed_url_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-signed-url-leak"
	ModuleName  = "Cloud Signed URL Leak"
	ModuleShort = "Detects leaked cloud storage signed URLs and SAS tokens in responses"
)

var (
	ModuleDesc = `**What it means:** A cloud storage signed URL or SAS token was found in an HTTP response body. These are AWS S3 presigned URLs (X-Amz-Signature), Google Cloud Storage signed URLs (X-Goog-Signature), or Azure Blob SAS tokens (sv=...sig=). Each is a self-contained credential that grants direct access to a storage object or container to anyone who holds the URL, with no further authentication.

**How it's exploited:** Anyone who obtains the leaked URL, including via shared links, logs, browser history, referrers, or caches, can replay it to read the referenced object until it expires. The scanner parses each token's permissions and expiry and raises the severity to High when the URL is write-capable (AWS/GCS PUT or DELETE method, or Azure w/d/c/a permissions) or long-lived (valid for over 24 hours), since those allow tampering, deletion, or sustained unauthorized access to the bucket.

**Fix:** Avoid embedding signed URLs in cacheable or broadly accessible responses; scope each token to read-only and the shortest practical lifetime, and rotate or revoke any token exposed here.`

	ModuleConfirmation = "Confirmed when response body contains cloud storage signed URL or SAS token parameters"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "info-disclosure", "light"}
)
