package cloud_signed_url_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-signed-url-leak"
	ModuleName  = "Cloud Signed URL Leak"
	ModuleShort = "Detects leaked cloud storage signed URLs and SAS tokens in responses"
)

var (
	ModuleDesc = `## Description
Passively detects leaked AWS presigned URLs, GCS signed URLs, and Azure SAS tokens
in HTTP response bodies. Parses expiry and permissions to assess risk level.

## Notes
- Scans response body for X-Amz-Signature, X-Goog-Signature, and Azure SAS parameters
- Upgrades severity to High if write-capable or long-lived (>24h)
- Deduplicates by URL and signature hash

## References
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html
- https://cloud.google.com/storage/docs/access-control/signed-urls
- https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview`

	ModuleConfirmation = "Confirmed when response body contains cloud storage signed URL or SAS token parameters"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "info-disclosure", "light"}
)
