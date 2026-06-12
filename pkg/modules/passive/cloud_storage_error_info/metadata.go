package cloud_storage_error_info

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-storage-error-info"
	ModuleName  = "Cloud Storage Error Info"
	ModuleShort = "Extracts bucket names and regions from cloud storage error responses"
)

var (
	ModuleDesc = `**What it means:** A cloud storage error response (AWS S3 XML, Azure blob error, or Google Cloud Storage JSON) leaked internal identifiers such as the bucket name, region, storage endpoint, or provider error code. This is a low-severity information disclosure that exposes backend storage details a public-facing app would normally keep hidden.

**How it's exploited:** An attacker uses the disclosed bucket name and region to directly probe the storage backend out of band, mapping attack surface and testing for misconfigured public access, object enumeration, or other buckets in the same account. A NoSuchBucket error is especially useful because it flags a referenced-but-unclaimed bucket that may be registrable for a subdomain or storage takeover, while AccessDenied or PermanentRedirect confirms a real bucket worth targeting further.

**Fix:** Return generic error pages for storage failures and avoid proxying raw S3/Azure/GCS error bodies and provider error headers (x-ms-error-code, x-amz-request-id) back to clients.`

	ModuleConfirmation = "Confirmed when error response reveals cloud storage bucket name, region, or error code"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"cloud", "info-disclosure", "light"}
)
