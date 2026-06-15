package cloud_storage_error_info

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-storage-error-info"
	ModuleName  = "Cloud Storage Error Info"
	ModuleShort = "Extracts bucket names and regions from cloud storage error responses"
)

var (
	ModuleDesc = `**What it means:** A cloud storage error response (S3 XML, Azure blob, or GCS JSON) leaked internal identifiers - bucket name, region, endpoint, or provider error code. Low-severity recon exposing backend storage details normally hidden.

**How it's exploited:** An attacker uses the disclosed bucket and region to probe the backend for public access or enumeration. NoSuchBucket flags an unclaimed bucket open to takeover, while AccessDenied or PermanentRedirect confirms a real bucket worth targeting.

**Fix:** Return generic error pages for storage failures and avoid proxying raw S3/Azure/GCS error bodies and provider headers (x-ms-error-code, x-amz-request-id) to clients.`

	ModuleConfirmation = "Confirmed when error response reveals cloud storage bucket name, region, or error code"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"cloud", "info-disclosure", "light"}
)
