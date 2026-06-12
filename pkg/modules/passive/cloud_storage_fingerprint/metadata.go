package cloud_storage_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-storage-fingerprint"
	ModuleName  = "Cloud Storage Fingerprint"
	ModuleShort = "Detects S3, GCS, and Azure Blob Storage endpoints in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The application serves content from, or links to, a cloud object-storage backend (AWS S3, Google Cloud Storage, or Azure Blob Storage), identified passively from provider-specific response headers (x-amz-*, x-goog-*, x-ms-*), the Server header, the request host suffix, or storage URLs in the response body. This is an informational fingerprint, not a vulnerability on its own, but it discloses where assets and potentially sensitive files live.

**How it's exploited:** An attacker uses the disclosed bucket and account names to map attack surface and directly probe the storage endpoint for misconfigurations, such as public/anonymous read or write access, world-listable buckets, or overly broad ACLs, which can lead to data exposure or content tampering outside the application's own access controls.

**Fix:** Treat bucket names as known and lock down storage permissions: disable public/anonymous access, enforce least-privilege bucket policies and ACLs, block public listing, and serve assets through a controlled CDN or signed URLs rather than exposing raw storage endpoints.`

	ModuleConfirmation = "Confirmed when response headers or body contain cloud storage service identifiers"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"cloud", "fingerprint", "light"}
)
