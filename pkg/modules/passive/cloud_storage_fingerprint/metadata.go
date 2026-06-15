package cloud_storage_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-storage-fingerprint"
	ModuleName  = "Cloud Storage Fingerprint"
	ModuleShort = "Detects S3, GCS, and Azure Blob Storage endpoints in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The app serves content from or links to a cloud object-storage backend (S3, GCS, or Azure Blob), identified passively from provider headers (x-amz-*, x-goog-*, x-ms-*), the Server header, the host suffix, or storage URLs. Informational fingerprint that discloses where assets live.


**How it's exploited:** An attacker uses the disclosed bucket and account names to probe the endpoint for misconfigurations - public read/write, listable buckets, or broad ACLs - leading to data exposure or tampering.

**Fix:** Lock down storage permissions: disable public access, enforce least-privilege ACLs, block listing, and serve assets via a CDN or signed URLs.`

	ModuleConfirmation = "Confirmed when response headers or body contain cloud storage service identifiers"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"cloud", "fingerprint", "light"}
)
