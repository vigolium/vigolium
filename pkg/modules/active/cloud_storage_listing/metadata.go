package cloud_storage_listing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-storage-listing"
	ModuleName  = "Cloud Storage Listing"
	ModuleShort = "Detects publicly listable S3 buckets and Azure containers"
)

var (
	ModuleDesc = `**What it means:** A cloud storage endpoint (an AWS S3 bucket or Azure Blob container) allows anonymous listing of its contents - confirmed by an XML response enumerating real objects or blobs. This exposes the full inventory of stored files, often including private data.

**How it's exploited:** An attacker reads the listing to discover every object name and path, then downloads each, commonly leaking backups, source code, credentials, and customer records and revealing the layout for deeper attacks.

**Fix:** Disable anonymous listing (block public access on the S3 bucket; set Azure container access to Private), and require authenticated, least-privilege access.`

	ModuleConfirmation = "Confirmed when storage endpoint returns XML listing response with object/blob entries"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"cloud", "info-disclosure", "light"}
)
