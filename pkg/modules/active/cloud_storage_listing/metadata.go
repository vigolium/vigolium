package cloud_storage_listing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-storage-listing"
	ModuleName  = "Cloud Storage Listing"
	ModuleShort = "Detects publicly listable S3 buckets and Azure containers"
)

var (
	ModuleDesc = `**What it means:** A cloud storage endpoint (an AWS S3 bucket or an Azure Blob Storage container/account) allows anonymous, unauthenticated listing of its contents. The scanner confirmed this by sending a listing request and receiving an XML response that enumerates real objects, blobs, or containers. This exposes the full inventory of stored files, which often includes data the owner never intended to be public.

**How it's exploited:** An attacker reads the returned listing to discover every object name and path in the bucket or container, then downloads each one directly. This commonly leaks backups, source code, credentials, customer records, configuration files, and other sensitive assets, and reveals the storage layout for deeper attacks against the account.

**Fix:** Disable public/anonymous listing and access on the storage resource (block public access on the S3 bucket and remove anonymous list permissions; set the Azure container access level to Private), and require authenticated, least-privilege access to any objects that must stay reachable.`

	ModuleConfirmation = "Confirmed when storage endpoint returns XML listing response with object/blob entries"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"cloud", "info-disclosure", "light"}
)
