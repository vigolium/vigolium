package cloud_storage_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-storage-fingerprint"
	ModuleName  = "Cloud Storage Fingerprint"
	ModuleShort = "Detects S3, GCS, and Azure Blob Storage endpoints in HTTP responses"
)

var (
	ModuleDesc = `## Description
Passively detects cloud storage services (AWS S3, Google Cloud Storage, Azure Blob Storage)
from HTTP response headers, URL patterns in response bodies, and request host analysis.

## Notes
- Checks Server, x-amz-request-id, x-ms-request-id, x-goog-* headers
- Scans response body for cloud storage URL patterns
- Runs once per host with deduplication

## References
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html
- https://cloud.google.com/storage/docs/request-endpoints
- https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blobs-introduction`

	ModuleConfirmation = "Confirmed when response headers or body contain cloud storage service identifiers"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"cloud", "fingerprint", "light"}
)
