package cloud_storage_listing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-cloud-storage-listing"
	ModuleName  = "Cloud Storage Listing"
	ModuleShort = "Detects publicly listable S3 buckets and Azure containers"
)

var (
	ModuleDesc = `## Description
Tests cloud storage endpoints for public listing access. Attempts S3 ListObjectsV2,
Azure container blob listing, and Azure account container listing requests.

## Notes
- Only runs on hosts identified as cloud storage endpoints
- S3: GET /?list-type=2 checking for ListBucketResult
- Azure: GET /<container>?restype=container&comp=list checking for Blobs
- Azure: GET /?comp=list checking for Containers
- Runs once per host with deduplication

## References
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
- https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs`

	ModuleConfirmation = "Confirmed when storage endpoint returns XML listing response with object/blob entries"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"cloud", "info-disclosure", "light"}
)
