package cloud_storage_error_info

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-cloud-storage-error-info"
	ModuleName  = "Cloud Storage Error Info"
	ModuleShort = "Extracts bucket names and regions from cloud storage error responses"
)

var (
	ModuleDesc = `## Description
Passively extracts leaked cloud storage identifiers (bucket names, regions, endpoints)
from S3 XML error responses, Azure x-ms-error-code headers, and GCS error JSON.

## Notes
- Parses S3 XML errors for BucketName, Region, Code elements
- Checks Azure x-ms-error-code header and XML error bodies
- Parses GCS JSON error responses for bucket metadata
- Runs once per host with deduplication

## References
- https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
- https://learn.microsoft.com/en-us/rest/api/storageservices/common-rest-api-error-codes`

	ModuleConfirmation = "Confirmed when error response reveals cloud storage bucket name, region, or error code"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"cloud", "info-disclosure", "light"}
)
