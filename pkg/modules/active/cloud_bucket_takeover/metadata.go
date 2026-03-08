package cloud_bucket_takeover

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-cloud-bucket-takeover"
	ModuleName  = "Cloud Bucket Takeover"
	ModuleShort = "Detects dangling cloud storage buckets vulnerable to takeover"
)

var (
	ModuleDesc = `## Description
Tests cloud storage endpoints for bucket/container not-found conditions that indicate
potential subdomain takeover. Checks for S3 NoSuchBucket, GCS bucket-not-found,
and Azure ContainerNotFound errors.

## Notes
- Only runs on hosts identified as cloud storage endpoints
- GET / and check for specific not-found error patterns
- Takeover risk exists when DNS points to storage but bucket is unclaimed
- Runs once per host with deduplication

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover
- https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html`

	ModuleConfirmation = "Confirmed when cloud storage endpoint returns bucket/container not-found error while DNS still resolves"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "misconfiguration", "moderate"}
)
