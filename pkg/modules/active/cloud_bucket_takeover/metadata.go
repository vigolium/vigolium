package cloud_bucket_takeover

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-bucket-takeover"
	ModuleName  = "Cloud Bucket Takeover"
	ModuleShort = "Detects dangling cloud storage buckets vulnerable to takeover"
)

var (
	ModuleDesc = `**What it means:** A hostname still points (via DNS or CNAME) to a cloud storage endpoint (AWS S3, GCS, or Azure Blob), but the bucket no longer exists - shown by a not-found error like NoSuchBucket. This dangling reference is a classic subdomain-takeover condition.

**How it's exploited:** Because the name is unclaimed, an attacker registers a bucket with that exact name in the same provider. The dangling DNS record then routes victim traffic to attacker storage under the trusted domain.

**Fix:** Remove the stale DNS record, or reclaim the bucket under the original name so an attacker cannot register it.`

	ModuleConfirmation = "Confirmed when cloud storage endpoint returns bucket/container not-found error while DNS still resolves"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "misconfiguration", "moderate"}
)
