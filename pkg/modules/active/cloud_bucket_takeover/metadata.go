package cloud_bucket_takeover

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-bucket-takeover"
	ModuleName  = "Cloud Bucket Takeover"
	ModuleShort = "Detects dangling cloud storage buckets vulnerable to takeover"
)

var (
	ModuleDesc = `**What it means:** A hostname or subdomain still points (via DNS or CNAME) to a cloud storage endpoint (AWS S3, Google Cloud Storage, or Azure Blob Storage), but the underlying bucket or container no longer exists. The module confirms this by requesting GET / and matching a provider not-found error such as NoSuchBucket, "The specified bucket does not exist", or ContainerNotFound. This is a dangling reference, a classic subdomain-takeover condition.
**How it's exploited:** Because the bucket name is unclaimed, an attacker can register a new bucket or container with that exact name in the same provider. The dangling DNS record then routes the victim's traffic to attacker-controlled storage, letting them serve malicious content, phishing pages, or scripts under the trusted domain and hijack cookies, OAuth flows, or CSP-trusted origins.
**Fix:** Remove or update the stale DNS record, or reclaim the bucket/container under the original name so it cannot be registered by an attacker.`

	ModuleConfirmation = "Confirmed when cloud storage endpoint returns bucket/container not-found error while DNS still resolves"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "misconfiguration", "moderate"}
)
