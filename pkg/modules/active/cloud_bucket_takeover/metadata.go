package cloud_bucket_takeover

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-bucket-takeover"
	ModuleName  = "Cloud Bucket Takeover"
	ModuleShort = "Detects dangling cloud storage buckets vulnerable to takeover"
)

var (
	ModuleDesc = `**What it means:** An AWS S3, Google Cloud Storage, or Azure storage hostname reproducibly returns a provider-specific structured bucket/container-not-found error to a credential-free client.

**How it's exploited:** If the namespace is genuinely unclaimed and a trusted custom domain still points to it, an attacker may register the name and serve content. The scanner does not register resources, so it reports a candidate rather than claiming takeover.

**Fix:** Remove the stale DNS record, or reclaim the bucket under the original name so an attacker cannot register it.`

	ModuleConfirmation = "Candidate requires provider-host binding plus the same structured resource-not-found error in two credential-free requests; claimability is never inferred from a generic 404"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "misconfiguration", "moderate"}
)
