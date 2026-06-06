package infra

// Shared internal / cloud-metadata SSRF target set used by the request-line
// routing modules (routing_ssrf, upgrade_routing_ssrf). Each target pairs an
// internal endpoint with self-evidencing response markers that prove the endpoint
// actually answered — distinctive tokens (ami-id, droplet_id, …) rather than the
// generic "this is an HTML page" markers used elsewhere, so a marker match here is
// strong evidence of a reached internal service rather than the app's own page.
//
// Kept deliberately separate from ssrf_detection's richer parameter-injection
// payload list (which carries broad page-shape markers and its own grading): those
// two contexts confirm differently, so they intentionally do not share a list.

// SSRFInternalTarget is an internal/metadata endpoint plus the markers and any
// endpoint-required headers needed to evidence reaching it.
type SSRFInternalTarget struct {
	// Effective is host[:port]/path WITHOUT a scheme and WITH a trailing path,
	// suitable to feed directly to RoutingTargets as the effective host.
	Effective string
	// Markers are self-evidencing tokens; any one present in the response body
	// (and absent from the baseline) evidences the endpoint answered.
	Markers []string
	// ExtraHeaders are headers the endpoint requires before it will answer (e.g.
	// GCP's Metadata-Flavor, Azure's Metadata). Empty for endpoints that answer
	// unconditionally (AWS IMDSv1, DigitalOcean).
	ExtraHeaders map[string]string
	// Label is a short human-readable name for findings.
	Label string
}

// InternalSSRFTargets returns the curated internal/metadata endpoints used to
// confirm a request-line routing SSRF in-band (no OAST callback is possible for an
// internal address). The list favours unauthenticated metadata services whose
// responses carry unmistakable tokens.
func InternalSSRFTargets() []SSRFInternalTarget {
	return []SSRFInternalTarget{
		{
			Effective: "169.254.169.254/latest/meta-data/",
			Markers:   []string{"ami-id", "instance-id", "local-hostname", "public-hostname", "iam/", "public-keys"},
			Label:     "AWS EC2 IMDSv1 metadata",
		},
		{
			Effective:    "metadata.google.internal/computeMetadata/v1/instance/",
			Markers:      []string{"hostname", "zone", "machine-type", "service-accounts/"},
			ExtraHeaders: map[string]string{"Metadata-Flavor": "Google"},
			Label:        "GCP compute metadata",
		},
		{
			Effective:    "169.254.169.254/metadata/instance?api-version=2021-02-01",
			Markers:      []string{"vmId", "vmSize", "azEnvironment", "resourceGroupName"},
			ExtraHeaders: map[string]string{"Metadata": "true"},
			Label:        "Azure IMDS metadata",
		},
		{
			Effective: "169.254.169.254/metadata/v1/",
			Markers:   []string{"droplet_id", "region", "interfaces/"},
			Label:     "DigitalOcean metadata",
		},
		{
			Effective: "100.100.100.200/latest/meta-data/",
			Markers:   []string{"instance-id", "image-id", "region-id", "zone-id"},
			Label:     "Alibaba Cloud metadata",
		},
	}
}
