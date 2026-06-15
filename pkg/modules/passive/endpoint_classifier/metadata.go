package endpoint_classifier

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "endpoint-classifier"
	ModuleName  = "Endpoint Classifier"
	ModuleShort = "Tags HTTP records with semantic labels based on request/response characteristics"
)

var (
	ModuleDesc = `**What it means:** An informational utility finding, not a vulnerability. The scanner passively attached semantic labels (such as graphql, api-endpoint, json-api, html-page, form-endpoint, file-upload, authenticated, redirect) so the endpoint's role is easier to triage. Labels come from the path, Content-Type, Authorization header, and status code.

**How it's exploited:** No direct exploit. The tags help an auditor map attack surface faster - quickly locating file-upload, GraphQL, or authenticated API endpoints worth deeper injection, access-control, or upload testing.

**Fix:** No remediation required; use the labels to focus security review on the higher-risk endpoints they surface.`

	ModuleConfirmation = "Endpoint classified based on HTTP request/response characteristics"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"utility", "light"}
)
