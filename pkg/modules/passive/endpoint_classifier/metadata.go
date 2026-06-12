package endpoint_classifier

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "endpoint-classifier"
	ModuleName  = "Endpoint Classifier"
	ModuleShort = "Tags HTTP records with semantic labels based on request/response characteristics"
)

var (
	ModuleDesc = `**What it means:** This is an informational utility finding, not a vulnerability. The scanner passively inspected the request and response and attached semantic labels to the endpoint (for example graphql, api-endpoint, json-api, xml-api, html-page, form-endpoint, file-upload, authenticated, redirect, or error-page) so the endpoint's role and attack surface are easier to triage. Labels come from the path, the request and response Content-Type, the presence of an Authorization header, and the HTTP status code.
**How it's exploited:** There is no direct exploit here. The tags help an attacker or auditor map attack surface faster, such as quickly locating file-upload, GraphQL, or authenticated API endpoints that warrant deeper testing for injection, access-control, or upload abuse, and identifying which routes return errors or redirects worth probing.
**Fix:** No remediation is required; this is metadata used to prioritize and filter findings, so simply use the labels to focus security review on the higher-risk endpoints they surface.`

	ModuleConfirmation = "Endpoint classified based on HTTP request/response characteristics"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"utility", "light"}
)
