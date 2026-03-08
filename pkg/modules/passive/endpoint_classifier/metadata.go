package endpoint_classifier

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-endpoint-classifier"
	ModuleName  = "Endpoint Classifier"
	ModuleShort = "Tags HTTP records with semantic labels based on request/response characteristics"
)

var (
	ModuleDesc = `## Description
Classifies HTTP endpoints and annotates database records with semantic tags (remarks).
Tags are derived from request/response characteristics such as content type, status code,
path patterns, and authentication headers.

## Tags Applied
- json-api, html-page, graphql, api-endpoint
- file-upload, redirect, error-page, authenticated
- xml-api, form-endpoint

## Notes
- Runs as a passive module, no additional requests sent
- Tags stored in HTTPRecord.Remarks for downstream filtering and prioritization`

	ModuleConfirmation = "Endpoint classified based on HTTP request/response characteristics"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"utility", "light"}
)
