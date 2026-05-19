package extensions

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

// LintQuickCheck validates a QuickCheck descriptor and returns issues.
func LintQuickCheck(qc agenttypes.QuickCheck) []agenttypes.QuickCheckLintIssue {
	var issues []agenttypes.QuickCheckLintIssue

	// Required: id
	if qc.ID == "" {
		issues = append(issues, agenttypes.QuickCheckLintIssue{
			Severity: "error",
			Message:  "missing required field 'id'",
		})
	} else if !isValidSlugID(qc.ID) {
		issues = append(issues, agenttypes.QuickCheckLintIssue{
			Severity: "warning",
			Message:  fmt.Sprintf("id %q should be lowercase with hyphens (e.g. \"ssti-jinja2\")", qc.ID),
		})
	}

	// Required: scan type
	if qc.Scan == "" {
		issues = append(issues, agenttypes.QuickCheckLintIssue{
			Severity: "error",
			Message:  "missing required field 'scan'",
		})
	} else {
		switch qc.Scan {
		case "per_insertion_point", "per_request", "per_host":
			// valid
		default:
			issues = append(issues, agenttypes.QuickCheckLintIssue{
				Severity: "error",
				Message:  fmt.Sprintf("invalid scan type %q; must be per_insertion_point, per_request, or per_host", qc.Scan),
			})
		}
	}

	// Validate severity
	if qc.Severity != "" && !isValidQCSeverity(qc.Severity) {
		issues = append(issues, agenttypes.QuickCheckLintIssue{
			Severity: "warning",
			Message:  fmt.Sprintf("unknown severity %q; expected: critical, high, medium, low, info", qc.Severity),
		})
	}

	// Validate match conditions
	hasMatch := qc.Match.BodyContains != "" || qc.Match.BodyRegex != "" || qc.Match.Status > 0 || qc.Match.HeaderContains != ""
	if !hasMatch {
		issues = append(issues, agenttypes.QuickCheckLintIssue{
			Severity: "error",
			Message:  "match has no conditions (need at least one of: body_contains, body_regex, status, header_contains)",
		})
	}

	// Validate regex in match
	if qc.Match.BodyRegex != "" {
		if _, err := regexp.Compile(qc.Match.BodyRegex); err != nil {
			issues = append(issues, agenttypes.QuickCheckLintIssue{
				Severity: "error",
				Message:  fmt.Sprintf("match.body_regex: invalid regex %q: %v", qc.Match.BodyRegex, err),
			})
		}
	}

	// Type-specific: per_insertion_point needs payloads, per_request/per_host needs requests
	switch qc.Scan {
	case "per_insertion_point":
		if len(qc.Payloads) == 0 {
			issues = append(issues, agenttypes.QuickCheckLintIssue{
				Severity: "error",
				Message:  "per_insertion_point quick check requires 'payloads'",
			})
		}
	case "per_request", "per_host":
		if len(qc.Requests) == 0 {
			issues = append(issues, agenttypes.QuickCheckLintIssue{
				Severity: "error",
				Message:  fmt.Sprintf("%s quick check requires 'requests'", qc.Scan),
			})
		}
		for i, req := range qc.Requests {
			if req.Path == "" {
				issues = append(issues, agenttypes.QuickCheckLintIssue{
					Severity: "warning",
					Message:  fmt.Sprintf("requests[%d]: missing 'path'", i),
				})
			}
		}
	}

	// Validate by generating and compiling the JS
	ext, err := generateQuickCheck(qc)
	if err == nil {
		if _, compileErr := sobek.Compile(ext.Filename, ext.Code, false); compileErr != nil {
			issues = append(issues, agenttypes.QuickCheckLintIssue{
				Severity: "error",
				Message:  fmt.Sprintf("generated JS has syntax error: %v", compileErr),
			})
		}
	}

	return issues
}

// LintSnippet validates a Snippet descriptor and returns issues.
func LintSnippet(snip agenttypes.Snippet) []agenttypes.QuickCheckLintIssue {
	var issues []agenttypes.QuickCheckLintIssue

	// Required: id
	if snip.ID == "" {
		issues = append(issues, agenttypes.QuickCheckLintIssue{
			Severity: "error",
			Message:  "missing required field 'id'",
		})
	} else if !isValidSlugID(snip.ID) {
		issues = append(issues, agenttypes.QuickCheckLintIssue{
			Severity: "warning",
			Message:  fmt.Sprintf("id %q should be lowercase with hyphens", snip.ID),
		})
	}

	// Required: body
	if strings.TrimSpace(snip.Body) == "" {
		issues = append(issues, agenttypes.QuickCheckLintIssue{
			Severity: "error",
			Message:  "missing required field 'body'",
		})
	}

	// Required: scan type
	if snip.Scan == "" {
		issues = append(issues, agenttypes.QuickCheckLintIssue{
			Severity: "error",
			Message:  "missing required field 'scan'",
		})
	} else {
		switch snip.Scan {
		case "per_insertion_point", "per_request", "per_host":
			// valid
		default:
			issues = append(issues, agenttypes.QuickCheckLintIssue{
				Severity: "error",
				Message:  fmt.Sprintf("invalid scan type %q; must be per_insertion_point, per_request, or per_host", snip.Scan),
			})
		}
	}

	// Validate severity
	if snip.Severity != "" && !isValidQCSeverity(snip.Severity) {
		issues = append(issues, agenttypes.QuickCheckLintIssue{
			Severity: "warning",
			Message:  fmt.Sprintf("unknown severity %q; expected: critical, high, medium, low, info", snip.Severity),
		})
	}

	// Validate by generating and compiling the JS
	ext, err := generateSnippet(snip)
	if err == nil {
		if _, compileErr := sobek.Compile(ext.Filename, ext.Code, false); compileErr != nil {
			issues = append(issues, agenttypes.QuickCheckLintIssue{
				Severity: "error",
				Message:  fmt.Sprintf("generated JS has syntax error: %v", compileErr),
			})
		}
	}

	return issues
}

func isValidSlugID(id string) bool {
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return id != "" && id[0] != '-' && id[len(id)-1] != '-'
}

func isValidQCSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "medium", "low", "info":
		return true
	}
	return false
}
