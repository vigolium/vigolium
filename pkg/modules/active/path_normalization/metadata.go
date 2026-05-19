package path_normalization

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "path-normalization"
	ModuleName  = "Path Normalization"
	ModuleShort = "Detects path normalization vulnerabilities"
)

var (
	ModuleDesc = `## Description
Tests for path normalization vulnerabilities by iteratively applying traversal payloads
(with conditional auto-slashing) and checking response status codes and fingerprints
against expected internal/public patterns.

## Notes
- Compares response fingerprints between public and internal path variations
- Uses iterative payload application with auto-slashing heuristics
- Targets middleware and reverse proxy path normalization inconsistencies

## References
- https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf`

	ModuleConfirmation = "Confirmed when traversal payloads produce response fingerprints matching internal resources that differ from public access patterns"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "lfi", "moderate"}
)
