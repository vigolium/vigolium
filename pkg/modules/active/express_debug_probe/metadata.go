package express_debug_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-debug-probe"
	ModuleName  = "Express Debug Probe"
	ModuleShort = "Triggers error responses in Express/NestJS apps to detect stack trace and debug info leakage"
)

var (
	ModuleDesc = `## Description
Actively triggers error responses in Express.js and NestJS applications to detect
stack trace leakage and debug information exposure. When NODE_ENV is not set to
production, Express and NestJS return detailed error responses including stack traces,
file paths, and internal module information.

## Notes
- Runs once per host
- Probes: malformed JSON body, type-mismatch path parameters, random 404 endpoint
- Detects NODE_ENV misconfiguration, stack trace leakage, file path disclosure
- Fingerprints 404 to avoid false positives on custom error pages

## References
- https://expressjs.com/en/guide/error-handling.html
- https://docs.nestjs.com/exception-filters`

	ModuleConfirmation = "Confirmed when an error response contains stack traces, file paths, or debug markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"express", "misconfiguration", "info-disclosure", "moderate"}
)
