package bfla_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "bfla-detection"
	ModuleName  = "BFLA Detection"
	ModuleShort = "Detects Broken Function-Level Authorization on privileged endpoints"
)

var (
	ModuleDesc = `## Description
Detects Broken Function-Level Authorization (BFLA) by testing admin and privileged
endpoints with missing or downgraded authentication. Strips Authorization and Cookie
headers, attempts empty tokens, and tests method switching on admin-like paths.

## Notes
- Runs once per unique host+path combination via DiskSet dedup
- Skips non-2xx original responses (only tests endpoints that currently succeed)
- Compares response status codes and body lengths to reduce false positives
- Heuristic-based detection targeting known admin/privileged path patterns

## References
- https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- https://portswigger.net/web-security/access-control`

	ModuleConfirmation = "Confirmed when a privileged endpoint returns a successful response after removing or downgrading authentication credentials"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"auth-bypass", "api-security", "moderate"}
)
