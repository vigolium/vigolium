package sqli_time_based_header

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sqli-time-based-header"
	ModuleName  = "SQLi Time Based - Header"
	ModuleShort = "Detects time-based SQL injection in HTTP headers"
)

var (
	ModuleDesc = `## Description
Detects time-based blind SQL injection in HTTP headers by injecting sleep/delay
SQL payloads and measuring response time differences.

## Notes
- Targets common injectable headers (Referer, X-Forwarded-For, User-Agent, etc.)
- Uses statistical timing analysis with multiple rounds to reduce false positives
- Tests multiple database syntaxes (MySQL SLEEP, PostgreSQL pg_sleep, MSSQL WAITFOR)

## References
- https://owasp.org/www-community/attacks/Blind_SQL_Injection`

	ModuleConfirmation = "Confirmed when SQL delay payloads in HTTP headers cause consistent response time increases matching the injected delay value"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "sqli", "heavy"}
)
