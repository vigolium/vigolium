package sqli_time_based_params

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sqli-time-based-params"
	ModuleName  = "SQLi Time Based - Params"
	ModuleShort = "Detects time-based SQL injection in parameters"
)

var (
	ModuleDesc = `## Description
Detects time-based blind SQL injection in URL and body parameters by injecting
sleep/delay SQL payloads and measuring response time differences.

## Notes
- Tests both URL query and body parameters
- Uses statistical timing analysis with multiple rounds to reduce false positives
- Tests multiple database syntaxes (MySQL SLEEP, PostgreSQL pg_sleep, MSSQL WAITFOR)

## References
- https://owasp.org/www-community/attacks/Blind_SQL_Injection`

	ModuleConfirmation = "Confirmed when SQL delay payloads in parameters cause consistent response time increases matching the injected delay value"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"injection", "sqli", "heavy"}
)
