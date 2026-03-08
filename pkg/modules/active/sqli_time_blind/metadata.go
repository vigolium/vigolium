package sqli_time_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-sqli-time-blind"
	ModuleName  = "Blind SQL Injection (Time-Based)"
	ModuleShort = "Detects time-based blind SQL injection vulnerabilities"
)

var (
	ModuleDesc = `## Description
Tests for time-based blind SQL injection by sending paired sleep/no-sleep payloads and
measuring response time differentials. Uses triple-verification (sleep, no-sleep, sleep)
to minimize false positives caused by network jitter or server load.

## Notes
- Sends sleep and no-sleep payload pairs to each injection point
- Measures response time using wall-clock timing around each request
- Triple-verification: confirms sleep causes consistent delay across multiple requests
- Tests MySQL SLEEP, PostgreSQL pg_sleep, MSSQL WAITFOR DELAY, SQLite RANDOMBLOB, Oracle DBMS_PIPE
- Tests both string and numeric contexts
- Uses NoRedirects to capture timing before redirect

## References
- https://owasp.org/www-community/attacks/Blind_SQL_Injection
- https://portswigger.net/web-security/sql-injection/blind/lab-time-delays`

	ModuleConfirmation = "Confirmed when sleep payloads consistently cause measurable time delays compared to no-sleep payloads across triple verification"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"injection", "sqli", "heavy"}
)
