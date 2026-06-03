package sqli_time_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sqli-time-blind"
	ModuleName  = "Blind SQL Injection (Time-Based)"
	ModuleShort = "Detects time-based blind SQL injection vulnerabilities"
)

var (
	ModuleDesc = `## Description
Tests for time-based blind SQL injection by sending paired sleep/no-sleep payloads and
measuring response time differentials. Uses triple-verification (sleep, no-sleep, sleep)
to minimize false positives caused by network jitter or server load.

## Notes
- Samples each insertion point's baseline latency and derives a per-target delay
  threshold (mean + max(5·stdev, 3s), floored at 2s) instead of a fixed cutoff —
  adaptive to fast and slow targets, and skips hosts too jittery to time reliably
- Measures response time using wall-clock timing around each request
- Multi-round, multi-factor confirmation: for several rounds the no-sleep request
  must stay fast, the high-sleep request must exceed the threshold, and the
  high−low delay differential must track the requested (high−low) seconds — so a
  fixed timeout/retry delay or random slowness is rejected because it does not
  scale with the injected sleep value
- Uses parametric sleeps (MySQL SLEEP, PostgreSQL pg_sleep, MSSQL WAITFOR DELAY,
  Oracle DBMS_PIPE). SQLite RANDOMBLOB is intentionally omitted: its delay is not
  expressible in seconds and cannot be scale-verified
- Tests both string and numeric contexts
- Uses NoRedirects to capture timing before redirect

## References
- https://owasp.org/www-community/attacks/Blind_SQL_Injection
- https://portswigger.net/web-security/sql-injection/blind/lab-time-delays`

	ModuleConfirmation = "Confirmed when sleep payloads consistently cause measurable time delays compared to no-sleep payloads across triple verification"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "sqli", "heavy"}
)
