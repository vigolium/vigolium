package sqli_time_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sqli-time-blind"
	ModuleName  = "Blind SQL Injection (Time-Based)"
	ModuleShort = "Detects time-based blind SQL injection vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** A request parameter reaches a backend SQL query unsanitized. Confirmed by injecting database sleep functions (MySQL SLEEP, PostgreSQL pg_sleep, MSSQL WAITFOR, Oracle DBMS_PIPE) and seeing response time grow in step with the requested delay, proving the SQL executes even though nothing is visible.

**How it's exploited:** An attacker uses the timed delay as a yes/no oracle, asking one true/false question per request and chaining many to extract usernames, hashes, and session tokens - sometimes escalating to writing data or running commands.

**Fix:** Use parameterized queries or prepared statements for all database access, and apply least-privilege accounts.`

	ModuleConfirmation = "Confirmed when sleep payloads consistently cause measurable time delays compared to no-sleep payloads across triple verification"
	// Time-based blind is the least reliable SQLi signal — it rides on wall-clock
	// latency alone, which edge/network jitter can forge — so findings are
	// reported as a lead to verify by hand (Suspect/Tentative), not High/Firm.
	ModuleSeverity   = severity.Suspect
	ModuleConfidence = severity.Tentative
	ModuleTags       = []string{"injection", "sqli", "heavy"}
)
