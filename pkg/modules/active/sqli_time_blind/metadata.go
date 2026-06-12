package sqli_time_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sqli-time-blind"
	ModuleName  = "Blind SQL Injection (Time-Based)"
	ModuleShort = "Detects time-based blind SQL injection vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** A request parameter is passed into a backend SQL query without proper sanitization, so an attacker can alter the query. This module confirms it by injecting database sleep functions and observing the response time grow in step with the requested delay, proving the injected SQL actually executes even though no data or error is visible in the response.

**How it's exploited:** An attacker uses time delays as a yes/no oracle, asking the database one true/false question per request (for example, whether the first character of the admin password hash is an "a"). By chaining many such timed queries they can extract usernames, password hashes, session tokens, and any other data the database account can read, and in some configurations escalate to writing data or running commands. The scanner verified it with MySQL SLEEP, PostgreSQL pg_sleep, MSSQL WAITFOR, or Oracle DBMS_PIPE payloads.

**Fix:** Use parameterized queries or prepared statements for all database access so user input is never concatenated into SQL, and apply least-privilege database accounts.`

	ModuleConfirmation = "Confirmed when sleep payloads consistently cause measurable time delays compared to no-sleep payloads across triple verification"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "sqli", "heavy"}
)
