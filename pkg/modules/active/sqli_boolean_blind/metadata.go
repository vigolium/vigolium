package sqli_boolean_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sqli-boolean-blind"
	ModuleName  = "Blind SQL Injection (Boolean-Based)"
	ModuleShort = "Detects boolean-based blind SQL injection vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** A request parameter is concatenated into a backend SQL query, letting an attacker alter its logic. No errors or output appear, but a TRUE payload returns a different page than a FALSE one (boolean-based blind SQL injection), confirmed via matched AND 1=1 / AND 1=2 conditions.

**How it's exploited:** An attacker turns the TRUE/FALSE difference into a one-bit oracle, extracting data character by character - credentials, hashes, whole tables - and escalating to authentication bypass or data exfiltration.

**Fix:** Use parameterized queries or prepared statements for all database access, never concatenating user input into SQL.`

	ModuleConfirmation = "Confirmed when TRUE payloads consistently produce different responses from FALSE payloads across multiple verification requests"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "sqli", "heavy"}
)
