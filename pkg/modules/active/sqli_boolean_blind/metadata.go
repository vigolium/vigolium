package sqli_boolean_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sqli-boolean-blind"
	ModuleName  = "Blind SQL Injection (Boolean-Based)"
	ModuleShort = "Detects boolean-based blind SQL injection vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** A request parameter is concatenated into a backend SQL query, letting an attacker inject conditions that alter the query's logic. The application returns no SQL errors or query output, but a payload that evaluates TRUE produces a different page than one that evaluates FALSE, proving the injection is exploitable (boolean-based blind SQL injection). This module confirms the flaw by injecting matched TRUE (e.g. AND 1=1) and FALSE (e.g. AND 1=2) conditions and observing a stable, reproducible content difference.

**How it's exploited:** An attacker turns the TRUE/FALSE page difference into a one-bit oracle and asks yes/no questions of the database, extracting data character by character (credentials, password hashes, session tokens, entire tables) and enumerating its structure. Depending on the database account's privileges, this can escalate to authentication bypass, full data exfiltration, or further compromise of the backend.

**Fix:** Use parameterized queries or prepared statements for all database access, and never build SQL by concatenating user input.`

	ModuleConfirmation = "Confirmed when TRUE payloads consistently produce different responses from FALSE payloads across multiple verification requests"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "sqli", "heavy"}
)
