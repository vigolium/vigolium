package default_credentials

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "default-credentials"
	ModuleName  = "Default Credentials"
	ModuleShort = "Tests for default or common credential pairs on login endpoints"
)

var (
	ModuleDesc = `**What it means:** A login endpoint on this host accepts a well-known default or common credential pair (such as admin/admin, root/root, tomcat/tomcat, or postgres/postgres) that was never changed after install. This grants anyone direct, authenticated access to an account without needing to discover or steal a real password.

**How it's exploited:** The module finds a username/password login form (POST with form-encoded or JSON body), records the response to deliberately invalid credentials, then submits a short list of factory defaults; a response that clearly differs from the invalid-credential baseline (status change to success/redirect, a new session cookie with a substantially different body, or success wording like dashboard or logout) confirms a working login. An attacker logs in with the same pair to take over the account, often reaching administrative panels and the data or functionality behind them, and can pivot to fuller compromise.

**Fix:** Force a change of all default and shared accounts at first use, disable or remove built-in demo accounts, and enforce strong unique passwords.`

	ModuleConfirmation = "Confirmed when a known credential pair produces a response significantly different from the invalid-credential baseline, indicating successful authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"auth-bypass", "probe", "moderate"}
)
