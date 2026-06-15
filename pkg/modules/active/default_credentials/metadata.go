package default_credentials

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "default-credentials"
	ModuleName  = "Default Credentials"
	ModuleShort = "Tests for default or common credential pairs on login endpoints"
)

var (
	ModuleDesc = `**What it means:** A login endpoint accepts a well-known default credential pair (admin/admin, root/root, tomcat/tomcat, postgres/postgres) never changed after install, granting direct authenticated access without stealing a password.

**How it's exploited:** An attacker logs in with the same default pair to take over the account, often reaching administrative panels and the data behind them. Confirmed when a factory-default pair produces a response clearly differing from the invalid-credential baseline (success redirect or new session cookie).

**Fix:** Force a password change on all default and shared accounts at first use, disable built-in demo accounts, and enforce strong unique passwords.`

	ModuleConfirmation = "Confirmed when a known credential pair produces a response significantly different from the invalid-credential baseline, indicating successful authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"auth-bypass", "probe", "moderate"}
)
