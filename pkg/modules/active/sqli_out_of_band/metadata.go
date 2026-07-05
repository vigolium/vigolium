package sqli_out_of_band

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sqli-out-of-band"
	ModuleName  = "SQL Injection (Out-of-Band)"
	ModuleShort = "Confirms blind SQL injection via out-of-band DBMS callbacks (LOAD_FILE/xp_dirtree/UTL_HTTP)"
)

var (
	ModuleDesc = `**What it means:** A parameter reaches a SQL query with no in-band error, boolean, or timing signal, but the database can be made to resolve or fetch a unique OAST subdomain via a built-in function. A correlated callback proves the injected SQL ran.

**How it's exploited:** An attacker injects an out-of-band function (MySQL LOAD_FILE UNC, MSSQL xp_dirtree, Oracle UTL_INADDR/UTL_HTTP, PostgreSQL COPY TO PROGRAM) to confirm or exfiltrate data even when the response is fully blind.

**Fix:** Use parameterized queries, restrict DB privileges (no file/network functions), and block outbound DNS/HTTP from the database host.`

	ModuleConfirmation = "Confirmed only when the database makes an out-of-band DNS/HTTP callback to the unique per-payload OAST subdomain injected via a DBMS out-of-band function"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "sqli", "oast", "moderate"}
)
