package nginx_off_by_slash

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nginx-off-by-slash"
	ModuleName  = "Nginx Off-by-Slash"
	ModuleShort = "Detects Nginx alias traversal via missing trailing slash"
)

var (
	ModuleDesc = `**What it means:** The server has the Nginx off-by-slash alias traversal misconfiguration: a location uses alias without a matching trailing slash, so a request path breaks out of the intended directory and an attacker reads files outside it.

**How it's exploited:** An attacker appends a traversal marker after the location prefix (/static../config, /static..;/etc/passwd), confirmed as a stable file read differing from in-alias and random-suffix controls. This discloses adjacent source, configuration, and secrets served one directory up.

**Fix:** Ensure every alias directive ends with a trailing slash matching its location prefix, or replace alias with root.`

	ModuleConfirmation = "Confirmed when an off-by-slash traversal path returns a stable, non-wildcard 200 whose body differs from both the in-alias equivalent path and a random-suffix traversal — proving the response depends on the escaped path rather than a prefix-wide generic handler"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nginx", "misconfiguration", "lfi", "moderate"}
)
