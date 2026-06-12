package nginx_off_by_slash

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nginx-off-by-slash"
	ModuleName  = "Nginx Off-by-Slash"
	ModuleShort = "Detects Nginx alias traversal via missing trailing slash"
)

var (
	ModuleDesc = `**What it means:** The server has the Nginx "off-by-slash" alias traversal misconfiguration: a location block uses the alias directive without a matching trailing slash (for example, location /static { alias /var/www/assets/; }), so a request path can break out of the intended directory. This lets an unauthenticated attacker read files outside the directory the location was meant to serve.

**How it's exploited:** The scanner appends a traversal marker just after the location prefix (such as /static../config or /static..;/etc/passwd) and confirms the response is a stable, non-wildcard file read whose body differs from the in-alias and random-suffix controls. In practice this discloses adjacent application files, source code, configuration, secrets, or other sensitive files served from one directory up, and can be used to map and pull further files from the host filesystem.

**Fix:** Ensure every alias directive ends with a trailing slash that matches its location prefix, or replace alias with root, so the path cannot escape the intended directory.`

	ModuleConfirmation = "Confirmed when an off-by-slash traversal path returns a stable, non-wildcard 200 whose body differs from both the in-alias equivalent path and a random-suffix traversal — proving the response depends on the escaped path rather than a prefix-wide generic handler"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nginx", "misconfiguration", "lfi", "moderate"}
)
