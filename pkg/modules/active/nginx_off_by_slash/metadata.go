package nginx_off_by_slash

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nginx-off-by-slash"
	ModuleName  = "Nginx Off-by-Slash"
	ModuleShort = "Detects Nginx alias traversal via missing trailing slash"
)

var (
	ModuleDesc = `## Description
Tests for Nginx "off-by-slash" alias traversal misconfiguration. When an Nginx location block
uses an alias directive without a matching trailing slash, attackers can traverse outside the
intended directory. For example, "location /static { alias /var/www/assets/; }" allows
requesting "/static../etc/passwd" to read files outside /var/www/assets/.

## Notes
- Operates on path segments, testing each first-level directory for alias traversal
- Compares response body against baseline to confirm the traversal resolved to the same content
- Skips media/JS URLs, non-GET requests, and very small baseline responses

## References
- https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
- https://github.com/bayotop/off-by-slash
- https://github.com/yandex/gixy
- https://github.com/hakaioffsec/nginx-alias-traversal`

	ModuleConfirmation = "Confirmed when a path-traversal request using the off-by-slash pattern returns status 200 with a body matching a known valid suffix endpoint"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags = []string{"nginx", "misconfiguration", "lfi", "moderate"}
)
