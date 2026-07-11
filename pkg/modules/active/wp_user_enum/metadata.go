package wp_user_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-user-enum"
	ModuleName  = "WordPress User Enumeration"
	ModuleShort = "Detects WordPress user enumeration via author archives and REST API"
)

var (
	ModuleDesc = `**What it means:** Credential-free controls found distinct WordPress author slugs through canonical author redirects or the public REST author collection. These slugs often identify content authors by design.

**How it's exploited:** Author slugs may help password spraying if they equal login names, but this module does not prove that mapping, identify private accounts, or test login controls. Results therefore remain observations.

**Fix:** Block author-scan redirects, restrict the REST users endpoint to authenticated requests, and enforce strong passwords plus login rate-limiting or 2FA.`

	ModuleConfirmation = "Observed when credential-free author-ID controls yield distinct non-catch-all slugs or structurally parsed REST author objects; login identity is not inferred"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"wordpress", "cms", "php", "authentication", "light"}
)
