package reverse_tabnabbing_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "reverse-tabnabbing-detect"
	ModuleName  = "Reverse Tabnabbing"
	ModuleShort = "Flags target=_blank links to cross-origin URLs missing rel=noopener"
)

var (
	ModuleDesc = `**What it means:** The page opens a cross-origin link with target="_blank" but without rel="noopener" (or "noreferrer"). The opened page receives a window.opener reference back to this page.

**How it's exploited:** The linked (attacker-controlled or compromised) page uses window.opener.location to silently navigate the original tab to a phishing clone — reverse tabnabbing — while the user is looking at the new tab.

**Fix:** Add rel="noopener noreferrer" to every target="_blank" link, and set a Referrer-Policy. Modern browsers imply noopener for target=_blank, so this mainly affects older browsers.`

	ModuleConfirmation = "Confirmed when an anchor with target=_blank points at a cross-origin URL and carries no rel=noopener/noreferrer"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"client-side", "tabnabbing", "html", "light"}
)
