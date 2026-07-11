package reverse_tabnabbing_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "reverse-tabnabbing-detect"
	ModuleName  = "Reverse Tabnabbing"
	ModuleShort = "Flags cross-origin target=_blank links that explicitly opt into rel=opener"
)

var (
	ModuleDesc = `**What it means:** The page opens a cross-origin link with target="_blank" and explicitly opts into rel="opener". This overrides the HTML Standard's implicit noopener behavior for ordinary _blank links.

**How it's exploited:** The linked (attacker-controlled or compromised) page uses window.opener.location to silently navigate the original tab to a phishing clone — reverse tabnabbing — while the user is looking at the new tab.

**Fix:** Remove the opener token unless the destination genuinely needs to control the opening page. rel="noopener" or rel="noreferrer" can be used explicitly for clarity.`

	ModuleConfirmation = "Candidate when a cross-origin target=_blank anchor explicitly contains rel=opener without noopener or noreferrer"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"client-side", "tabnabbing", "html", "light"}
)
