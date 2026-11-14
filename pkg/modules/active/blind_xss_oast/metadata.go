package blind_xss_oast

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "blind-xss-oast"
	ModuleName  = "Blind XSS (out-of-band)"
	ModuleShort = "Plants script tags pointing at a unique OAST host in stored inputs; a browser loading it later proves blind XSS"
)

var (
	ModuleDesc = `**What it means:** Input the application stores is rendered later, somewhere the scanner cannot see (an admin panel, a support console, a log viewer), without HTML encoding: a planted script tag was loaded by a browser.

**How it's exploited:** An attacker stores a script payload; when a privileged user opens the page that renders it, the script runs in that user's session.

**Fix:** HTML-encode stored input for its rendering context on every page that shows it, internal tools included, and set a Content Security Policy that forbids third-party scripts.`

	ModuleConfirmation = "Confirmed when a web browser fetches the unique OAST script URL planted in a stored input (possibly days later; collected by `vigolium oast poll`). A DNS-only or non-browser fetch files as Suspect/Tentative"
	// The live finding is rated by the OAST classifier (High/Firm for a
	// browser fetch, Suspect/Tentative otherwise); the module itself files
	// nothing in-band.
	ModuleSeverity   = severity.High
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"xss", "stored", "blind", "oast", "injection", "moderate"}
)
