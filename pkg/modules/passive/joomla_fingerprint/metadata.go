package joomla_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "joomla-fingerprint"
	ModuleName  = "Joomla Fingerprint"
	ModuleShort = "Identifies Joomla installations and enumerates components, modules, and plugins from asset paths"
)

var (
	ModuleDesc = `**What it means:** The target is running the Joomla CMS, identified passively from the served HTML via the generator meta tag, /media/system/js/ and com_* asset paths, or the Joomla 4+ JavaScript API. The scanner also reports the major generation (e.g. Joomla 4+) and enumerates installed components, modules, and plugins referenced in the page. This is an informational fingerprint, not a vulnerability on its own, but it discloses the exact CMS and third-party extensions in use.

**How it's exploited:** Knowing the site runs Joomla and which extensions are installed lets an attacker map the attack surface and look up known CVEs for the core version and for each named component, module, or plugin, then aim version-specific exploits (third-party Joomla extensions are a common source of SQLi, LFI, and RCE) instead of probing blindly.

**Fix:** Keep Joomla core and every installed extension fully patched, remove unused extensions, and consider suppressing the generator meta tag if you do not want the CMS publicly advertised.`

	ModuleConfirmation = "Confirmed when Joomla-specific asset paths, headers, or meta tags are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"joomla", "cms", "fingerprint", "light"}
)
