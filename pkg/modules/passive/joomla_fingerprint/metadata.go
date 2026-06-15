package joomla_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "joomla-fingerprint"
	ModuleName  = "Joomla Fingerprint"
	ModuleShort = "Identifies Joomla installations and enumerates components, modules, and plugins from asset paths"
)

var (
	ModuleDesc = `**What it means:** The target runs the Joomla CMS, identified from the generator meta tag, /media/system/js/ and com_* asset paths, or the Joomla 4+ JS API. The check reports the major generation and enumerates installed components, modules, and plugins. Informational recon, not a vulnerability.

**How it's exploited:** An attacker uses the disclosed version and extensions to map the surface and look up version-specific CVEs - third-party Joomla extensions are a common source of SQLi, LFI, and RCE.

**Fix:** Keep Joomla core and every extension patched, remove unused ones, and consider suppressing the generator meta tag.`

	ModuleConfirmation = "Confirmed when Joomla-specific asset paths, headers, or meta tags are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"joomla", "cms", "fingerprint", "light"}
)
