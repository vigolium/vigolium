package iis_shortname_discovery

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "iis-shortname-discovery"
	ModuleName  = "IIS Short Filename Discovery"
	ModuleShort = "Enumerates IIS 8.3 short filenames via tilde-based oracle (per-host)"
)

var (
	ModuleDesc = `**What it means:** The IIS server leaks partial file and directory names because 8.3 short-filename (tilde) generation is enabled. Wildcard paths with a tilde return differential HTTP status codes recovering the first six characters and three-character extension of files under the web root. Informational recon.

**How it's exploited:** An attacker maps hidden surface from these fragments: backup files (web~1.zip), config and credential files, admin pages, and unlinked endpoints, narrowing full-filename guessing into targeted requests.

**Fix:** Disable 8.3 short-name generation on the volume (NtfsDisable8dot3NameCreation, strip names with fsutil), or restrict the surface so the tilde oracle returns no distinct status.`

	ModuleConfirmation = "Confirmed when the server returns distinct status codes for wildcard patterns matching existing vs non-existing 8.3 short filenames"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"aspnet", "info-disclosure", "heavy"}
)
