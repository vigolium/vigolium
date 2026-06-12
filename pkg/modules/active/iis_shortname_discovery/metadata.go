package iis_shortname_discovery

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "iis-shortname-discovery"
	ModuleName  = "IIS Short Filename Discovery"
	ModuleShort = "Enumerates IIS 8.3 short filenames via tilde-based oracle (per-host)"
)

var (
	ModuleDesc = `**What it means:** The Microsoft IIS server leaks partial file and directory names because 8.3 short-filename (tilde) generation is enabled. By sending wildcard paths containing a tilde and watching for differential HTTP status codes, anyone can recover the first six characters and three-character extension of files under the web root, even when directory listing is disabled. This module confirmed the oracle and brute-forced the disclosed short names it reports.

**How it's exploited:** An attacker maps the hidden attack surface from these fragments: backup files (web~1.zip), config and credential files, admin pages, and unlinked endpoints never meant to be reachable. The short names narrow guessing of full filenames dramatically, turning blind discovery into targeted requests that can pull source, secrets, or otherwise restricted resources. It is information disclosure on its own, but a strong stepping stone to further compromise.

**Fix:** Disable 8.3 short-name generation on the volume (set NtfsDisable8dot3NameCreation and strip existing short names with fsutil), or restrict the surface so the tilde oracle no longer returns distinct status codes.`

	ModuleConfirmation = "Confirmed when the server returns distinct status codes for wildcard patterns matching existing vs non-existing 8.3 short filenames"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"aspnet", "info-disclosure", "heavy"}
)
