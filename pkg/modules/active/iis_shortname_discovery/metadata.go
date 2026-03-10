package iis_shortname_discovery

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "iis-shortname-discovery"
	ModuleName  = "IIS Short Filename Discovery"
	ModuleShort = "Enumerates IIS 8.3 short filenames via tilde-based oracle (per-host)"
)

var (
	ModuleDesc = `## Description
Detects and enumerates IIS 8.3 short filenames exposed through the tilde (~)
vulnerability. When IIS has short filename generation enabled, an attacker can
discover partial file and directory names by observing differential HTTP status
codes for wildcard-based requests.

The module performs three phases:
1. **Vulnerability detection** - tests HTTP methods and path suffixes to find a
   working oracle (distinct status codes for existing vs non-existing patterns)
2. **Character discovery** - identifies which characters appear in short filenames
   to minimize the enumeration search space
3. **Recursive enumeration** - brute-forces filenames character-by-character
   (up to 6 chars for name, 3 for extension per 8.3 convention)

## Notes
- Only runs on IIS servers (detected via Server, X-Powered-By, or X-AspNet-Version headers)
- Runs once per unique host
- Caps total requests at 2000 per host to avoid excessive traffic
- Reports discovered 8.3 short filenames (does not attempt full-name autocomplete)

## References
- https://soroush.me/blog/2023/07/thirteen-years-on-advancing-the-understanding-of-iis-short-file-name-sfn-disclosure/
- https://github.com/bitquark/shortscan`

	ModuleConfirmation = "Confirmed when the server returns distinct status codes for wildcard patterns matching existing vs non-existing 8.3 short filenames"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"aspnet", "info-disclosure", "heavy"}
)
