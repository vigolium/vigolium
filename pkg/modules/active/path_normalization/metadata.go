package path_normalization

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "path-normalization"
	ModuleName  = "Path Normalization"
	ModuleShort = "Detects path normalization vulnerabilities"
)

var (
	ModuleDesc = `## Description
Tests for path normalization vulnerabilities through two oracles:

1. **Proxy normalization (status oracle):** iteratively applies traversal payloads
   (with conditional auto-slashing) and checks response status codes and fingerprints
   against expected internal/public patterns, surfacing reverse-proxy/backend
   path-parsing disagreements.
2. **Static-root traversal (file-read oracle):** on static-file-handler requests,
   sends matrix-parameter + encoded-slash bypasses (e.g. ` + "`/static;/..%2f..%2f`" + `)
   that keep the router pointed at the static mount while the file resolver
   (Node ` + "`send`" + ` / ` + "`serve-static`" + ` and similar) decodes and traverses above the
   root, defeating its startsWith(root) boundary check. Confirms by reading known
   files (OS files plus Node app-root files such as package.json/.env) or by
   surfacing a directory / cloud-bucket listing.

## Notes
- Status oracle: compares response fingerprints between public and internal path
  variations; requires the backed-off path to actually reach a resource (2xx) and
  to reproduce, so a host's generic 403/404/500 handling for malformed paths is
  not mistaken for an internal resource.
- Static-root oracle: tiered payload sweep (canonical shape first; unicode /
  double-encoding / control-character breakers %0a %0d %00 %23 and extra targets
  only after a Tier-1 signal). Confirms with baseline-subtracted content markers,
  a wildcard/soft-404 reject, a decoy-filename negative, and a reproduction
  re-fetch. A multi-marker file read is reported Critical/Certain.
- The static-root oracle intentionally runs on media/JS asset URLs because those
  are the static-handler requests; it is deduped once per (host, mount-segment).

## References
- https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
- https://github.com/pillarjs/send`

	ModuleConfirmation = "Confirmed either when a traversal payload is rejected (HTTP 400) while the backed-off path reproducibly reaches a 2xx resource whose fingerprint differs from the baseline/root/non-existent references, or when a matrix-parameter/encoded-slash shell reproducibly reads a known file (or surfaces a directory/bucket listing) off the static root, with baseline-subtracted markers surviving a wildcard and decoy-filename negative"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "lfi", "traversal", "moderate"}
)
