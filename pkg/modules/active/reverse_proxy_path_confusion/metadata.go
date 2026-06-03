package reverse_proxy_path_confusion

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "reverse-proxy-path-confusion"
	ModuleName  = "Reverse Proxy Path Confusion"
	ModuleShort = "Reaches restricted backend endpoints via proxy-vs-backend path-parsing disagreement"
)

var (
	ModuleDesc = `## Description
Detects access-control bypass where a reverse proxy and its backend disagree about which path a
request names. The proxy routes (or blocks) based on its reading of the path, while the backend
normalizes a confusion shell — fragment truncation (` + "`/%23/..`" + `), path-parameter
traversal (` + "`/..;`" + `), or encoded traversal — back to a restricted endpoint and serves it.
This reaches admin/internal endpoints (Tomcat Manager, Spring Actuator, mod_status, Prometheus)
that are blocked when requested directly.

Based on Aleksei Tiurin's "A Fresh Look on Reverse Proxy Related Attacks" (Acunetix, 2019) and
Orange Tsai's path-confusion work.

## Notes
- Distinct from nginx-off-by-slash (filesystem alias traversal) and forbidden-bypass (mangles
  the same path, only on an existing 401/403). This module reaches a curated set of *different*
  restricted endpoints via routing/ACL confusion and confirms with a backend fingerprint.
- Very strong false-positive control (no finding on a bare 200):
  1. the target fetched directly must be blocked/absent;
  2. the same shell around a random non-existent target must NOT yield the fingerprint;
  3. the shell must reproducibly return 200 + the endpoint fingerprint across multiple rounds;
  4. an introduced-content differential (with vs without the payload, repeated) must confirm the
     fingerprint content is genuinely introduced by the shell and absent from the direct baseline;
  5. soft-404 / SPA wildcard responses are rejected.
- Runs once per host.

## References
- https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/
- https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf`

	ModuleConfirmation = "Confirmed when a path-confusion shell reaches a restricted backend endpoint (matching its content fingerprint) that is blocked when requested directly, surviving a decoy-target negative, multi-round replay, and an introduced-content differential"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"proxy", "access-control", "heavy"}
)
