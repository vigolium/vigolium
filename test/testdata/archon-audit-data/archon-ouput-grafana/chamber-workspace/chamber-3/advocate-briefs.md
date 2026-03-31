# Chamber 3 -- Advocate Defense Briefs

Generated: 2026-03-21T12:00:00Z

---

### [ADVOCATE] Defense Brief for H-01 -- 2026-03-21T12:00:00Z

**Hypothesis:** Public Dashboard Annotation Timerange Bypass (CVE-2026-21722)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | int64 zero-value semantics: `From=0` is a valid epoch timestamp, not "unset" | No | Go zero values are valid integers; no sentinel concept |
| Framework | None -- xorm_store.go:389 uses `query.From > 0 && query.To > 0` as filter guard | No | This IS the vulnerability; the guard treats 0 as "no filter" |
| Middleware | Public dashboard access token validation (UUID format) | Partial -- limits to valid access tokens | `pkg/services/publicdashboards/validation/validation.go:45` |
| Application | `TimeSelectionEnabled` boolean (default false) -- when false, dashboard's own time range is used | Partial -- only blocks when false | `pkg/services/publicdashboards/service/query.go:645` |
| Application | `AnnotationsEnabled` boolean (default false) -- when false, returns empty | Yes -- when false | `pkg/services/publicdashboards/service/query.go:28` |
| Application | OrgID scoping in annotation query | Partial -- limits to org scope | `pkg/services/publicdashboards/service/query.go:52` |
| Documentation | CVE-2026-21722 confirms this is a known bug | N/A -- confirmed vulnerability | CVE reference in debate |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked -- attacker input (HTTP request `from`/`to` fields) directly flows to `reqDTO.From`/`reqDTO.To` via `getAnnotationsTimeRange()` at query.go:644-646, then to `annoQuery.From`/`annoQuery.To` at query.go:49-50, and finally to xorm_store.go:389 where the guard is bypassed.
- Pattern 2 (phantom validation): checked -- `validation.go` validates query time ranges only for `PublicDashboardQueryDTO` (metric queries), NOT for `AnnotationsQueryDTO`. No validation on annotation from/to exists.
- Pattern 3 (framework protection): checked -- not applicable; no framework-level annotation time range enforcement.
- Pattern 4 (same-origin): checked -- not applicable; public dashboards are unauthenticated endpoints.
- Pattern 5 (CVE reachability): checked -- not applicable; this is not a dependency CVE.
- Pattern 6 (config-as-vuln): PARTIAL MATCH -- `TimeSelectionEnabled` must be true. However, this is a per-dashboard setting that dashboard owners commonly enable to allow viewers to adjust time ranges. It is not an admin-only global config, it is a feature toggle that users intentionally enable for legitimate purposes.
- Pattern 7 (test code): checked -- not applicable; this is production code in `pkg/services/publicdashboards/`.
- Pattern 8 (double-counting): checked -- not applicable; unique finding.

**Defense argument:** The strongest defense is that **three conditions must be met simultaneously**: (1) `AnnotationsEnabled` must be true, (2) `TimeSelectionEnabled` must be true, and (3) the dashboard must have tag-based annotation queries (to zero out `DashboardID` at query.go:61). Without tag-based annotations, annotation leakage is limited to the dashboard's own annotations. Additionally, even when all three conditions are met, the scope is limited to the organization's annotations -- not cross-organization. An attacker still needs a valid public dashboard access token (which is a UUID). The `from=0`/`to=0` behavior could also be argued as semantically correct -- epoch 0 (1970-01-01) to epoch 0 is a valid (albeit degenerate) time range, and the xorm guard `From > 0` is simply an optimization to avoid filtering when no range is specified. One might argue this is working as designed.

**Verdict recommendation:** Cannot disprove. The defense arguments are preconditions that reduce exploitability but do not block the attack. The `from > 0` guard at xorm_store.go:389 is clearly a security-relevant filter bypass. Tag-based annotation queries zeroing `DashboardID` at query.go:61 amplifies the scope from single-dashboard to org-wide. The combination is a real information disclosure vulnerability.

---

### [ADVOCATE] Defense Brief for H-02 -- 2026-03-21T12:01:00Z

**Hypothesis:** Renderer JWT Forgery via Default Auth Token (renderAuthJWT)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | JWT library requires valid HMAC-SHA512 signature | Yes -- when token is non-default | `pkg/services/rendering/auth.go:58-60`, `jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()})` |
| Framework | Feature flag `renderAuthJWT` defaults to `false` with `Expression: "false"` | Yes -- blocks by default | `pkg/services/featuremgmt/registry.go:181-185` |
| Framework | Feature stage `PublicPreview` -- not GA | Partial -- signals experimental status | `pkg/services/featuremgmt/registry.go:183` |
| Middleware | `looksLikeJWT()` check gates JWT path -- non-JWT keys use cache path | Yes -- for default mode | `pkg/services/rendering/auth.go:41` |
| Application | Default mode uses per-request random 32-char cache keys (`util.GetRandomString(32)`) | Yes -- for default mode | `pkg/services/rendering/auth.go:103-104` |
| Application | Default `RendererAuthToken` is `"-"` (single hyphen) | No -- this IS the weakness | `pkg/setting/setting.go:2070` |
| Documentation | Feature described as "Public Preview" -- expected to have rough edges | N/A -- implicit acceptance of risk | registry.go:183 |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked -- path is confirmed: attacker crafts JWT signed with `"-"` -> sends as render key -> `GetRenderUser()` at auth.go:34 -> `looksLikeJWT()` check passes (JWT starts with "eyJ") -> `getRenderUserFromJWT()` at auth.go:56 -> validates signature with `[]byte("-")` -> returns `RenderUser` with attacker-controlled OrgID/UserID/OrgRole.
- Pattern 2 (phantom validation): checked -- no additional validation on the render key beyond JWT signature verification.
- Pattern 3 (framework protection): checked -- not applicable; custom auth mechanism.
- Pattern 4 (same-origin): checked -- not applicable; renderer communicates over HTTP.
- Pattern 5 (CVE reachability): checked -- not applicable.
- Pattern 6 (config-as-vuln): MATCH -- **Two** config preconditions: (1) `renderAuthJWT` feature flag must be enabled (default: false), AND (2) `renderer_token` must be left at default `"-"`. Both are admin-level configuration decisions.
- Pattern 7 (test code): checked -- not applicable; production code.
- Pattern 8 (double-counting): checked -- not applicable.

**Defense argument:** This finding requires **two independent administrative configuration decisions** to become exploitable: enabling a `PublicPreview` feature flag (`renderAuthJWT`) AND leaving the renderer auth token at its default value (`"-"`). The default mode (feature flag disabled) uses per-request cryptographically random 32-character cache keys that are deleted after use (auth.go:134-136), which is immune to this attack. The feature flag has `Expression: "false"` and `Stage: FeatureStagePublicPreview`, meaning it is opt-in and explicitly marked as not production-ready. Any administrator who enables a preview feature without configuring its associated security settings is making a deliberate choice. This is a textbook Pattern 6 (config-as-vulnerability) match. Furthermore, access to the render endpoint itself requires authentication -- an attacker needs to be an authenticated user to trigger rendering, and the forged JWT would only elevate their privileges within the rendering subsystem.

**Verdict recommendation:** Cannot fully disprove. While Pattern 6 applies strongly (two admin config prerequisites), the default token value `"-"` is dangerously weak and trivially guessable. A production system enabling `renderAuthJWT` without changing the token would be silently vulnerable with no warning. The finding is valid but severity should reflect the dual preconditions.

---

### [ADVOCATE] Defense Brief for H-03 -- 2026-03-21T12:02:00Z

**Hypothesis:** Plugin Zip Symlink Chain Traversal (SAST-009)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | `filepath.Clean()` normalizes paths | Partial | `pkg/plugins/storage/fs.go:99` |
| Framework | ZipSlip check -- rejects absolute paths and `../` prefixes | Yes -- for direct traversal | `pkg/plugins/storage/fs.go:91-97` |
| Application | `isSymlinkRelativeTo()` -- rejects absolute symlink targets and targets resolving outside plugin dir | Partial -- uses string ops, no `os.EvalSymlinks` | `pkg/plugins/storage/fs.go:165-181` |
| Application | `filepath.Rel()` + `".."` prefix check | Yes -- for single-hop symlinks | `pkg/plugins/storage/fs.go:171-177` |
| Application | Plugin signature verification -- unsigned plugins rejected by default | Yes -- for default config | Grafana plugin signature system |
| Application | `plugins:install` RBAC action required | Yes -- admin-only | `pkg/services/pluginsintegration/pluginaccesscontrol/accesscontrol.go:17` |
| Documentation | Symlink extraction logs warning and continues (non-fatal) | N/A | `pkg/plugins/storage/fs.go:123-124` |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked -- the code path is real: zip file entry -> `extractSymlink()` at fs.go:141 -> `isSymlinkRelativeTo()` at fs.go:153. However, no concrete exploit has been demonstrated that bypasses both ZipSlip AND symlink checks.
- Pattern 2 (phantom validation): MATCH -- Three layers of validation exist: (1) ZipSlip at fs.go:91-97, (2) `isSymlinkRelativeTo` at fs.go:153, (3) plugin signature verification upstream.
- Pattern 3 (framework protection): checked -- not applicable.
- Pattern 4 (same-origin): checked -- not applicable.
- Pattern 5 (CVE reachability): checked -- not applicable.
- Pattern 6 (config-as-vuln): MATCH -- requires admin with `plugins:install` permission AND either unsigned plugin support or a compromised plugin repository.
- Pattern 7 (test code): checked -- not applicable; production code. Tests at `fs_test.go` cover symlink scenarios.
- Pattern 8 (double-counting): checked -- not applicable.

**Defense argument:** This finding has **three independent layers of defense**: (1) The ZipSlip check at fs.go:91-97 prevents direct path traversal via `../` or absolute paths in zip entries. (2) The `isSymlinkRelativeTo` function at fs.go:165-181 checks that symlink targets resolve within the plugin directory using `filepath.Rel()` and `".."` prefix detection. While it lacks `os.EvalSymlinks()` (which would resolve actual filesystem symlinks), the check at fs.go:170 uses `filepath.Clean(filepath.Join(fileDir, symlinkDestPath))` which correctly normalizes `../` sequences in the symlink target itself. A multi-hop symlink chain (symlink A -> symlink B -> ../../target) would need symlink B to already exist on disk at extraction time, but zip entries are extracted sequentially and the order is not guaranteed -- making chain exploitation unreliable. (3) Plugin installation requires `plugins:install` RBAC permission (admin-level) AND plugin signature verification blocks unsigned plugins by default. An attacker would need to compromise the official Grafana plugin repository or convince an admin to enable unsigned plugins. The Tracer marked this as PARTIAL with "No concrete exploit bypassing both ZipSlip + symlink checks." The absence of a demonstrated bypass after analysis strengthens the defense.

**Verdict recommendation:** Disproved by Application protection (three-layer defense + admin-only + no demonstrated bypass). Valid as defense-in-depth observation (the missing `os.EvalSymlinks` call), but not exploitable at current commit.

---

### [ADVOCATE] Defense Brief for H-04 -- 2026-03-21T12:03:00Z

**Hypothesis:** Datasource TOCTOU ReadOnly Bypass (CVE-2026-21725)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | None -- Go has no built-in TOCTOU protection | No | N/A |
| Framework | None -- xorm does not provide automatic pessimistic locking | No | N/A |
| Middleware | RBAC: `datasources:delete` permission required | Yes -- limits to authorized users | Standard Grafana RBAC |
| Application | ReadOnly check before delete at datasources.go:260 and datasources.go:314 | Partial -- check-then-act, not atomic | `pkg/api/datasources.go:260,314` |
| Application | Store `DeleteDataSource` re-fetches DS inside transaction but does NOT re-check ReadOnly | No | `pkg/services/datasources/service/store.go:190-228` |
| Documentation | CVE-2026-21725 pattern reference | N/A -- confirmed pattern | debate.md |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked -- path is confirmed. API handler at datasources.go:252 fetches DS, checks ReadOnly at :260, then calls DeleteDataSource at :266. Store at store.go:190-228 runs in transaction but never checks ReadOnly.
- Pattern 2 (phantom validation): checked -- store.go:192-193 re-fetches the datasource inside the transaction but does NOT check `ds.ReadOnly` before deletion at line 201. No phantom validation exists.
- Pattern 3 (framework protection): checked -- not applicable.
- Pattern 4 (same-origin): checked -- not applicable.
- Pattern 5 (CVE reachability): checked -- not applicable.
- Pattern 6 (config-as-vuln): checked -- not applicable; ReadOnly is set by provisioning config, not a global admin toggle. The TOCTOU exists regardless of configuration.
- Pattern 7 (test code): checked -- not applicable; production code.
- Pattern 8 (double-counting): checked -- related to H-05 (cache invalidation) but different root cause. H-04 is about the race between read and delete; H-05 is about stale cache after delete.

**Defense argument:** The TOCTOU race window is **extremely narrow**. The attacker must: (1) have `datasources:delete` RBAC permission (admin-level), (2) time their delete request to land between when another admin changes the datasource to ReadOnly and when their request reads the stale state. The practical exploit scenario is: Admin A provisions a datasource as ReadOnly via config. Admin B (malicious or confused) calls DELETE API. The race is between the provisioning system setting ReadOnly=true and the DELETE handler's read at datasources.go:252. In practice, provisioning writes ReadOnly at creation time, not as an update. Once a datasource is created as ReadOnly, it remains ReadOnly -- there is no API to toggle ReadOnly dynamically. The only way to change ReadOnly is via provisioning config file changes, which require a Grafana restart or reload. This means the race window only exists during the brief moment of provisioning reload. Furthermore, even if the race succeeds, the impact is limited: a provisioned datasource gets deleted, but the provisioning system will re-create it on next reload. **The operational impact is transient and self-healing.**

**Verdict recommendation:** Cannot disprove structurally (the TOCTOU pattern exists in code), but practical exploitability is extremely low due to: (1) admin-only RBAC requirement, (2) ReadOnly only set via provisioning (not API-toggleable), (3) self-healing on next provisioning reload. The finding is valid as a structural code quality issue but not as a practical security vulnerability.

---

### [ADVOCATE] Defense Brief for H-05 -- 2026-03-21T12:04:00Z

**Hypothesis:** Datasource Cache No Delete Invalidation (CVE-2026-21725)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | None | No | N/A |
| Framework | None | No | N/A |
| Middleware | RBAC: `datasources:delete` permission required for delete | Yes -- limits to authorized users | Standard Grafana RBAC |
| Application | Cache TTL of 5 seconds (`DefaultCacheTTL`) | Partial -- bounds stale window | `pkg/services/datasources/service/cache.go:17` |
| Application | `canQuery()` guardian check on every cache hit | Yes -- access control enforced even from cache | `pkg/services/datasources/service/cache.go:50-51,97-98` |
| Application | `skipCache` parameter allows bypassing cache | Partial -- callers can opt out | `pkg/services/datasources/service/cache.go:46,93` |
| Documentation | N/A | N/A | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked -- confirmed. `DeleteDataSource` at store.go:190 deletes from DB. No call to `CacheService.Delete()` or cache invalidation. `GetDatasource`/`GetDatasourceByUID` at cache.go:38,79 will serve stale cached entries for up to 5 seconds.
- Pattern 2 (phantom validation): PARTIAL MATCH -- `canQuery()` at cache.go:50-51 is called on every cache hit, enforcing access control even for stale entries. However, `canQuery` checks RBAC permissions, not whether the datasource still exists. A deleted datasource would still pass `canQuery` if the user had permission.
- Pattern 3 (framework protection): checked -- not applicable.
- Pattern 4 (same-origin): checked -- not applicable.
- Pattern 5 (CVE reachability): checked -- not applicable.
- Pattern 6 (config-as-vuln): checked -- not applicable; this is a code-level missing invalidation.
- Pattern 7 (test code): checked -- not applicable; production code.
- Pattern 8 (double-counting): PARTIAL MATCH -- this is closely related to H-04 (same datasource lifecycle, same CVE reference). Different root cause (cache vs TOCTOU) but same attack surface. Could be argued as the same underlying issue: "datasource deletion is not atomic with respect to its cached state."

**Defense argument:** The 5-second TTL at cache.go:17 provides a **hard upper bound** on the stale window. After 5 seconds, any cached datasource entry expires naturally and subsequent lookups hit the database, which will return `ErrDataSourceNotFound`. The practical impact is that for at most 5 seconds after deletion, queries targeting the deleted datasource might still succeed. However: (1) `canQuery()` is still enforced on every cache hit (cache.go:50-51), meaning only users with existing query permissions can exploit the stale cache. (2) The stale window is bounded and self-correcting. (3) In HA deployments, different nodes may have different cache states, but each node independently expires after 5 seconds. (4) The deleted datasource's underlying data source (e.g., Prometheus endpoint) likely still exists -- the deletion only removes Grafana's reference to it. Querying a "deleted" datasource reference for 5 seconds reveals no data that the user could not have accessed 5 seconds earlier when the datasource was still active. **The security impact is negligible because no authorization boundary is crossed.**

**Verdict recommendation:** Cannot fully disprove (the missing cache invalidation is real), but the security impact is minimal. The 5-second TTL bounds the window, `canQuery()` enforces access control, and no authorization boundary is crossed during the stale window. This is better classified as a correctness/quality issue than a security vulnerability.

---

### [ADVOCATE] Defense Brief for H-06 -- 2026-03-21T12:05:00Z

**Hypothesis:** Renderer ServeFile No Path Confinement (SAST-008)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | `http.ServeFile` from Go stdlib -- handles path cleaning internally | Partial -- prevents `../` in URL but file path is from server | `pkg/api/render.go:122` |
| Framework | Grafana auth middleware -- render endpoint requires authentication | Yes -- limits to authenticated users | Standard Grafana route registration |
| Application | File path generated from 20-char crypto-random string via `util.GetRandomString(20)` | Yes -- path not user-controlled | `pkg/services/rendering/rendering.go:389` |
| Application | File extension hardcoded to `.png`, `.pdf`, or `.csv` | Yes -- no user control over extension | `pkg/services/rendering/rendering.go:396-406` |
| Application | Directory is server-configured (`ImagesDir`, `PDFsDir`, `CSVsDir`) | Yes -- not user-controlled | `pkg/services/rendering/rendering.go:399-405` |
| Application | `filepath.Abs(filepath.Join(folder, ...))` constructs path safely | Yes -- no path injection possible | `pkg/services/rendering/rendering.go:408` |
| Documentation | CVE-2025-11539 is referenced as historical precedent for renderer vulnerabilities | N/A -- historical context | debate.md |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): MATCH -- the `result.FilePath` at render.go:122 is NOT user-controlled. It comes from `getNewFilePath()` at rendering.go:388 which constructs the path from: (1) a server-configured directory, (2) a 20-character crypto-random string, (3) a hardcoded extension. No user input influences the file path.
- Pattern 2 (phantom validation): checked -- not needed; the path is server-generated.
- Pattern 3 (framework protection): checked -- `http.ServeFile` does its own path cleaning but that is irrelevant since the file path is not from user input.
- Pattern 4 (same-origin): checked -- not applicable.
- Pattern 5 (CVE reachability): checked -- not applicable.
- Pattern 6 (config-as-vuln): checked -- not applicable.
- Pattern 7 (test code): checked -- not applicable; production code.
- Pattern 8 (double-counting): checked -- not applicable.

**Defense argument:** The file path passed to `http.ServeFile` at render.go:122 is **entirely server-generated** with no user input influencing any component. The path is constructed from: (1) a server-configured directory (e.g., `cfg.ImagesDir`), (2) a 20-character cryptographically random string from `util.GetRandomString(20)`, and (3) a hardcoded file extension (`.png`, `.pdf`, or `.csv`). The resulting path looks like `/var/lib/grafana/png/aB3xK9mN2pQ7wR4tY5.png`. There is no vector for an attacker to influence this path to point to an arbitrary file. The Tracer correctly concluded "REACHABLE but NOT EXPLOITABLE" and the finding is purely a defense-in-depth observation. The reference to CVE-2025-11539 is a historical precedent from a different code path and does not demonstrate exploitability of this specific code. This is a classic **Pattern 1 match** -- the code looks unsafe (unconstrained `ServeFile`) but there is no path from attacker input to the file path parameter.

**Verdict recommendation:** Disproved by Application protection. The file path is not user-controlled. Pattern 1 match (unsafe-looking code without path tracing). Valid only as defense-in-depth observation.

---

### [ADVOCATE] Defense Brief for H-07 -- 2026-03-21T12:06:00Z

**Hypothesis:** Stored XSS via Annotation Text in Public Dashboard

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go `encoding/json` serializes annotation text as plain string | Partial -- no server-side HTML encoding but JSON encoding prevents injection in JSON context | N/A |
| Framework | React's JSX auto-escaping -- `{text}` in JSX is auto-escaped | Yes -- for direct text rendering | React default behavior |
| Application | Server returns annotation text as raw JSON string field (no HTML rendering) | Partial -- depends on client handling | `pkg/services/publicdashboards/service/query.go:79` |
| Application | DOMPurify sanitization on client for annotation text rendering | Yes -- blocks XSS payloads | Standard Grafana frontend sanitization |
| Application | Content-Type: application/json on API responses | Partial -- prevents direct HTML interpretation of API response | Standard Grafana API behavior |
| Documentation | N/A | N/A | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked -- the server does return raw annotation text without sanitization at query.go:79. But the question is whether the client renders it unsafely.
- Pattern 2 (phantom validation): MATCH -- DOMPurify sanitization exists on the client side for annotation text rendering.
- Pattern 3 (framework protection): MATCH -- React's JSX auto-escaping prevents XSS when text is rendered via `{text}` syntax.
- Pattern 4 (same-origin): checked -- not applicable.
- Pattern 5 (CVE reachability): checked -- not applicable.
- Pattern 6 (config-as-vuln): checked -- not applicable.
- Pattern 7 (test code): checked -- not applicable.
- Pattern 8 (double-counting): checked -- not applicable.

**Defense argument:** The annotation text is returned as a plain JSON string field in the API response. On the client side, Grafana renders annotations using React components that apply **two layers of XSS protection**: (1) React's built-in JSX auto-escaping, which prevents raw HTML injection when text is rendered via `{text}` expressions, and (2) DOMPurify sanitization for any annotation text that is rendered via `dangerouslySetInnerHTML` (for markdown/HTML annotations). The Tracer marked this as PARTIAL with "Client sanitization active by default. No DOMPurify bypass demonstrated." Without a demonstrated bypass of DOMPurify, this finding lacks a concrete attack path. The server's decision to not sanitize annotation text is a design choice -- sanitization belongs at the rendering layer (client), not the data layer (server), since the same text may be rendered in different contexts (HTML, plain text, notifications).

**Verdict recommendation:** Disproved by Framework protection (React auto-escaping) and Application protection (DOMPurify). FP pattern match: Pattern 2 (phantom validation) and Pattern 3 (framework protection). No bypass demonstrated.

---

## Summary of Defense Verdicts

| Hypothesis | Advocate Verdict | Key Defense |
|-----------|-----------------|-------------|
| H-01 | Cannot disprove | Three preconditions reduce exposure but do not block; xorm_store.go:389 guard bypass is real |
| H-02 | Cannot fully disprove | Pattern 6 (dual config prerequisites) but default token `"-"` is dangerously weak |
| H-03 | Disproved by Application | Three-layer defense + admin-only + no demonstrated bypass |
| H-04 | Cannot disprove structurally | TOCTOU exists in code but practical exploitability is extremely low |
| H-05 | Cannot fully disprove | 5s TTL bounds window, canQuery() enforced, minimal security impact |
| H-06 | Disproved by Application | Pattern 1 match: file path not user-controlled |
| H-07 | Disproved by Framework+Application | Pattern 2+3 match: DOMPurify + React auto-escaping |
