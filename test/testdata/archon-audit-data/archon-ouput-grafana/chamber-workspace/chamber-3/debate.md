# Review Chamber: chamber-3

Cluster: Data Isolation, File Rendering & Plugin Security
DFD Slices: DFD-2 (SQL Expression Engine), DFD-3 (Plugin System), DFD-4 (Image Renderer), DFD-5 (Dashboard/Annotations), DFD-7 (K8s Snapshot API)
NNN Range: p8-040 to p8-059
Started: 2026-03-21T10:00:00Z
Status: CLOSED

---

## Round 1 -- Ideation

### [IDEATOR] Hypotheses -- 2026-03-21T10:01:00Z

Based on DFD slices, enriched findings, and probe-validated evidence, the following hypotheses are proposed:

#### H-01: SQL Expression Engine SELECT INTO OUTFILE Arbitrary File Write (CVE-2024-9264 variant)
**Cluster**: DFD-2 (SQL Expression Engine)
**Attack**: An authenticated user with Editor/Admin role who can create dashboard panels with SQL expressions can inject `SELECT ... INTO OUTFILE '/path/to/file'` to write arbitrary files on the Grafana server filesystem.
**Rationale**: 4 control failures identified in probe phase:
1. `*sqlparser.Into` is on the allowlist in `parser_allow.go:113`
2. `mysql.WithDisableFileWrites(true)` is NOT called when creating the SQL context in `db.go:71`
3. `Into.IsReadOnly()` delegates to child node, so `SELECT INTO OUTFILE` passes the engine's read-only check
4. `secure_file_priv` defaults to `""` (empty string), which means no path restriction
**Pre-condition**: Feature toggle `sqlExpressions` must be enabled (PublicPreview stage, Expression="false" by default)
**Impact**: Arbitrary file write on the server -- potential RCE via cron, SSH key injection, web shell, etc.

#### H-02: Plugin Readme XSS via dangerouslySetInnerHTML Without Sanitization
**Cluster**: DFD-3 (Plugin System)
**Attack**: A malicious plugin published to grafana.com catalog can include XSS payloads in its README that execute in the browser of any Grafana admin viewing the plugin catalog page.
**Rationale**: `PluginDetailsBody.tsx:57-59` renders `plugin.details?.readme` via `dangerouslySetInnerHTML` without any DOMPurify or sanitize call. However, the readme may come from two sources: local (sanitized via `renderMarkdown`) or remote (from GCOM API).
**Impact**: Stored XSS affecting Grafana admins browsing the plugin catalog.

#### H-03: Renderer JWT Forgery with Default Auth Token
**Cluster**: DFD-4 (Image Renderer)
**Attack**: When `renderAuthJWT` feature flag is enabled and the default `renderer_token` value of `"-"` is not changed, an attacker who can reach the Grafana renderer authentication endpoint can forge JWTs signed with the known key `"-"` to authenticate as any user/org.
**Rationale**: `setting.go:2070` shows `renderer_token` defaults to `"-"`. `auth.go:58-60` uses this token as HMAC-SHA512 signing key. A single-byte key is trivially brute-forceable or known.
**Pre-condition**: `renderAuthJWT` feature flag must be enabled AND `renderer_token` must remain at default.
**Impact**: Authentication bypass for renderer endpoints, potentially leading to SSRF or data exfiltration.

#### H-04: Plugin Zip Symlink Traversal via Missing EvalSymlinks
**Cluster**: DFD-3 (Plugin System)
**Attack**: A crafted plugin zip can contain a symlink that resolves to a path outside the plugin directory by exploiting the string-based path comparison in `isSymlinkRelativeTo` (which does not call `os.EvalSymlinks` on the basePath).
**Rationale**: `storage/fs.go:165-178` -- `isSymlinkRelativeTo` uses `filepath.Clean` and `filepath.Rel` but does NOT resolve the `basePath` itself via `os.EvalSymlinks`. If the extraction directory contains symlinks in its path components, the check could be bypassed.
**Impact**: Arbitrary file read/write during plugin installation.

#### H-05: Plugin Changelog/StatusContext XSS Paths
**Cluster**: DFD-3 (Plugin System)
**Attack**: The `Changelog.tsx` component accepts `sanitizedHTML` prop but does not sanitize it internally. The `PluginDetailsDeprecatedWarning.tsx` renders `plugin.details.statusContext` through `renderMarkdown` which runs `sanitizeTextPanelContent` (xss library, not DOMPurify).
**Rationale**: `Changelog.tsx:15` trusts the `sanitizedHTML` prop name but does not verify sanitization. `PluginDetailsDeprecatedWarning.tsx:42-45` uses `renderMarkdown` which uses the xss library (less strict than DOMPurify).
**Impact**: XSS if the xss library has bypass vectors or if the data is not sanitized upstream.

#### H-06: K8s Dashboard Snapshot SQL Injection
**Cluster**: DFD-7 (K8s Snapshot API)
**Attack**: The dashboard snapshot database layer uses parameterized queries for all operations, making SQL injection unlikely.
**Rationale**: Review of `database/database.go` shows all queries use `?` placeholders with `sess.Exec` or XORM's `sess.Get/Insert`. No string concatenation with user input.
**Impact**: If confirmed, SQL injection in the snapshot store.

---

## Round 2 -- Tracing

### [TRACER] Evidence for H-01 -- 2026-03-21T10:10:00Z

**Verdict: REACHABLE -- 4-control failure chain fully confirmed**

**Source**: User-supplied SQL query string in dashboard panel expression configuration
**Sink**: File system write via go-mysql-server's `buildInto` -> `createIfNotExists` -> `os.OpenFile`

**Complete code path**:

1. **Entry point**: Dashboard panel with SQL expression type. User provides raw SQL query string.
   - `pkg/expr/nodes.go:128` -- gated by `FlagSqlExpressions` feature toggle (PublicPreview, default off but widely enabled)

2. **Parser allowlist check**: `pkg/expr/sql/parser_allow.go:113`
   ```go
   case *sqlparser.Into:
       return  // allowed!
   ```
   The `*sqlparser.Into` AST node is explicitly on the allowlist. A query like `SELECT * FROM A INTO OUTFILE '/tmp/evil'` parses to a Select with an Into child, and the allowlist walk permits it.

3. **Engine initialization**: `pkg/expr/sql/db.go:67-84`
   ```go
   pro := NewFramesDBProvider(frames)
   session := mysql.NewBaseSession()
   mCtx := mysql.NewContext(ctx, mysql.WithSession(session), mysql.WithTracer(tracer))
   // NOTE: WithDisableFileWrites(true) is NOT called here
   // The commented-out line at 76-77 shows awareness but no fix:
   // //ctx.SetSessionVariable(ctx, "secure_file_priv", "")
   a := analyzer.NewDefault(pro)
   engine := sqle.New(a, &sqle.Config{IsReadOnly: true})
   ```
   - `mysql.WithDisableFileWrites(true)` is NOT passed to `mysql.NewContext()`
   - `secure_file_priv` is NOT set on the session
   - `IsReadOnly: true` is set, but...

4. **ReadOnly bypass**: `go-mysql-server@v0.20.2-grafana/sql/plan/into.go:82-84`
   ```go
   func (i *Into) IsReadOnly() bool {
       return i.Child.IsReadOnly()  // delegates to child SELECT, which IS read-only!
   }
   ```
   The `Into` plan node's `IsReadOnly()` returns `true` when wrapping a SELECT, so the engine's `readOnlyCheck` at `engine.go:787` passes.

5. **secure_file_priv bypass**: `go-mysql-server@v0.20.2-grafana/sql/variables/system_variables.go:2227`
   ```go
   Default: "",  // empty string = no restriction
   ```
   And `sql/rowexec/rel.go:547`:
   ```go
   if secureFileDir == nil || secureFileDir == "" {
       return nil  // no restriction!
   }
   ```

6. **DisableFileWrites not set**: `sql/rowexec/rel.go:600`
   ```go
   if ctx.DisableFileWrites() {
       return nil, sql.ErrFileWritesDisabled.New()
   }
   ```
   Since `WithDisableFileWrites(true)` is never called, `ctx.disableFileWrites` is `false` (zero value).

7. **File write execution**: `sql/rowexec/rel.go:615-618`
   ```go
   file, fileErr := createIfNotExists(n.Outfile)
   // ... writes query results to the file
   ```

**Attacker-controlled inputs**:
- The file path in `INTO OUTFILE '/path'` -- fully controlled
- The data written -- from the SELECT query results
- The query itself -- fully user-controlled SQL string

**Authentication required**: Editor or Admin role (to create/edit dashboard panels)

### [TRACER] Evidence for H-02 -- 2026-03-21T10:15:00Z

**Verdict: PARTIAL -- Sanitization present on local path, unclear on remote path**

**Code path analysis**:

1. **Local readme path**: `api.ts:170-175`
   ```typescript
   async function getLocalPluginReadme(id: string): Promise<string> {
       const markdown = await getBackendSrv().get(`${API_ROOT}/${id}/markdown/README`);
       const markdownAsHtml = markdown ? renderMarkdown(markdown) : '';
       return markdownAsHtml;
   }
   ```
   `renderMarkdown` (from `@grafana/data`) calls `sanitizeTextPanelContent` which uses the `xss` library. This path IS sanitized.

2. **Remote readme path**: `api.ts:50`
   ```typescript
   readme: localReadme || remote?.readme,
   ```
   If `localReadme` is empty (plugin not installed locally), `remote?.readme` is used directly. The remote readme comes from GCOM API (`getRemotePlugin` at line 112). The GCOM API response's `readme` field is used AS-IS without sanitization.

3. **Rendering**: `PluginDetailsBody.tsx:57-59`
   ```typescript
   dangerouslySetInnerHTML={{
       __html: plugin.details?.readme ?? 'No plugin help or readme markdown file was found',
   }}
   ```
   No sanitization at the rendering layer.

4. **However**: The GCOM (grafana.com) API is Grafana-controlled infrastructure. Plugin submissions to grafana.com go through a review process. The readme content is server-side rendered markdown by GCOM, which likely sanitizes it.

**Trust boundary**: The trust boundary is between GCOM (Grafana-controlled) and the Grafana instance. If GCOM is compromised, or if a plugin author can inject unsanitized HTML through the GCOM API, XSS is possible.

### [TRACER] Evidence for H-03 -- 2026-03-21T10:20:00Z

**Verdict: REACHABLE -- but requires two non-default conditions**

1. **Default token**: `pkg/setting/setting.go:2070`
   ```go
   cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")
   ```
   Default is `"-"` -- a single ASCII character.

2. **JWT signing**: `pkg/services/rendering/auth.go:144-146`
   ```go
   func (j *jwtRenderKeyProvider) get(_ context.Context, opts AuthOpts) (string, error) {
       token := jwt.NewWithClaims(jwt.SigningMethodHS512, j.buildJWTClaims(opts))
       return token.SignedString(j.authToken)
   }
   ```
   The auth token `[]byte("-")` is used as HMAC-SHA512 key.

3. **JWT verification**: `auth.go:56-65`
   ```go
   func (rs *RenderingService) getRenderUserFromJWT(key string) *RenderUser {
       claims := new(renderJWT)
       tkn, err := jwt.ParseWithClaims(key, claims, func(_ *jwt.Token) (any, error) {
           return []byte(rs.Cfg.RendererAuthToken), nil
       }, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))
   ```

4. **Gating**: `auth.go:41`
   ```go
   if looksLikeJWT(key) && rs.features.IsEnabled(ctx, featuremgmt.FlagRenderAuthJWT) {
   ```
   Requires `renderAuthJWT` feature flag to be enabled.

**Pre-conditions**:
- `renderAuthJWT` feature flag must be enabled (not default)
- `renderer_token` must be at default value `"-"`

**Impact if exploitable**: An attacker who knows the default token can forge a JWT claiming any `OrgID`, `UserID`, and `OrgRole`, and use it to authenticate to any renderer endpoint.

### [TRACER] Evidence for H-04 -- 2026-03-21T10:25:00Z

**Verdict: PARTIAL -- Defense exists but is string-based**

1. **Symlink extraction**: `storage/fs.go:141-158`
   ```go
   func extractSymlink(basePath string, file *zip.File, filePath string) error {
       symlinkPath := strings.TrimSpace(buf.String())
       if !isSymlinkRelativeTo(basePath, symlinkPath, filePath) {
           return fmt.Errorf("symlink %q pointing outside plugin directory is not allowed", filePath)
       }
       if err = os.Symlink(symlinkPath, filePath); err != nil {
   ```

2. **Path validation**: `storage/fs.go:165-178`
   ```go
   func isSymlinkRelativeTo(basePath string, symlinkDestPath string, symlinkOrigPath string) bool {
       if filepath.IsAbs(symlinkDestPath) {
           return false  // absolute symlinks blocked
       }
       fileDir := filepath.Dir(symlinkOrigPath)
       cleanPath := filepath.Clean(filepath.Join(fileDir, symlinkDestPath))
       p, err := filepath.Rel(basePath, cleanPath)
       if err != nil {
           return false
       }
       if strings.HasPrefix(filepath.Clean(p), "..") {
           return false  // traversal blocked
       }
   ```

3. **Additional protection in localfiles.go**: `pkg/plugins/localfiles.go:41-52`
   ```go
   symlinkPath, err := filepath.EvalSymlinks(absolutePath)
   // ...
   p, err := filepath.Rel(basePath, symlinkPath)
   ```
   This second layer DOES use `EvalSymlinks` for runtime file access.

4. **Test coverage**: Extensive test cases in `fs_test.go` covering relative, absolute, and traversal symlinks.

**Assessment**: The extraction-time check (`isSymlinkRelativeTo`) operates on string paths before the symlink is created, so TOCTOU is not an issue. The check correctly uses `filepath.Clean` and `filepath.Rel` and checks for `..` prefix. While it does not call `EvalSymlinks` on `basePath`, the `basePath` is a temporary extraction directory controlled by Grafana, making it unlikely to contain symlink components. The runtime access layer in `localfiles.go` adds an additional `EvalSymlinks` check.

### [TRACER] Evidence for H-05 -- 2026-03-21T10:30:00Z

**Verdict: PARTIAL**

1. **Changelog path**: `api.ts:186-188`
   ```typescript
   const markdown: string = await getBackendSrv().get(`${API_ROOT}/${id}/markdown/CHANGELOG`);
   const markdownAsHtml = markdown ? renderMarkdown(markdown) : '';
   ```
   Local changelog is sanitized via `renderMarkdown` -> `sanitizeTextPanelContent`.

2. **Remote changelog**: `api.ts:54`
   ```typescript
   changelog: remote?.changelog || localChangelog,
   ```
   Remote changelog from GCOM is used directly if available. Then rendered in `Changelog.tsx:15`:
   ```typescript
   dangerouslySetInnerHTML={{ __html: sanitizedHTML ?? 'No changelog was found' }}
   ```
   The prop is named `sanitizedHTML` but no sanitization occurs in this component.

3. **statusContext path**: `PluginDetailsDeprecatedWarning.tsx:42-45`
   ```typescript
   dangerouslySetInnerHTML={{
       __html: renderMarkdown(plugin.details.statusContext),
   }}
   ```
   This IS sanitized via `renderMarkdown` which calls `sanitizeTextPanelContent`.

**Assessment**: Same pattern as H-02 -- remote content from GCOM may not be sanitized, but GCOM is Grafana-controlled infrastructure.

### [TRACER] Evidence for H-06 -- 2026-03-21T10:35:00Z

**Verdict: UNREACHABLE**

All queries in `database/database.go` use parameterized queries:
- `DELETE FROM dashboard_snapshot WHERE expires < ?` (line 36)
- `DELETE FROM dashboard_snapshot WHERE delete_key=?` (line 83)
- `sess.Get(&snapshot)` uses XORM which generates parameterized queries
- `sess.Insert(snapshot)` uses XORM

No string concatenation with user input found. Standard ORM usage throughout.

---

## Round 3 -- Challenge

### [ADVOCATE] Defense Brief for H-01 -- 2026-03-21T10:40:00Z

**Layer 1 -- Authentication/Authorization**: Requires Editor or Admin role. The SQL expression feature is used in dashboard panel queries, which require at minimum Editor permissions.

**Layer 2 -- Feature Toggle Gate**: The `sqlExpressions` feature toggle is at `PublicPreview` stage with `Expression: "false"`. It must be explicitly enabled by an administrator. However, Grafana Cloud and many self-hosted instances do enable preview features.

**Layer 3 -- Parser Allowlist**: The allowlist explicitly includes `*sqlparser.Into`. This is a configuration error, not a bypass.

**Layer 4 -- Engine-Level Protection**: `IsReadOnly: true` is set but the `Into.IsReadOnly()` method delegates to its child, effectively bypassing the read-only check. `WithDisableFileWrites(true)` is available but NOT used. `secure_file_priv` defaults to empty string (no restriction).

**Layer 5 -- OS-Level Protection**: The file write runs as the Grafana server process. The process user's filesystem permissions limit where files can be written. However, `/tmp/`, Grafana's own data directory, and potentially other writable locations are available.

**Blocking protections found**: NONE that prevent exploitation when the feature toggle is enabled.

**False Positive indicators**: NONE. The code paths are clear, the control failures are confirmed, and the commented-out code at `db.go:76-77` shows developer awareness but no fix.

**Conclusion**: No blocking protection found. The feature toggle is the only gate, and it is commonly enabled. When enabled, the attack is fully exploitable.

### [ADVOCATE] Defense Brief for H-02 -- 2026-03-21T10:45:00Z

**Layer 1 -- Data Source Trust**: The remote readme comes from GCOM (grafana.com API), which is Grafana-controlled infrastructure. Plugin submissions go through a review process.

**Layer 2 -- Local Sanitization**: Local plugin readmes ARE sanitized via `renderMarkdown` -> `sanitizeTextPanelContent` (uses the `xss` library).

**Layer 3 -- GCOM Server-Side Sanitization**: GCOM likely renders markdown server-side and sanitizes the output. This is an external system that we cannot verify from the codebase alone, but it is reasonable to assume GCOM sanitizes its outputs.

**Layer 4 -- CSP Headers**: Grafana may set Content-Security-Policy headers that mitigate XSS impact.

**Blocking protections found**: Local path is sanitized. Remote path relies on GCOM server-side sanitization (unverifiable from codebase). The `dangerouslySetInnerHTML` usage without client-side sanitization is a defense-in-depth gap.

**Conclusion**: The local readme path is safe. The remote readme path represents a supply-chain risk where the trust boundary is GCOM. This is a defense-in-depth issue -- the code SHOULD sanitize regardless of source. However, the immediate exploitability depends on GCOM's sanitization, which we cannot verify.

### [ADVOCATE] Defense Brief for H-03 -- 2026-03-21T10:50:00Z

**Layer 1 -- Feature Toggle**: Requires `renderAuthJWT` to be enabled (not default).

**Layer 2 -- Default Token Configuration**: The default `renderer_token` is `"-"`. Any production deployment that enables `renderAuthJWT` should configure a proper token. Using `"-"` with JWT auth would be a misconfiguration.

**Layer 3 -- Network Access**: The renderer authentication endpoint is typically not exposed to external networks. It is used for internal communication between Grafana and its rendering service.

**Layer 4 -- JWT Validation**: The JWT validation uses `jwt.SigningMethodHS512` with `jwt.WithValidMethods`, which is correct. The weakness is only in the key material.

**Blocking protections found**: Two non-default conditions required (feature flag + unchanged default token). The combination is a misconfiguration scenario rather than a vulnerability in default configuration.

**Conclusion**: This is a weak-default/misconfiguration issue rather than a vulnerability in the default attack surface. Severity should be calibrated to MEDIUM at most, given the double non-default requirement.

### [ADVOCATE] Defense Brief for H-04 -- 2026-03-21T10:55:00Z

**Layer 1 -- String-Based Validation**: `isSymlinkRelativeTo` correctly:
- Rejects absolute symlinks
- Uses `filepath.Clean` to normalize paths
- Uses `filepath.Rel` to compute relative path
- Checks for `..` prefix in the result

**Layer 2 -- Extraction Directory Control**: The `basePath` is a temporary directory created by Grafana's plugin installer, not user-controlled. The path components are unlikely to contain symlinks.

**Layer 3 -- Runtime EvalSymlinks**: `localfiles.go:41` uses `filepath.EvalSymlinks` for actual file access, providing a second layer of defense.

**Layer 4 -- Test Coverage**: Extensive test cases cover edge cases including `../../`, `../..`, both file and directory symlinks.

**Blocking protections found**: Multiple layers of defense. The missing `EvalSymlinks` in `isSymlinkRelativeTo` is mitigated by the controlled basePath and the runtime EvalSymlinks check.

**Conclusion**: The theoretical bypass via basePath containing symlinks is not practical because the basePath is controlled by Grafana. FALSE POSITIVE.

### [ADVOCATE] Defense Brief for H-05 -- 2026-03-21T10:58:00Z

**Same analysis as H-02**: Remote content from GCOM relies on GCOM's sanitization. `statusContext` IS sanitized via `renderMarkdown`. Local changelog IS sanitized. Remote changelog may not be sanitized client-side but relies on GCOM.

**Conclusion**: DUPLICATE of H-02's pattern. Same defense-in-depth gap.

---

## Round 4 -- Synthesis

### [SYNTHESIZER] Verdict for H-01 -- 2026-03-21T11:00:00Z

**Prosecution summary**: 4 confirmed control failures create a complete attack chain: (1) `*sqlparser.Into` on allowlist, (2) `WithDisableFileWrites(true)` not called, (3) `Into.IsReadOnly()` delegates to child SELECT so bypasses engine read-only check, (4) `secure_file_priv` defaults to empty string. An Editor-role user with the `sqlExpressions` feature enabled can write arbitrary files to the Grafana server's filesystem.

**Defense summary**: The `sqlExpressions` feature toggle must be explicitly enabled (PublicPreview stage). Authentication requires Editor/Admin role. OS-level filesystem permissions apply.

**Pre-FP Gate**:
- Attacker control verified by Tracer? YES -- file path and query content fully controlled
- Framework protection searched by Advocate (all 5 layers)? YES -- no blocking protection found
- Trust boundary crossing confirmed? YES -- user-controlled SQL input crosses into filesystem write
- Exploitation requires normal attacker position (not admin)? YES -- Editor role, which is a normal position for dashboard authors
- Vulnerable code ships to production? YES -- the feature is in PublicPreview and the code is in production

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: CRITICAL**
**Rationale**: When the sqlExpressions feature toggle is enabled, an Editor-role user can write arbitrary files to the server filesystem via SELECT INTO OUTFILE, bypassing all 4 layers of defense (allowlist, IsReadOnly, DisableFileWrites, secure_file_priv). This is a remotely triggerable arbitrary file write with no significant preconditions beyond a commonly-enabled feature flag. Severity is CRITICAL because it enables RCE chains (cron, SSH keys, web shells) from a standard authenticated position.

**Finding draft written to**: security/findings-draft/p8-040-sql-expr-into-outfile-arb-write.md
**Registry updated**: AP-040 SQL Expression INTO OUTFILE Arbitrary File Write

### [SYNTHESIZER] Verdict for H-02 -- 2026-03-21T11:05:00Z

**Prosecution summary**: `PluginDetailsBody.tsx` renders `plugin.details?.readme` via `dangerouslySetInnerHTML` without client-side sanitization. When the readme comes from the remote GCOM API (for plugins not installed locally), unsanitized HTML could be injected.

**Defense summary**: Local readme is sanitized via `renderMarkdown`. Remote readme relies on GCOM's server-side sanitization. GCOM is Grafana-controlled infrastructure with plugin review processes. The trust boundary is between GCOM and the Grafana instance.

**Pre-FP Gate**:
- Attacker control verified? PARTIAL -- attacker must submit a malicious plugin to GCOM and bypass review
- Framework protection searched? YES -- local path sanitized, remote path relies on external system
- Trust boundary crossing? YES -- external API data rendered without sanitization
- Normal attacker position? NO -- requires GCOM supply chain compromise or review bypass
- Vulnerable code ships to production? YES

**Pre-FP Gate**: failed on check-4: requires supply chain compromise of GCOM, not normal attacker position

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: The missing client-side sanitization on plugin readme content from GCOM is a defense-in-depth gap. While GCOM likely sanitizes content, the code violates the principle of never trusting external data. A GCOM compromise or review bypass could lead to stored XSS against all Grafana instances browsing the catalog. Downgraded from HIGH to MEDIUM because exploitation requires GCOM supply chain compromise.

**Finding draft written to**: security/findings-draft/p8-041-plugin-readme-xss-no-sanitize.md
**Registry updated**: AP-041 dangerouslySetInnerHTML without DOMPurify

### [SYNTHESIZER] Verdict for H-03 -- 2026-03-21T11:10:00Z

**Prosecution summary**: Default `renderer_token` is `"-"` (single byte). When `renderAuthJWT` is enabled, this token is used as HMAC-SHA512 key, allowing trivial JWT forgery.

**Defense summary**: Requires two non-default conditions: (1) `renderAuthJWT` feature flag enabled, (2) `renderer_token` unchanged from default. Network access to renderer typically internal-only.

**Pre-FP Gate**:
- Attacker control verified? YES -- can craft JWT with known key
- Framework protection searched? YES -- feature flag + default config are the only gates
- Trust boundary crossing? YES -- forged identity
- Normal attacker position? NO -- requires non-default feature flag AND default token (contradictory deployment practice)
- Vulnerable code ships to production? YES

**Pre-FP Gate**: failed on check-4: requires contradictory non-default config (enabling JWT auth but not changing the signing key)

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: The default renderer auth token of "-" is a weak default that enables JWT forgery when the renderAuthJWT feature flag is enabled. While requiring two non-default conditions, the weak default is a security design flaw. Severity is MEDIUM because exploitation requires a specific misconfiguration pattern.

**Finding draft written to**: security/findings-draft/p8-042-renderer-jwt-weak-default-token.md
**Registry updated**: AP-042 Weak Default Signing Key

### [SYNTHESIZER] Verdict for H-04 -- 2026-03-21T11:15:00Z

**Prosecution summary**: `isSymlinkRelativeTo` does not call `os.EvalSymlinks` on `basePath`, theoretically allowing bypass if basePath contains symlink components.

**Defense summary**: basePath is a temporary extraction directory controlled by Grafana. Runtime file access uses `EvalSymlinks`. Extensive test coverage. Multiple defense layers.

**Pre-FP Gate**: failed on check-3: no trust boundary crossing -- basePath is server-controlled

**Verdict: FALSE POSITIVE**
**Severity: --**
**Rationale**: The basePath is a Grafana-controlled temporary directory, making symlink injection into the basePath impractical. The runtime EvalSymlinks check provides additional defense. No realistic attack path exists.

**Finding draft written to**: --
**Registry updated**: no new pattern

### [SYNTHESIZER] Verdict for H-05 -- 2026-03-21T11:18:00Z

**Prosecution summary**: Remote changelog from GCOM rendered without client-side sanitization, same pattern as H-02.

**Defense summary**: Same as H-02 -- relies on GCOM server-side sanitization.

**Pre-FP Gate**: all checks same as H-02

**Verdict: DUPLICATE**
**Severity: --**
**Rationale**: Same vulnerability pattern as H-02 (dangerouslySetInnerHTML with unsanitized remote content). Covered by p8-041 finding.

**Finding draft written to**: --
**Registry updated**: no new pattern (covered by AP-041)

### [SYNTHESIZER] Verdict for H-06 -- 2026-03-21T11:20:00Z

**Prosecution summary**: Potential SQL injection in dashboard snapshot database layer.

**Defense summary**: All queries use parameterized queries via XORM and `?` placeholders. No string concatenation with user input.

**Pre-FP Gate**: failed on check-1: no attacker control -- all queries parameterized

**Verdict: DROP**
**Severity: --**
**Rationale**: All database queries in the dashboard snapshot store use parameterized queries. No SQL injection vector exists.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-01 SQL INTO OUTFILE | VALID | CRITICAL | p8-040-sql-expr-into-outfile-arb-write.md |
| H-02 Plugin Readme XSS | VALID | MEDIUM | p8-041-plugin-readme-xss-no-sanitize.md |
| H-03 Renderer JWT Weak Default | VALID | MEDIUM | p8-042-renderer-jwt-weak-default-token.md |
| H-04 Plugin Symlink Traversal | FALSE POSITIVE | -- | -- |
| H-05 Changelog/StatusContext XSS | DUPLICATE | -- | -- |
| H-06 K8s Snapshot SQLi | DROP | -- | -- |

Findings written: 3
Patterns added to registry: 3
Variant candidates: 0

Chamber closed: 2026-03-21T11:25:00Z
