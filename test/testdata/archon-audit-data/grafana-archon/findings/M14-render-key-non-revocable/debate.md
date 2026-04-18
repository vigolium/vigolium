# Review Chamber: chamber-3

Cluster: Authentication & Plugin Security
DFD Slices: DFD-5 (Plugin Loading), DFD-6 (Alerting Notification), DFD-7 (Authentication), DFD-9 (Rendering Auth)
NNN Range: p8-040 to p8-059
Started: 2026-04-11T10:00:00Z
Status: CLOSED

---

## Pre-Seeded Hypotheses from Deep Probes

The following hypotheses were validated by Deep Probe teams 05 (Authentication + Rendering Auth) and 06 (Plugin + Alerting) and are pre-seeded into this chamber. The Ideator should build on these rather than re-generate them. The Tracer should verify and extend the existing evidence.

### H-00a (from PH-02): Proxy Auth Empty IP Allowlist — Full Authentication Bypass
- **Probe severity**: CRITICAL (conditional)
- **Target**: `pkg/services/authn/clients/proxy.go:200` — `isAllowedIP()`
- **Pre-traced path**: `Proxy.Test()` -> header present -> `Proxy.Authenticate()` -> `isAllowedIP()` -> `len(c.acceptedIPs) == 0 -> return true` -> full auth bypass
- **Condition**: `auth_proxy.enabled=true` AND `auth_proxy.whitelist` is empty string (default when proxy auth is first enabled)

### H-00b (from PH-14): EnableUserHook Unconditionally Re-enables LDAP Users
- **Probe severity**: HIGH
- **Target**: `pkg/services/authn/authnimpl/sync/user_sync.go:421-441`
- **Pre-traced path**: LDAP login -> `EnableUser: true` -> `EnableUserHook` (priority 20) -> `userService.Update(IsDisabled: false)` — no admin-disable check

### H-00c (from PH-19/PH-06): ExtendedJWT Empty AllowedAudiences + TypeRenderService Escalation
- **Probe severity**: HIGH
- **Target**: `pkg/services/authn/clients/ext_jwt.go:60,147-192`
- **Pre-traced path**: ID token with `sub=render:<anything>` + empty AllowedAudiences -> Admin role without renderer active

### H-00d (from PH-09/PH-04): JWT Render Keys Not Revocable + Priority Shadowing
- **Probe severity**: HIGH
- **Target**: `pkg/services/rendering/auth.go:141-143`, `pkg/services/authn/clients/render.go:36-67`
- **Pre-traced path**: Leaked JWT render key persists until expiry, priority 10 shadows session auth

### H-00e (from PH-01): OrgID Context Injection Before Auth
- **Probe severity**: HIGH
- **Target**: `pkg/services/authn/authnimpl/service.go:488-508`
- **Pre-traced path**: `?targetOrgId=<victim>` or `X-Grafana-Org-Id` -> org context set before membership check

### H-00f (from PH-11): OAuth allow_insecure_email_lookup Account Takeover
- **Probe severity**: HIGH
- **Target**: `pkg/services/authn/clients/oauth.go:206-210`
- **Pre-traced path**: When enabled, email-only lookup enables account takeover from any configured OAuth provider

### H-00g (from PH-04/PH-CV-03): Receiver Secrets Exposed via V1-Hardcoded Schema
- **Probe severity**: MEDIUM
- **Target**: `pkg/services/ngalert/notifier/crypto.go:88`
- **Pre-traced path**: V1 schema secret paths -> V2+ secrets left unencrypted in Settings JSON -> FilterRead only suppresses SecureSettings

### H-00h (from PH-05/PH-CV-08): CDN Plugin Bypasses Angular Detection and ModuleJS Validation
- **Probe severity**: MEDIUM
- **Target**: `pkg/plugins/manager/pipeline/validation/steps.go:59,100`
- **Pre-traced path**: CDN plugin -> ModuleJSValidator/AngularDetector skip -> XSS in Grafana origin

### H-00i (from PH-15/PH-CV-06): OAuth Token Forwarding to Plugin Backends
- **Probe severity**: MEDIUM
- **Target**: `pkg/services/pluginsintegration/clientmiddleware/oauthtoken_middleware.go:52`
- **Pre-traced path**: oauthPassThru=true + malicious plugin backend -> token exfiltration

### H-00j (from F-009/PH-09): Render Key JWT Auth Path Analysis
- **Probe severity**: HIGH (SAST F-009)
- **Target**: `pkg/services/rendering/auth.go:151`
- **Pre-traced path**: render_key cookie -> jwt.ParseWithClaims without RendererServerUrl check

### H-00k (from F-006): Plugin ZIP Symlink Traversal
- **Probe severity**: HIGH (SAST F-006)
- **Target**: `pkg/plugins/storage/fs.go:99`
- **Pre-traced path**: Plugin archive with symlink -> extraction outside plugin directory

---

## Round 1 -- Ideation

### [SYNTHESIZER] Hypothesis Selection and Prioritization

Given the extensive Deep Probe pre-validation (11 hypotheses pre-seeded), the Ideator is directed to:
1. Confirm the top 7 hypotheses by impact
2. Note any novel attack patterns not covered by pre-seeded items
3. Merge overlapping hypotheses (H-00d + H-00j are the same render key issue; H-00e folds into H-00c)

**Selected Hypotheses for Tracing (ranked by impact):**

### H-01: Auth Proxy Empty IP Allowlist — Full Authentication Bypass
- **Source**: PH-02 (Deep Probe 05)
- **Severity estimate**: CRITICAL
- **Target**: `pkg/services/authn/clients/proxy.go:200`
- **Attack**: When `auth_proxy.enabled=true` and whitelist is empty (default for new proxy setups), any IP can authenticate as any user by setting the proxy header (e.g., `X-WEBAUTH-USER: admin`)
- **Condition**: Requires auth_proxy to be explicitly enabled (non-default global config)

### H-02: ExtendedJWT Empty AllowedAudiences — Cross-Service Identity Spoofing
- **Source**: PH-19 + PH-06 (Deep Probe 05)
- **Severity estimate**: HIGH
- **Target**: `pkg/services/authn/clients/ext_jwt.go:60,147-192`
- **Attack**: ID token verifier has no audience check. In shared-JWKS deployments, any service's ID token with `sub=render:<anything>` grants Admin role. Combined with OrgID injection (PH-01) for cross-org escalation.
- **Condition**: Requires `ExtJWTAuth.Enabled=true` and shared JWKS endpoint

### H-03: EnableUserHook Unconditionally Re-enables Admin-Disabled LDAP Users
- **Source**: PH-14 (Deep Probe 05)
- **Severity estimate**: HIGH
- **Target**: `pkg/services/authn/authnimpl/sync/user_sync.go:421-441`
- **Attack**: Admin disables LDAP user during incident response. Next LDAP login attempt silently re-enables the account in DB before any other validation, undermining admin's ability to revoke access.

### H-04: OAuth allow_insecure_email_lookup Account Takeover
- **Source**: PH-11 (Deep Probe 05)
- **Severity estimate**: HIGH
- **Target**: `pkg/services/authn/clients/oauth.go:206-210`
- **Attack**: When `oauth_allow_insecure_email_lookup=true`, attacker-controlled OAuth provider presents victim's email -> account takeover via email-only user lookup.
- **Condition**: Requires non-default setting to be enabled

### H-05: JWT Render Key Non-Revocable + Priority Shadowing Session Auth
- **Source**: PH-09 + PH-04 (Deep Probe 05), F-009 (SAST)
- **Severity estimate**: HIGH
- **Target**: `pkg/services/rendering/auth.go:141-143`, `pkg/services/authn/clients/render.go:36-67`
- **Attack**: Leaked JWT render key persists until JWT expiry (no revocation). Render client at priority 10 shadows user session at priority 60. Grants Admin role in org.
- **Condition**: Requires render key leakage (log exposure, XSS, network sniff)

### H-06: Plugin ZIP Symlink Traversal — File System Escape
- **Source**: F-006 (SAST enriched)
- **Severity estimate**: HIGH
- **Target**: `pkg/plugins/storage/fs.go:99`
- **Attack**: Plugin admin uploads ZIP archive containing symlinks. Symlink targets are resolved at use time, not extraction time, enabling read/write outside plugin directory.
- **Condition**: Requires plugin admin privilege

### H-07: Receiver Integration Secrets Exposed via V1-Hardcoded Schema
- **Source**: PH-04/PH-CV-03 (Deep Probe 06)
- **Severity estimate**: MEDIUM
- **Target**: `pkg/services/ngalert/notifier/crypto.go:88`
- **Attack**: V1 schema secret field list is incomplete for integrations that added secrets in V2+. FilterRead suppresses SecureSettings but not the Settings JSON blob, leaving plaintext secrets visible to Viewers.

---

### Deferred Hypotheses (covered in findings from other chambers or lower priority)

- **H-00e (OrgID injection)**: Structural prerequisite for cross-org attacks; impact realized through H-02 and other IDOR patterns (Chamber 1 scope)
- **H-00h (CDN plugin validation bypass)**: MEDIUM; requires CDN compromise or self-hosted HTTP CDN — lower immediate impact
- **H-00i (OAuth token forwarding)**: MEDIUM; requires admin to enable oauthPassThru + compromised plugin — covered by datasource proxy chamber scope
- **H-00j (render key JWT path)**: Merged into H-05

## Round 2 -- Tracing

### [TRACER] Evidence for H-01: Auth Proxy Empty IP Allowlist

**Status**: REACHABLE
**Code path confirmed**:
1. `proxy.go:200` — `isAllowedIP()`: `if len(c.acceptedIPs) == 0 { return true }` — confirmed at line 201
2. `proxy.go:76-113` — `Authenticate()`: calls `isAllowedIP(r)` first, then reads header via `getProxyHeader()`
3. `conf/defaults.ini:978` — `whitelist =` (empty by default under `[auth.proxy]`)
4. `proxy.go:220-224` — `parseAcceptList()`: `if len(strings.TrimSpace(s)) == 0 { return nil, nil }` — empty string yields nil slice
5. Full flow: HTTP request with `X-WEBAUTH-USER: admin` -> `Proxy.Test()` (header present) -> `Proxy.Authenticate()` -> `isAllowedIP()` returns true (empty list) -> identity created for `admin`
**Attacker control**: Full control over username via HTTP header from any IP
**Precondition**: `auth_proxy.enabled=true` (non-default; `enabled = false` in defaults.ini:973)

### [TRACER] Evidence for H-02: ExtendedJWT Empty AllowedAudiences

**Status**: REACHABLE
**Code path confirmed**:
1. `ext_jwt.go:58-60` — Comment: "For ID tokens, we explicitly do not validate audience, hence an empty AllowedAudiences". `idTokenVerifier := authlib.NewIDTokenVerifier(authlib.VerifierConfig{}, keys)` — empty VerifierConfig means no audience check
2. `ext_jwt.go:147` — `TypeRenderService` accepted: `if !claims.IsIdentityType(t, claims.TypeUser, claims.TypeServiceAccount, claims.TypeRenderService, claims.TypeAnonymous)`
3. `ext_jwt.go:184-190` — TypeRenderService grants Admin: `identity.OrgRoles = map[int64]org.RoleType{s.cfg.DefaultOrgID(): org.RoleAdmin}` with no check that rendering service is actually running
4. Namespace cross-check exists (must match between access token and ID token), providing some protection
**Attacker control**: Requires a valid JWT signed by the JWKS key with correct namespace claim
**Precondition**: `ExtJWTAuth.Enabled=true` + shared JWKS endpoint between services

### [TRACER] Evidence for H-03: EnableUserHook Re-enables Disabled Users

**Status**: REACHABLE
**Code path confirmed**:
1. `user_sync.go:421-441` — `EnableUserHook()`: checks `id.ClientParams.EnableUser` (set by LDAP client), then unconditionally calls `userService.Update(ctx, &user.UpdateUserCommand{UserID: userID, IsDisabled: &isDisabled})` where `isDisabled = false`
2. No check for admin-imposed disable vs. sync-imposed disable — DB has single `is_disabled bool` column
3. Hook runs at priority 20 (before ValidateUserProvisioningHook at priority 30)
4. The DB write executes regardless of whether the login ultimately succeeds or fails
**Attacker control**: Any LDAP user whose account was disabled by admin can trigger re-enable by attempting login
**Precondition**: LDAP auth must be configured

### [TRACER] Evidence for H-04: OAuth Insecure Email Lookup

**Status**: REACHABLE
**Code path confirmed**:
1. `oauth.go:207` — `allowInsecureEmailLookup := c.settingsProviderSvc.KeyValue("auth", "oauth_allow_insecure_email_lookup").MustBool(false)`
2. `oauth.go:208-210` — When true: `lookupParams.Email = &userInfo.Email` — only email used for user matching
3. No AuthID/sub check when this setting is enabled — attacker OAuth provider presents victim email -> matched to existing account
**Attacker control**: Full control over email claim via attacker-controlled OAuth IdP
**Precondition**: `oauth_allow_insecure_email_lookup=true` (non-default)

### [TRACER] Evidence for H-05: JWT Render Key Non-Revocable

**Status**: REACHABLE
**Code path confirmed**:
1. `auth.go:141-143` — `jwtRenderKeyProvider.afterRequest()`: empty function, comment "do nothing - the JWT will just expire"
2. `auth.go:145-161` — `validate()`: parses JWT with HS512, checks signature against `j.authToken` (server secret), returns RenderUser with OrgID/OrgRole
3. `auth.go:33-37` — `GetRenderUser()`: nil check on `perRequestRenderKeyProvider` (added by commit 85c811ef4b8) prevents use when renderer not configured — this IS a mitigation
4. `render.go:36-67` — `Render.Authenticate()`: creates identity with `OrgRoles: map[int64]org.RoleType{renderUsr.OrgID: org.RoleType(renderUsr.OrgRole)}` — can be Admin
5. Priority 10 registration means render auth is checked before session auth (priority 60)
**Attacker control**: Requires obtaining a valid JWT render key (e.g., from logs, XSS, network sniff)
**Mitigation found**: `perRequestRenderKeyProvider == nil` check at auth.go:34 prevents exploitation when renderer is not configured

### [TRACER] Evidence for H-06: Plugin ZIP Symlink Traversal

**Status**: PARTIAL (mitigation found)
**Code path**:
1. `fs.go:121-127` — Symlinks ARE processed: `if isSymlink(zf) { if err := extractSymlink(installDir, zf, dstPath); err != nil { ... continue } }`
2. `fs.go:141-161` — `extractSymlink()` reads symlink target, then calls `isSymlinkRelativeTo(basePath, symlinkPath, filePath)`
3. `fs.go:165-181` — `isSymlinkRelativeTo()`: checks `filepath.IsAbs(symlinkDestPath)` returns false for absolute targets; then resolves `filepath.Clean(filepath.Join(fileDir, symlinkDestPath))` and checks `filepath.Rel(basePath, cleanPath)` doesn't start with `..`
4. **Mitigation present**: The `isSymlinkRelativeTo` function appears to correctly validate symlink targets. Absolute paths rejected, relative paths resolved against the symlink's directory and checked against basePath.
**Potential bypass**: TOCTOU — validation occurs at extraction time, but filesystem state could change between validation and use. However, this requires concurrent write access to the plugin directory, which is a very narrow attack window. The CodeQL finding was for `go/unsafe-unzip-symlink` which may not account for the custom validation function.
**Attacker control**: Plugin admin controls archive contents

### [TRACER] Evidence for H-07: Receiver Secrets V1 Schema Exposure

**Status**: REACHABLE
**Code path confirmed**:
1. `crypto.go:88` — `alertingNotify.GetSchemaVersionForIntegration(schema.IntegrationType(gr.Type), schema.V1)` — hardcoded V1 schema
2. `crypto.go:92` — `secretPaths := typeSchema.GetSecretFieldsPaths()` — only V1 secret field paths returned
3. `crypto.go:100-108` — Only V1 secrets are detected and moved from Settings to SecureSettings
4. V2+ secrets remain as plaintext in the `Settings` JSON blob
5. `receiver_svc.go:231-235` — `FilterRead`/`FilterReadDecrypted` operate on `SecureSettings` map, not the `Settings` JSON
6. Access path: `GET /api/v1/provisioning/contact-points` requires `ActionAlertingNotificationsRead` (Viewer-accessible)
**Attacker control**: Any Viewer can read the Settings JSON containing plaintext V2+ secrets
**Precondition**: Integration must have secrets added in V2+ schema that were not in V1

---

## Round 3 -- Challenge

### [ADVOCATE] Defense Brief for H-01

**Protection search (5 layers)**:
1. **Framework auth middleware**: N/A — auth proxy IS the authentication layer
2. **Configuration gate**: `auth_proxy.enabled = false` by default in `conf/defaults.ini:973`. Must be explicitly enabled.
3. **Network architecture**: In typical deployments, auth proxy is used behind a reverse proxy that sets the header. Direct internet exposure would be a deployment misconfiguration.
4. **Documentation**: Grafana documentation warns about configuring IP allowlist when using auth proxy
5. **Header stripping**: No automatic stripping of proxy headers when auth_proxy is disabled

**Defense assessment**: The `enabled = false` default is a significant mitigating factor. However, when enabled, the empty whitelist default creates an insecure-by-default configuration for the auth proxy feature itself. This matches a known anti-pattern: opt-in feature with insecure defaults within that feature. The vulnerability is real for any deployment that enables auth_proxy without configuring a whitelist.

**FP check**: NOT a false positive. The code path is confirmed. The insecure default within the feature is a genuine design flaw.

### [ADVOCATE] Defense Brief for H-02

**Protection search (5 layers)**:
1. **Access token audience check**: The access token verifier DOES check audience (`cfg.ExtJWTAuth.Audiences`). Only the ID token verifier skips audience.
2. **Namespace cross-check**: ID token namespace must match access token namespace. This limits exploitation to services in the same namespace/stack.
3. **JWKS key isolation**: If each service has its own signing key, cross-service token reuse is impossible.
4. **Feature gate**: `ExtJWTAuth.Enabled` defaults to false.
5. **Comment awareness**: Code comment at line 58 explicitly acknowledges the audience skip as intentional design.

**Defense assessment**: The namespace check significantly limits the attack surface. However, in Grafana Cloud or shared-infrastructure deployments where multiple services share a JWKS endpoint and namespace, the audience skip on ID tokens allows cross-service identity spoofing. The TypeRenderService escalation to Admin is particularly dangerous.

**FP check**: NOT a false positive, but severity is conditional on deployment architecture.

### [ADVOCATE] Defense Brief for H-03

**Protection search (5 layers)**:
1. **LDAP sync design**: EnableUser is intentionally designed to re-enable users found in LDAP — this is the sync mechanism.
2. **Alternative disable path**: Admin could disable the user in LDAP directory instead of Grafana.
3. **Audit logging**: User state changes may be logged (not verified).
4. **No `ManuallyDisabled` flag**: The DB schema does not distinguish admin-imposed from sync-imposed disable.
5. **Hook priority**: EnableUserHook at priority 20 runs before other validation hooks.

**Defense assessment**: This is a genuine design gap. The intended behavior (re-enable users found in LDAP) conflicts with the admin's expectation that disabling a user in Grafana is effective. During incident response, an admin needs to immediately revoke access; directing them to the LDAP directory is not always feasible (different team, different system). The DB write persisting even on failed login attempts makes this worse.

**FP check**: NOT a false positive. Confirmed security design flaw.

### [ADVOCATE] Defense Brief for H-04

**Protection search (5 layers)**:
1. **Default setting**: `oauth_allow_insecure_email_lookup` defaults to `false`. Setting name explicitly contains "insecure".
2. **Configuration warning**: The setting name itself warns administrators of the risk.
3. **OAuth provider trust**: Exploitation requires a configured OAuth provider controlled by the attacker, or an OAuth provider that allows arbitrary email claims.
4. **Email domain restriction**: `IsEmailAllowed()` at oauth.go:202 may restrict allowed email domains.
5. **AuthID match**: When the setting is false (default), AuthID/sub is used for matching, preventing this attack.

**Defense assessment**: The non-default configuration and explicit "insecure" naming are strong mitigating factors. However, the setting exists because some deployments need it (migration scenarios, multiple IdPs). For those deployments, this is a complete account takeover path. The "insecure" name is a documentation defense, not a code defense.

**FP check**: NOT a false positive, but severity should account for the non-default, explicitly-warned configuration.

### [ADVOCATE] Defense Brief for H-05

**Protection search (5 layers)**:
1. **Nil check gate**: `auth.go:34` — `if rs.perRequestRenderKeyProvider == nil { return nil, false }` — rejects render keys when renderer not configured.
2. **JWT signature validation**: Render key JWT is signed with HS512 using the server's `auth_token` secret. Forging requires knowing the secret.
3. **Key leakage prerequisite**: Exploitation requires obtaining a valid render key during its lifetime.
4. **JWT expiry**: Keys have a configured expiry time (`j.keyExpiry`).
5. **Network isolation**: Render keys are typically exchanged over localhost between Grafana and the renderer.

**Defense assessment**: The nil check (commit 85c811ef4b8) significantly mitigates this — render key auth is disabled when no renderer is configured. For deployments WITH a renderer, the non-revocable nature of JWT keys is a genuine design weakness, but exploitation requires key leakage which is itself a separate vulnerability. The priority 10 shadowing is by design (renderer must authenticate before session checks).

**FP check**: The non-revocability is a design limitation, not a vulnerability per se. However, combined with key leakage, it enables persistent unauthorized access. MEDIUM-severity design weakness rather than HIGH vulnerability.

### [ADVOCATE] Defense Brief for H-06

**Protection search (5 layers)**:
1. **`isSymlinkRelativeTo()` validation**: fs.go:165-181 — validates symlink targets are relative and resolve within basePath. Checks: absolute path rejection, filepath.Clean, filepath.Rel prefix check.
2. **ZipSlip check**: fs.go:91-97 — separate check for directory traversal in file names.
3. **Plugin admin privilege**: Requires plugin admin role to upload archives.
4. **Plugin signature verification**: Plugins must pass signature verification (separate from extraction).
5. **Warn-and-skip**: fs.go:123-124 — if symlink extraction fails, it logs warning and continues (does not extract the malicious symlink).

**Defense assessment**: The `isSymlinkRelativeTo` function appears to be a sound defense. It correctly handles: absolute targets (rejected), relative traversal (resolved and checked against basePath), and uses `filepath.Clean` for normalization. The CodeQL `go/unsafe-unzip-symlink` rule may have fired on the structural pattern (symlinks extracted from archives) without recognizing the custom validation function. This is likely a **FALSE POSITIVE** for the CodeQL rule.

**FP check**: LIKELY FALSE POSITIVE. The custom symlink validation function addresses the vulnerability class. Would need to find a specific bypass of `isSymlinkRelativeTo` to confirm a true positive.

### [ADVOCATE] Defense Brief for H-07

**Protection search (5 layers)**:
1. **Schema versioning intent**: The V1 hardcoding appears intentional — it handles legacy integrations.
2. **FilterRead suppression**: `FilterRead` suppresses `SecureSettings` but not `Settings` JSON body.
3. **Access control**: Viewer-accessible endpoint (`ActionAlertingNotificationsRead`).
4. **Historical pattern**: CVE-2024-11741 (VictorOps token exposure) and CVE-2025-3415 (DingDing token) are exactly this bug class.
5. **Schema evolution**: New secret fields in V2+ schema are not recognized by V1 `GetSecretFieldsPaths()`.

**Defense assessment**: This is a confirmed vulnerability class with two prior CVEs in the same component. The V1 hardcoding creates a systematic gap where any integration that adds a secret field in a schema version after V1 will have that secret exposed as plaintext in the Settings JSON. The FilterRead/FilterReadDecrypted functions cannot catch this because the secrets never make it to SecureSettings. This is a genuine MEDIUM-severity finding.

**FP check**: NOT a false positive. Confirmed pattern recurrence from CVE-2024-11741 and CVE-2025-3415.

---

## Round 4 -- Synthesis

### [SYNTHESIZER] Verdict for H-01 -- 2026-04-11T11:00:00Z

**Prosecution summary**: Code at proxy.go:200-202 confirms `isAllowedIP()` returns true when `acceptedIPs` is empty. Empty whitelist is the default under `[auth.proxy]`. Any IP can authenticate as any user via the proxy header. Full authentication bypass.

**Defense summary**: `auth_proxy.enabled = false` by default. Feature must be explicitly enabled. Typical deployments use this behind a reverse proxy. The empty whitelist is insecure-by-default within the feature but the feature itself is opt-in.

**Pre-FP Gate**: all checks passed (attacker control: HTTP header; framework protection: none within enabled feature; trust boundary: unauthenticated -> full auth; normal attacker position: yes; ships to production: yes)

**Verdict: VALID**
**Severity: HIGH** (downgraded from CRITICAL: requires non-default `auth_proxy.enabled=true` configuration; when enabled, it IS critical, but the non-default prerequisite reduces the population of affected deployments)
**Rationale**: Confirmed insecure-by-default IP allowlist behavior within the auth proxy feature — when enabled, empty whitelist (default) allows any IP to impersonate any user, but requires explicit opt-in to enable auth proxy.

**Finding draft written to**: archon/findings-draft/p8-040-proxy-auth-empty-allowlist.md
**Registry updated**: AP-040 Auth Proxy Empty Allowlist

---

### [SYNTHESIZER] Verdict for H-02 -- 2026-04-11T11:01:00Z

**Prosecution summary**: ext_jwt.go:58-60 explicitly skips audience validation on ID tokens. Combined with TypeRenderService at lines 184-190, a cross-service ID token grants Admin role. Code comment acknowledges the design choice.

**Defense summary**: Access token audience IS checked. Namespace cross-check limits scope. ExtJWTAuth defaults to disabled. In deployments with isolated JWKS keys, this is unexploitable.

**Pre-FP Gate**: all checks passed (attacker control: JWT claims from shared JWKS; framework protection: namespace check is partial; trust boundary: cross-service -> admin; normal attacker position: yes for shared-infrastructure attacker; ships to production: yes)

**Verdict: VALID**
**Severity: HIGH** (conditional on shared JWKS deployment; when conditions met, grants Admin escalation)
**Rationale**: ID token audience check intentionally omitted (ext_jwt.go:58 comment), enabling cross-service identity spoofing with TypeRenderService escalation to Admin in shared-JWKS deployments, despite namespace cross-check mitigation.

**Finding draft written to**: archon/findings-draft/p8-041-extjwt-empty-audience.md
**Registry updated**: AP-041 JWT Audience Skip

---

### [SYNTHESIZER] Verdict for H-03 -- 2026-04-11T11:02:00Z

**Prosecution summary**: user_sync.go:421-441 unconditionally sets `is_disabled=false` when EnableUser flag is set by LDAP client. No distinction between admin-imposed and sync-imposed disable. DB write persists even on failed login.

**Defense summary**: Re-enable is the intended LDAP sync behavior. Admin can disable in LDAP directory instead. However, no ManuallyDisabled flag exists, and the DB write on failed login is clearly unintended.

**Pre-FP Gate**: all checks passed (attacker control: LDAP login attempt; framework protection: none — no admin-disable flag; trust boundary: disabled-user -> enabled-user; normal attacker position: any LDAP user; ships to production: yes)

**Verdict: VALID**
**Severity: MEDIUM** (downgraded from HIGH: requires LDAP configuration; the attacker must still have valid LDAP credentials to trigger the path; the re-enable only matters if admin specifically disabled the user)
**Rationale**: EnableUserHook unconditionally re-enables admin-disabled LDAP users on login attempt with no mechanism to distinguish admin-imposed disable from sync-imposed disable, undermining incident response access revocation.

**Finding draft written to**: archon/findings-draft/p8-042-ldap-enable-hook-bypass.md
**Registry updated**: AP-042 LDAP Enable Hook Admin Bypass

---

### [SYNTHESIZER] Verdict for H-04 -- 2026-04-11T11:03:00Z

**Prosecution summary**: oauth.go:207-210 confirms email-only lookup when `oauth_allow_insecure_email_lookup=true`. Complete account takeover via email claim from any configured OAuth provider.

**Defense summary**: Setting defaults to false. Name explicitly contains "insecure". Email domain restrictions via `IsEmailAllowed()` provide partial mitigation. Exploitation requires attacker-controlled OAuth provider.

**Pre-FP Gate**: all checks passed (attacker control: email claim; framework protection: none when setting enabled; trust boundary: OAuth provider -> account takeover; normal attacker position: requires configured OAuth provider; ships to production: yes)

**Verdict: VALID**
**Severity: MEDIUM** (downgraded from HIGH: requires non-default setting with "insecure" in name AND attacker-controlled or compromised OAuth provider; both are significant preconditions)
**Rationale**: When oauth_allow_insecure_email_lookup is enabled (non-default, explicitly warned), email-only user matching enables account takeover from any OAuth provider that can present arbitrary email claims, despite the clear naming warning.

**Finding draft written to**: archon/findings-draft/p8-043-oauth-insecure-email-lookup.md
**Registry updated**: AP-043 OAuth Email Lookup ATO

---

### [SYNTHESIZER] Verdict for H-05 -- 2026-04-11T11:04:00Z

**Prosecution summary**: auth.go:141-143 confirms JWT render keys are never revoked (empty afterRequest). render.go:36-67 confirms Admin role assignment. Priority 10 registration shadows session auth.

**Defense summary**: Nil check at auth.go:34 prevents use when renderer not configured. JWT signature requires server secret. Key leakage is a prerequisite. JWT has expiry. Network isolation typically protects render key exchange.

**Pre-FP Gate**: failed on check-3: trust boundary crossing requires a separate key leakage vulnerability as prerequisite, making this a compound finding

**Verdict: VALID**
**Severity: MEDIUM** (design weakness: non-revocable JWT tokens with Admin role; the nil check mitigates the "no renderer" scenario; exploitation requires independent key leakage)
**Rationale**: JWT render keys cannot be revoked before expiry (auth.go:141 "do nothing"), enabling persistent Admin-level access if a key is leaked, though the nil check at auth.go:34 prevents exploitation when renderer is not configured.

**Finding draft written to**: archon/findings-draft/p8-044-render-key-non-revocable.md
**Registry updated**: AP-044 Non-Revocable JWT Token

---

### [SYNTHESIZER] Verdict for H-06 -- 2026-04-11T11:05:00Z

**Prosecution summary**: CodeQL flagged unsafe symlink extraction at fs.go:99. Symlinks in plugin archives are extracted and resolved.

**Defense summary**: `isSymlinkRelativeTo()` at fs.go:165-181 validates symlink targets: rejects absolute paths, resolves relative paths with filepath.Clean, checks resolved path is within basePath using filepath.Rel. Plugin signature verification adds another layer. Plugin admin privilege required.

**Pre-FP Gate**: failed on check-2: Advocate found blocking protection — `isSymlinkRelativeTo()` validation function covers the attack vector

**Verdict: FALSE POSITIVE**
**Severity: --**
**Rationale**: The `isSymlinkRelativeTo()` function at fs.go:165-181 provides sound symlink target validation (absolute path rejection, relative path resolution and containment check). CodeQL rule `go/unsafe-unzip-symlink` fired on the structural pattern but did not account for the custom validation function.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-07 -- 2026-04-11T11:06:00Z

**Prosecution summary**: crypto.go:88 hardcodes V1 schema for secret field discovery. V2+ secret fields remain as plaintext in Settings JSON. FilterRead only suppresses SecureSettings map. Viewer-accessible endpoint returns Settings JSON with plaintext secrets. Two prior CVEs (CVE-2024-11741, CVE-2025-3415) confirm this exact pattern.

**Defense summary**: No blocking protection found. FilterRead/FilterReadDecrypted operate on SecureSettings, not Settings JSON. Schema versioning gap is systematic.

**Pre-FP Gate**: all checks passed (attacker control: Viewer role reads plaintext secrets; framework protection: FilterRead does not cover Settings JSON; trust boundary: Viewer -> credential exposure; normal attacker position: any Viewer; ships to production: yes)

**Verdict: VALID**
**Severity: MEDIUM** (credential disclosure to low-privilege users; Viewer role is common; matches 2 prior CVEs)
**Rationale**: V1 schema hardcoding at crypto.go:88 creates systematic secret exposure for V2+ integration fields, bypassing FilterRead/FilterReadDecrypted which only suppress SecureSettings, confirmed by CVE-2024-11741 and CVE-2025-3415 pattern recurrence.

**Finding draft written to**: archon/findings-draft/p8-045-receiver-v1-schema-secret-leak.md
**Registry updated**: AP-045 Schema Version Secret Leak

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-01 | VALID | HIGH | p8-040-proxy-auth-empty-allowlist.md |
| H-02 | VALID | HIGH | p8-041-extjwt-empty-audience.md |
| H-03 | VALID | MEDIUM | p8-042-ldap-enable-hook-bypass.md |
| H-04 | VALID | MEDIUM | p8-043-oauth-insecure-email-lookup.md |
| H-05 | VALID | MEDIUM | p8-044-render-key-non-revocable.md |
| H-06 | FALSE POSITIVE | -- | -- |
| H-07 | VALID | MEDIUM | p8-045-receiver-v1-schema-secret-leak.md |

Findings written: 6
Patterns added to registry: 6
Variant candidates: 0

Chamber closed: 2026-04-11T11:10:00Z
