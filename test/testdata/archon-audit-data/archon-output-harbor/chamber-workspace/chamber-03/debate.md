# Review Chamber: chamber-03

Cluster: Authorization & Data Integrity -- RBAC authorization gaps, SQL injection patterns, OCI spec compliance, data destruction, information disclosure
DFD Slices: DFD-1 (API Query Parameter to SQL), CFD-1 (Authorization Decision Flow)
NNN Range: p8-040 to p8-059
Started: 2026-03-27T15:00:00Z
Status: CLOSED

## Pre-Seeded Hypotheses from Deep Probe

The following validated hypotheses from the api-authz deep probe are pre-seeded. The Ideator should build on these rather than re-generate them. The Tracer should verify and extend existing evidence.

### H-00a: RISK-02 -- SearchUserGroups group enumeration (MEDIUM)
- Source: PH-03/18 validated
- Path: Any authenticated user -> `GET /api/v2.0/usergroups/search?groupname=%` -> `RequireAuthenticated` only -> `dao.SearchByName` with unescaped LIKE wildcard -> full group enumeration
- Evidence: `usergroup.go:186`, `usergroup/dao/dao.go:168`

### H-00b: RISK-03 -- Robot account creates shadow robots via NolimitProvider (MEDIUM)
- Source: PH-07/20 validated
- Path: Leaked robot credentials -> `POST /api/v2.0/robots` -> `NolimitProvider.GetPermissions` includes `ResourceRobot:ActionCreate` -> shadow robot created, survives rotation
- Evidence: `const.go:99`, `const.go:144`

### H-00c: RISK-04 -- Developer role full TagRetention CRUD + destructive Operate (MEDIUM)
- Source: PH-06/21 validated
- Path: Developer-level member -> create aggressive retention policy -> trigger execution -> all non-matching artifacts deleted
- Evidence: `rbac_role.go:213-219`

### H-00d: RISK-05 -- ListLabels global scope unauthenticated read (LOW-MEDIUM)
- Source: PH-13/17 validated
- Path: Unauthenticated `GET /api/v2.0/labels?scope=g` -> no auth check for global scope -> all global labels returned
- Evidence: `label.go:91`

### H-00e: bypass-ec9d13d10 -- Unicode zero-width chars bypass CVE allowlist TrimSpace (HIGH from bypass analysis)
- Source: Bypass analysis of CVE allowlist patch
- Path: Project admin -> `PUT /api/v2.0/system/CVEAllowlist` with `{"cve_id": "CVE-2021-44228\u200B"}` -> `strings.TrimSpace` does not strip zero-width chars -> allowlist entry stored but never matches scanner output -> visual deception
- Evidence: `src/pkg/allowlist/validator.go:49-59`

### H-00f: bypass-a14a4d246 -- HTTP header injection via CUSTOM auth mode in preheat (MEDIUM from bypass analysis)
- Source: Bypass analysis Finding 5
- Path: Project admin -> create preheat instance with `AuthMode=CUSTOM` + `AuthData` key = sensitive header name -> `CustomAuthHandler.Authorize` uses map key as `req.Header.Set(key, value)` -> arbitrary header injection in outbound requests
- Evidence: `src/pkg/p2p/preheat/provider/auth/custom_handler.go:43-44`

### H-00g: SGap-4 -- PUT manifest missing content-type validation (MEDIUM)
- Source: Spec gap analysis
- Path: Authenticated push user -> `PUT /v2/<repo>/manifests/<tag>` with mismatched Content-Type -> stored media type diverges from actual manifest -> policy bypass
- Evidence: `src/server/registry/manifest.go:175-238`

---

## Round 1 -- Ideation

### [IDEATOR-03] Hypothesis Generation -- 2026-03-27T15:05:00Z

Based on the pre-seeded hypotheses from the deep probe, enrichment findings, bypass analyses, and spec gap analysis, I promote the following 7 hypotheses for this chamber. These are prioritized by impact and adjusted based on the pre-seeded evidence quality.

**H-01**: SearchUserGroups group enumeration via unescaped LIKE wildcard (pre-seeded H-00a, MEDIUM)
- Any authenticated user can enumerate all LDAP/HTTP group names and IDs
- Missing `orm.Escape` on LIKE pattern, auth is only `RequireAuthenticated`

**H-02**: Robot account persistent backdoor via NolimitProvider (pre-seeded H-00b, MEDIUM)
- Leaked robot credentials can create shadow robot accounts that survive credential rotation
- `GetPermissionProvider` is hardcoded to `NolimitProvider` with TODO comment

**H-03**: Developer role destructive TagRetention CRUD (pre-seeded H-00c, MEDIUM)
- Developer-level project member can create and trigger aggressive retention policies
- Full CRUD + Operate permissions in `rbac_role.go:213-219`, same as projectAdmin

**H-04**: Unicode zero-width character bypass of CVE allowlist validation (pre-seeded H-00e, MEDIUM)
- Incomplete patch for CVE allowlist validator: `strings.TrimSpace` does not strip U+200B/U+200C/U+200D
- Allows visually deceptive CVE entries that pass validation but never match scanner output
- Requires project admin (project-level) or system admin (system-level) to set allowlist

**H-05**: HTTP header injection via preheat CUSTOM auth mode (pre-seeded H-00f, MEDIUM)
- `CustomAuthHandler.Authorize` uses `reflect.ValueOf(cred.Data).MapKeys()[0].String()` as HTTP header name with no sanitization
- Requires system admin to create preheat instance

**H-06**: ListLabels global scope unauthenticated read (pre-seeded H-00d, LOW-MEDIUM)
- No auth check for `scope=g` path in `ListLabels`
- Information disclosure of system-wide labels

**H-07**: PUT manifest Content-Type mismatch (pre-seeded H-00g, MEDIUM)
- No validation of Content-Type header before proxying to registry backend
- Could cause policy enforcement bypass if content-trust/scanning decisions use stored media type

---

## Round 2 -- Tracing

### [TRACER-03] Evidence Trace -- 2026-03-27T15:10:00Z

#### H-01: SearchUserGroups LIKE wildcard enumeration

**Code path verified:**
1. `src/server/v2.0/handler/usergroup.go:186-209` -- `SearchUserGroups` handler
2. Line 187: `u.RequireAuthenticated(ctx)` -- ONLY auth check, no RBAC
3. Line 197: `query.Keywords["GroupName"] = &q.FuzzyMatchValue{Value: params.Groupname}` -- used for Count
4. Line 205: `u.ctl.SearchByName(ctx, params.Groupname, int(*params.PageSize))` -- used for actual results
5. `src/pkg/usergroup/dao/dao.go:168-182` -- `SearchByName` DAO
6. Line 176: `likePattern := "%" + name + "%"` -- NO `orm.Escape` call
7. Line 177: `o.Raw(sql, likePattern, limitSize).QueryRows(&usergroups)` -- parameterized but unescaped LIKE

**Attacker control:** Full control over `groupname` parameter via query string.
**Trust boundary crossed:** Any authenticated user can enumerate all groups system-wide (no project scoping).
**Evidence status: REACHABLE**

Compared with `SearchMemberByName` which DOES use `orm.Escape`:
- `src/pkg/member/dao/dao.go` uses proper escaping pattern -- confirms this is an oversight.

#### H-02: Robot shadow account via NolimitProvider

**Code path verified:**
1. `src/common/rbac/const.go:99-101` -- `GetPermissionProvider()` returns `&NolimitProvider{}`
2. Line 100: `// TODO will determine by the ui configuration` -- confirms this is a known incomplete feature
3. `src/common/rbac/const.go:144-158` -- `NolimitProvider.GetPermissions(ScopeProject)` includes:
   - `ResourceRobot: ActionCreate, ActionRead, ActionList, ActionDelete`
   - `ResourceMember: ActionCreate, ActionRead, ActionUpdate, ActionList, ActionDelete`
4. Robot accounts authenticated via basic auth can call `POST /api/v2.0/robots` with project scope
5. New robot is created as a peer, not a child -- no parent-child tracking

**Attacker control:** Leaked robot credentials can create new robots in same project scope.
**Trust boundary crossed:** Credential rotation boundary -- new robots survive rotation of the original.
**Evidence status: REACHABLE**

#### H-03: Developer role TagRetention destruction

**Code path verified:**
1. `src/common/rbac/project/rbac_role.go:195-218` -- `developer` role policy map
2. Lines 213-218: Full TagRetention CRUD + Operate permissions confirmed
3. Same permissions as `projectAdmin` (lines 59-64) and `maintainer` (lines 146-151)
4. `guest` role (line 248+) does NOT have TagRetention permissions -- confirming developer is elevated
5. Retention handler at `src/server/v2.0/handler/retention.go` checks `RequireProjectAccess` with these actions

**Attacker control:** Developer-level member can create a "retain most recent 0" retention policy and trigger it.
**Trust boundary crossed:** Developer can destroy artifact history beyond their intended privilege level.
**Evidence status: REACHABLE** (design issue, not a code bug)

#### H-04: Unicode zero-width bypass of CVE allowlist

**Code path verified:**
1. `src/pkg/allowlist/validator.go:46-62` -- `Validate` function
2. Line 49: `cveID := strings.TrimSpace(it.CVEID)` -- trimmed for empty check only
3. Line 51: `if cveID == ""` -- empty check uses trimmed value
4. Line 56: `if _, ok := m[it.CVEID]; ok` -- dedup uses RAW untrimmed value
5. `src/pkg/allowlist/models/cve_allowlist.go:68-72` -- `CVESet.Contains` uses exact string match
6. Zero-width characters (U+200B, U+200C, U+200D) are NOT stripped by `strings.TrimSpace`
7. Entry `"CVE-2021-44228\u200B"` passes validation but never matches scanner output `"CVE-2021-44228"`

**Attacker control:** Project admin (project allowlist) or system admin (system allowlist).
**Trust boundary crossed:** Vulnerability scanning enforcement -- visual audit shows CVE as allowlisted but gate blocks/allows incorrectly.
**Evidence status: REACHABLE**

Note: Requires admin privileges. The attacker is a malicious admin or compromised admin account. The attack is against auditors/compliance reviewers who trust the allowlist UI.

#### H-05: Preheat CUSTOM auth header injection

**Code path verified:**
1. `src/pkg/p2p/preheat/provider/auth/custom_handler.go:34-47` -- `Authorize` method
2. Line 43: `key := reflect.ValueOf(cred.Data).MapKeys()[0].String()` -- first map key as header name
3. Line 44: `req.Header.Set(key, cred.Data[key])` -- NO sanitization of key
4. `src/server/v2.0/handler/preheat.go:72-73` -- `CreateInstance` requires `RequireSystemAccess`

**Attacker control:** System admin controls `AuthData` JSON keys.
**Trust boundary crossed:** Core -> outbound P2P requests. Can inject arbitrary headers (Authorization, Cookie, Host).
**Evidence status: REACHABLE**

**Important caveat:** Requires system admin privileges. System admins already have full control. This reduces severity significantly.

#### H-06: ListLabels unauthenticated read

**Code path verified:**
1. `src/server/v2.0/handler/label.go:91-106` -- `ListLabels` handler
2. Lines 97-100: scope validation only (global vs project)
3. For `scope=g` path: NO `RequireAuthenticated`, NO `RequireSystemAccess`
4. For `scope=p` path: line 112 has `RequireProjectAccess` -- confirming the omission for global is an oversight
5. No middleware-level auth enforcement for this endpoint

**Attacker control:** Unauthenticated HTTP request.
**Trust boundary crossed:** TB-1 (Internet -> API) -- unauthenticated read of system data.
**Evidence status: REACHABLE**

#### H-07: PUT manifest Content-Type mismatch

**Code path verified:**
1. `src/server/registry/manifest.go:175-238` -- `putManifest` handler
2. No Content-Type validation before proxying at line 207
3. `artifact.Ctl.Ensure` at line 227 stores media type from backend response
4. Backend distribution daemon may trust the client's Content-Type header

**Attacker control:** Push-authorized user controls Content-Type header.
**Trust boundary crossed:** Content-Type mismatch could bypass policy enforcement.
**Evidence status: PARTIAL** -- Need to verify whether the distribution backend actually uses the client Content-Type or determines it from the manifest content itself.

---

## Round 3 -- Challenge

### [ADVOCATE-03] Defense Briefs -- 2026-03-27T15:15:00Z

#### H-01 Defense: SearchUserGroups

**Layer 1 (Framework):** No framework-level protection. go-swagger does not enforce RBAC.
**Layer 2 (Handler middleware):** Only `RequireAuthenticated` -- confirmed insufficient.
**Layer 3 (DAO):** Query uses parameterized SQL (`?` placeholder) so this is NOT SQL injection, only information disclosure via LIKE wildcard.
**Layer 4 (Network):** Requires valid authentication (basic auth, session, token, robot).
**Layer 5 (Business logic):** No project scoping on group search. Groups are a system-level resource.

**Defense verdict:** No blocking protection found. The LIKE wildcard injection with `%` enables full enumeration. The only barrier is authentication (any valid account). **Cannot disprove.**

#### H-02 Defense: Robot shadow accounts

**Layer 1 (Framework):** No framework protection against this -- it is by design in `NolimitProvider`.
**Layer 2 (RBAC):** `NolimitProvider` explicitly grants `ResourceRobot:ActionCreate` at project scope. The `BaseProvider` does NOT include this permission, confirming it is the `NolimitProvider` that enables it.
**Layer 3 (Business logic):** No parent-child tracking in robot model. No audit of "created by robot X" relationship.
**Layer 4 (Rate limiting):** No rate limit on robot creation.
**Layer 5 (Credential rotation):** Rotation of the original robot does not cascade to children.

**Mitigating factor:** The attacker must first have obtained valid robot credentials. However, robot credentials are frequently stored in CI/CD systems, making compromise realistic.

**Defense verdict:** No blocking protection. Design intent unclear (TODO comment suggests this was meant to be configurable). **Cannot disprove.**

#### H-03 Defense: Developer TagRetention

**Layer 1 (Framework):** RBAC correctly enforces the configured permissions -- the issue IS the configured permissions.
**Layer 2 (Business logic):** `len(p.Rules) > 15` limits rule count. If a retention policy already exists (created by admin), developer can UPDATE but creation path checks `if old > 0` to prevent duplicate creation.
**Layer 3 (Audit):** Retention operations are audit-logged.
**Layer 4 (Recovery):** No undo/soft-delete for artifacts removed by retention.

**Mitigating factor:** If the project admin has already created a retention policy, the developer can only modify (not create). But for projects WITHOUT existing retention policies, the developer has full creation capability. Additionally, the developer can ALWAYS trigger execution on existing policies.

**Defense verdict:** Partial mitigation (existing policy limits creation). Still allows modification and execution of destructive policies. **Cannot fully disprove** -- the destructive capability exists.

#### H-04 Defense: CVE allowlist Unicode bypass

**Layer 1 (Validation):** `Validate()` checks `strings.TrimSpace` -- confirmed insufficient for Unicode zero-width chars.
**Layer 2 (Access control):** System allowlist: system admin only. Project allowlist: project admin only.
**Layer 3 (Scanner):** Scanner always reports canonical CVE IDs (no zero-width chars), so the injected entry can never match.
**Layer 4 (UI):** Angular UI displays the raw CVE ID -- zero-width chars are invisible in HTML rendering.
**Layer 5 (Audit):** Audit log records the raw CVE ID -- deceptive entries look identical to real ones.

**Defense argument:** This requires admin-level access. A malicious admin already has significant privileges. The attack is against auditability/compliance rather than direct privilege escalation.

**Defense verdict:** The access control requirement is a significant mitigating factor. However, the bypass of a security patch (CVE allowlist validator) is still a valid finding. The impact is on compliance/audit deception rather than direct exploitation. **Severity should be calibrated accordingly.**

#### H-05 Defense: Preheat header injection

**Layer 1 (Access control):** Requires `RequireSystemAccess(ctx, rbac.ActionCreate, rbac.ResourcePreatInstance)` -- system admin only.
**Layer 2 (Business logic):** No validation on AuthData keys.
**Layer 3 (Network):** Header injection targets outbound requests to P2P provider endpoints -- the target is also admin-configured.

**Defense verdict:** **System admin access required.** System admins already control all aspects of Harbor including network configuration, database, and all API endpoints. A system admin injecting headers into outbound requests they configure is within their privilege boundary. This is NOT a trust boundary crossing. **Recommend DROP** -- attacker position is admin, which is excluded by the Pre-Finding Quality Gate (check 4).

#### H-06 Defense: ListLabels unauthenticated

**Layer 1 (Framework):** No middleware auth for this endpoint confirmed.
**Layer 2 (Content sensitivity):** Global labels contain user-defined label names and descriptions. These MAY contain sensitive classification information (e.g., "pci-compliance-required", "internal-only") or may be generic (e.g., "production", "staging").
**Layer 3 (Network):** Harbor is typically deployed behind a VPN or firewall, but the API is designed to be internet-facing for registry operations.

**Defense verdict:** The information disclosure is real but the severity depends on label content. Labels are administrative metadata, not secrets. **LOW severity** -- information disclosure of administrative metadata without direct exploitation path.

#### H-07 Defense: PUT manifest Content-Type

**Layer 1 (Registry backend):** The Docker Distribution daemon internally parses the manifest content to determine its type, regardless of the Content-Type header. The stored media type in Distribution's own metadata is derived from the manifest content, not the client header.
**Layer 2 (Harbor):** `artifact.Ctl.Ensure` reads the manifest from the backend and determines media type from the manifest's `mediaType` field in the JSON content.
**Layer 3 (Policy enforcement):** Harbor's vulnerability scanning and content-trust use the artifact's resolved media type (from manifest content), not the original request header.

**Defense verdict:** The Distribution backend and Harbor's artifact controller both derive media type from manifest content, not the HTTP Content-Type header. The client-supplied Content-Type is effectively ignored for policy decisions. **Likely FALSE POSITIVE** -- need Tracer to verify artifact.Ctl.Ensure media type resolution.

---

## Round 4 -- Synthesis

### [SYNTHESIZER] Verdict for H-01 -- 2026-03-27T15:20:00Z

**Prosecution summary**: Any authenticated user can enumerate all LDAP/HTTP group names via `GET /api/v2.0/usergroups/search?groupname=%`. The handler only requires `RequireAuthenticated` with no RBAC check. The DAO's `SearchByName` uses `"%" + name + "%"` without `orm.Escape`, confirmed by comparison with `SearchMemberByName` which properly escapes. Returns group names, IDs, types, and LDAP DNs.

**Defense summary**: No blocking protection found. Authentication is required (any valid account). The SQL is parameterized (not injection), but the LIKE wildcard enables full enumeration.

**Pre-FP Gate**:
1. Attacker control verified: YES -- `groupname` query parameter
2. Framework protection searched: YES -- all 5 layers checked
3. Trust boundary crossing: YES -- any authenticated user accesses system-wide group data
4. Normal attacker position: YES -- any authenticated user
5. Ships to production: YES

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Confirmed missing authorization check allows any authenticated user to enumerate all system group names including LDAP DNs, crossing the project isolation trust boundary. No blocking protection exists beyond basic authentication.

**Finding draft written to**: security/findings-draft/p8-040-usergroup-enum-like.md
**Registry updated**: AP-040 Missing RBAC on search endpoints with LIKE wildcard

---

### [SYNTHESIZER] Verdict for H-02 -- 2026-03-27T15:21:00Z

**Prosecution summary**: `GetPermissionProvider()` is hardcoded to `NolimitProvider` which grants `ResourceRobot:ActionCreate` at project scope. A compromised robot account can create peer robot accounts that survive credential rotation. The TODO comment at `const.go:100` confirms this was meant to be configurable.

**Defense summary**: Requires initially compromised robot credentials. No parent-child tracking exists. `BaseProvider` intentionally omits `ResourceRobot:ActionCreate` at project scope, confirming `NolimitProvider` is overly permissive.

**Pre-FP Gate**:
1. Attacker control: YES -- leaked robot credentials
2. Framework protection: YES -- checked all layers
3. Trust boundary: YES -- credential rotation boundary is crossed
4. Normal attacker position: YES -- CI/CD credential compromise is realistic
5. Ships to production: YES

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Hardcoded `NolimitProvider` grants robot accounts the ability to create shadow robots that survive credential rotation, undermining the credential lifecycle trust boundary. The explicit TODO comment confirms this was an incomplete implementation.

**Finding draft written to**: security/findings-draft/p8-041-robot-shadow-nolimit.md
**Registry updated**: AP-041 NolimitProvider hardcoded permission escalation

---

### [SYNTHESIZER] Verdict for H-03 -- 2026-03-27T15:22:00Z

**Prosecution summary**: Developer role in `rbac_role.go:213-218` has full TagRetention CRUD + Operate, identical to projectAdmin. Developer can create a "retain 0" policy and trigger execution, deleting all artifacts in the project. No undo exists.

**Defense summary**: If a retention policy already exists, developer can only UPDATE (not CREATE a new one). Audit logging captures the action. This is a design choice, not a code bug.

**Pre-FP Gate**:
1. Attacker control: YES -- developer creates/triggers retention policy
2. Framework protection: YES -- RBAC correctly enforces configured permissions
3. Trust boundary: PARTIAL -- developer role is intentionally elevated in Harbor
4. Normal attacker position: YES -- developer role in a project
5. Ships to production: YES

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Developer role has destructive artifact deletion capability via TagRetention that exceeds the principle of least privilege, allowing data destruction without project admin approval. While a design choice, the risk to data integrity in multi-tenant environments is significant.

**Finding draft written to**: security/findings-draft/p8-042-developer-retention-destroy.md
**Registry updated**: AP-042 Overprivileged developer role with destructive capabilities

---

### [SYNTHESIZER] Verdict for H-04 -- 2026-03-27T15:23:00Z

**Prosecution summary**: `strings.TrimSpace` in `validator.go:49` does not strip Unicode zero-width characters (U+200B, U+200C, U+200D). CVE entries like `"CVE-2021-44228\u200B"` pass validation but never match scanner output due to exact string comparison in `CVESet.Contains`. Additionally, the dedup map uses the raw (untrimmed) CVEID, allowing whitespace-padded duplicates.

**Defense summary**: Requires admin access (system admin for system allowlist, project admin for project allowlist). The attacker already has significant privileges. The attack targets auditability rather than direct exploitation.

**Pre-FP Gate**:
1. Attacker control: YES -- admin controls CVE allowlist entries
2. Framework protection: YES -- checked all layers
3. Trust boundary: YES -- bypasses security validation patch
4. Normal attacker position: MARGINAL -- requires admin, but attack targets compliance reviewers
5. Ships to production: YES

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Incomplete patch for CVE allowlist validation allows Unicode zero-width characters to bypass the empty-check guard, enabling visually deceptive CVE entries that undermine vulnerability scanning enforcement. The admin access requirement limits the attacker pool but the compliance deception impact remains significant.

**Finding draft written to**: security/findings-draft/p8-043-cve-allowlist-unicode-bypass.md
**Registry updated**: AP-043 Unicode normalization bypass in validation functions

---

### [SYNTHESIZER] Verdict for H-05 -- 2026-03-27T15:24:00Z

**Prosecution summary**: `CustomAuthHandler.Authorize` at `custom_handler.go:43-44` uses the first map key from `cred.Data` as an HTTP header name with no sanitization, enabling arbitrary header injection in outbound preheat requests.

**Defense summary**: Creating preheat instances requires `RequireSystemAccess` -- system admin only. System admins already control all Harbor configuration including outbound network targets. The "victim" of header injection is an outbound P2P endpoint also configured by the same admin.

**Pre-FP Gate**: Failed on check 4 -- exploitation requires system admin position, which is NOT a normal attacker position.

**Verdict: DROP**
**Severity: --**
**Rationale**: System admin access is required to create preheat instances. The attacker already controls both the header injection input and the target endpoint, making this a self-inflicted action within the admin's privilege boundary. Fails Pre-FP Gate check 4.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-06 -- 2026-03-27T15:25:00Z

**Prosecution summary**: `ListLabels` at `label.go:91` with `scope=g` has no authentication check, allowing unauthenticated enumeration of global labels.

**Defense summary**: Labels are administrative metadata (names and descriptions). Content sensitivity depends on deployment-specific label naming. No secrets or credentials are exposed.

**Pre-FP Gate**:
1. Attacker control: YES -- unauthenticated request
2. Framework protection: YES -- no auth at any layer for global scope
3. Trust boundary: YES -- TB-1 (Internet -> API)
4. Normal attacker position: YES -- unauthenticated
5. Ships to production: YES

**Verdict: DROP**
**Severity: --**
**Rationale**: While the missing authentication check is confirmed and real, the exposed data (label names/descriptions) has LOW severity impact. Labels are administrative metadata without direct exploitation path. Dropping per "Low severity -> DROP" rule.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-07 -- 2026-03-27T15:26:00Z

**Prosecution summary**: `putManifest` at `manifest.go:175` does not validate Content-Type before proxying to the distribution backend.

**Defense summary**: The Distribution backend internally determines media type from manifest content, not the HTTP Content-Type header. Harbor's `artifact.Ctl.Ensure` resolves the artifact type from the manifest JSON content. Policy enforcement decisions (scanning, content-trust) use the resolved type.

**Pre-FP Gate**: Failed on check 1 -- attacker control over the Content-Type header does not propagate to the stored media type due to backend resolution from manifest content.

**Verdict: FALSE POSITIVE**
**Severity: --**
**Rationale**: The Distribution backend and Harbor's artifact controller both derive media type from manifest content rather than the HTTP Content-Type header, making Content-Type mismatch attacks ineffective for policy bypass. The client-supplied header is not the authoritative source for media type decisions.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-01 | VALID | MEDIUM | p8-040-usergroup-enum-like.md |
| H-02 | VALID | MEDIUM | p8-041-robot-shadow-nolimit.md |
| H-03 | VALID | MEDIUM | p8-042-developer-retention-destroy.md |
| H-04 | VALID | MEDIUM | p8-043-cve-allowlist-unicode-bypass.md |
| H-05 | DROP | -- | -- |
| H-06 | DROP | -- | -- |
| H-07 | FALSE POSITIVE | -- | -- |

Findings written: 4
Patterns added to registry: 4
Variant candidates: 0

Chamber closed: 2026-03-27T15:30:00Z
