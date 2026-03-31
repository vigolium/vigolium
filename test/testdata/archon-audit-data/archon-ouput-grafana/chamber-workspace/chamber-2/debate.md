# Review Chamber: chamber-2

Cluster: Proxy & SSRF
DFD Slices: DFD-1 (Datasource Proxy), DFD-6 (Cloud Migration SSRF), DFD-9 (xDS/OTel), TB4 (Datasource Proxy), TB9 (Cloud Migration), TB10 (External Services)
NNN Range: p8-020 to p8-039
Started: 2026-03-21T12:00:00Z
Status: CLOSED

## Enriched Findings Assigned

- **EF-002** (HIGH): Avatar Endpoint Anonymous Auth Bypass + SSRF/DoS
- **EF-006** (HIGH): Cloud Migration SSRF via GMS-Controlled Presigned Upload URL -- PoC executed in prior audit (p9-073)
- **EF-013** (MEDIUM): Datasource Proxy Forwards Connection Header and Listed Hop-by-Hop Headers (RFC 7230 violation)
- **EF-014** (MEDIUM): WebSocket Origin Check Unconditionally Allows Empty Origin (CSWSH risk)

## Pre-Validated Deep Probe Hypotheses

From `security/probe-workspace/proxy-ssrf-cloudmigration/probe-summary.md`:

- **PH-05/06** (HIGH): SSRF via GMS presigned URL + all decrypted datasource secret exfiltration
- **PH-02** (MEDIUM-HIGH): Global s.cancelFunc cross-org migration DoS without UID guessing
- **PH-01/10** (MEDIUM): Systemic missing org_id in UpdateSnapshot SQL
- **PH-11** (MEDIUM): Datasource proxy path differential CleanRelativePath vs PathUnescape
- **PH-12/16** (MEDIUM): Zero SSRF protection in default OSS installations

## Prior Audit Coverage

- p7-021: Cloud Migration SSRF (ClusterSlug injection in buildURL) -- MEDIUM
- p7-022: DS proxy parser differential (PathUnescape after route matching) -- MEDIUM
- p9-072: Cloud Migration SSRF post-creation GMS ops (persistent SSRF) -- MEDIUM
- p9-073: Cloud Migration SSRF presigned URL exfiltration (full chain) -- HIGH (PoC executed)

---

## Round 1 -- Ideation

### [IDEATOR] Hypotheses -- 2026-03-21T12:05:00Z

#### H-01: Cloud Migration Attacker-Controlled Encryption Key Enables Plaintext Credential Exfiltration

**Builds on**: PH-05/06, EF-006, p9-073
**Severity estimate**: HIGH

GMS returns `GMSPublicKey` in `StartSnapshotResponse` (gms_client.go:129-131). If GMS is compromised or MITM'd (http:// override at gms_client.go:314), the attacker controls this key. The key encrypts all decrypted datasource credentials (snapshot_mgmt.go:305). Attacker receives payload via presigned URL (s3.go:88). Since the attacker supplied the key, they can decrypt ALL credentials.

**Entry point**: `POST /api/cloudmigration/migration/:uid/snapshot`
**Code path**: gms_client.go:86-134 -> cloudmigration.go:504 GMSPublicKey -> snapshot_mgmt.go:305 DecryptJsonData -> s3.go:88 upload to attacker URL

#### H-02: Cross-Org Snapshot State Corruption via Missing org_id

**Builds on**: PH-01/10
**Severity estimate**: MEDIUM

UpdateSnapshot SQL at xorm_store.go:228-241 uses only (session_uid, uid) -- no org_id. CancelSnapshot at api.go:633 passes UIDs directly without org-scoped lookup.

**Entry point**: `POST /api/cloudmigration/migration/:uid/snapshot/:snapshotUid/cancel`
**Code path**: api.go:633 -> cloudmigration.go:819 -> xorm_store.go:228 UPDATE without org_id

#### H-03: Datasource Proxy Hop-by-Hop Header Smuggling

**Builds on**: EF-013, PH-12
**Severity estimate**: MEDIUM

PrepareProxyRequest (proxyutil.go:26-48) does NOT parse Connection header or remove hop-by-hop headers.

**Entry point**: `GET/POST /api/datasources/proxy/uid/:uid/*`
**Code path**: ds_proxy.go:137 -> reverse_proxy.go:70-81 -> proxyutil.go:26-48

#### H-04: WebSocket Empty Origin CSWSH

**Builds on**: EF-014
**Severity estimate**: MEDIUM

getCheckOriginFunc (live.go:537-539) and checkSameHost (ws.go:54-58) return true when Origin is empty.

**Entry point**: `GET /api/live/ws`

#### H-05: cancelFunc Global Singleton Cross-Org DoS

**Builds on**: PH-02, PH-08, PH-09
**Severity estimate**: MEDIUM

s.cancelFunc is a service-level singleton. CancelSnapshot calls it without mutex at line 812.

**Entry point**: `POST /api/cloudmigration/migration/:uid/snapshot/:snapshotUid/cancel`

#### H-06: X-DS-Authorization Override Credential Probing

**Builds on**: PH-13
**Severity estimate**: MEDIUM

ds_proxy.go:230-234 allows any user with datasources:query to override BasicAuth via X-DS-Authorization header.

#### H-07: Avatar Endpoint Anonymous Access

**Builds on**: EF-002
**Severity estimate**: LOW

Avatar endpoint uses reqSignedIn, accessible when anonymous auth enabled. BUT only fetches from hardcoded Gravatar URL.

---

## Round 2 -- Tracing

### [TRACER] Evidence -- 2026-03-21T12:15:00Z

#### H-01: REACHABLE -- CONFIRMED

1. gms_client.go:86-134: StartSnapshot decodes GMSPublicKey from GMS response (model.go:315)
2. cloudmigration.go:504: GMSPublicKey stored with NO validation (no format check, no trust anchor)
3. snapshot_mgmt.go:305: DecryptJsonData decrypts ALL org datasource credentials
4. Encrypted with attacker-controlled GMSPublicKey
5. s3.go:27-88: Uploaded to attacker-controlled presignedURL

Preconditions: GMS compromise or MITM (http:// override at gms_client.go:314) + GrafanaAdmin.
Trust boundary: TB-8 (Cloud Migration)

#### H-02: REACHABLE -- CONFIRMED

1. api.go:615-641: CancelSnapshot does NOT extract orgID
2. api.go:633: passes only sessUid, snapshotUid
3. cloudmigration.go:796: no org_id parameter
4. xorm_store.go:228: UPDATE without org_id
5. xorm_store.go:238-241: Same for public_key

Preconditions: GrafanaAdmin (instance-level superuser).

#### H-03: UNREACHABLE -- Go stdlib handles this

Go stdlib httputil.ReverseProxy.ServeHTTP calls removeHopByHopHeaders(outreq.Header) at reverseproxy.go:481 AFTER Director returns. This handles both Connection-listed headers and standard hop-by-hop set.

#### H-04: REACHABLE -- CONFIRMED

live.go:537-539 and ws.go:54-58 return true when Origin empty. However, browsers ALWAYS send Origin on WebSocket upgrades.

#### H-05: REACHABLE -- CONFIRMED

cloudmigration.go:539,768,668: three operations write to same s.cancelFunc
cloudmigration.go:812: s.cancelFunc() called WITHOUT lock (data race)

#### H-06: REACHABLE -- CONFIRMED

ds_proxy.go:230-234: X-DS-Authorization overwrites Authorization. But this is intentional behavior.

#### H-07: REACHABLE but NOT SSRF

avatar.go:132-138: Always uses hardcoded gravatarSource. Hash validated as 32 hex chars. URL not user-controlled.

---

## Round 3 -- Challenge

### [ADVOCATE] Defense Briefs -- 2026-03-21T12:25:00Z

#### H-01: Valid architectural weakness. No key verification mechanism. RBAC limits to GrafanaAdmin. Default HTTPS but http:// override available.

#### H-02: GrafanaAdmin already has cross-org access by design. Missing org_id is defense-in-depth gap, not privilege escalation.

#### H-03: BLOCKED by Go stdlib. httputil.ReverseProxy removes hop-by-hop headers automatically.

#### H-04: Browsers always send Origin on WebSocket upgrades. Requires misconfigured reverse proxy.

#### H-05: GrafanaAdmin has instance-level access. Data race is code quality issue.

#### H-06: Intentional feature. By-design behavior.

#### H-07: Not SSRF. Hardcoded Gravatar URL.

---

## Round 4 -- Synthesis

### [SYNTHESIZER] Verdict for H-01 -- 2026-03-21T12:35:00Z

**Prosecution**: GMS returns unverified GMSPublicKey used to encrypt all decrypted datasource credentials. Attacker controls key -> can decrypt all exfiltrated secrets.

**Defense**: Requires GrafanaAdmin + GMS compromise. Default HTTPS. p9-073 already covers SSRF chain.

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: The encryption key substitution is a distinct attack angle from p9-073 that upgrades impact from encrypted to plaintext credential exfiltration. No trust anchor or key verification exists for GMSPublicKey.

**Finding draft written to**: security/findings-draft/p8-020-cloud-migration-encryption-key-substitution.md
**Registry updated**: AP-020 Unverified Remote Encryption Key

### [SYNTHESIZER] Verdict for H-02 -- 2026-03-21T12:36:00Z

**Prosecution**: UpdateSnapshot SQL lacks org_id in WHERE clause.

**Defense**: GrafanaAdmin already has cross-org access by design.

**Pre-FP Gate**: failed on check-4: requires GrafanaAdmin (instance superuser)

**Verdict: DROP**
**Rationale**: GrafanaAdmin is instance-level superuser with implicit cross-org access. Missing org_id is code quality issue, not privilege escalation.

### [SYNTHESIZER] Verdict for H-03 -- 2026-03-21T12:37:00Z

**Prosecution**: PrepareProxyRequest does not strip hop-by-hop headers.

**Defense**: Go stdlib httputil.ReverseProxy strips them automatically after Director returns.

**Pre-FP Gate**: failed -- framework blocking protection found

**Verdict: FALSE POSITIVE**
**Rationale**: Go httputil.ReverseProxy automatically strips all hop-by-hop headers (including Connection-listed) after Director returns. Attack path is blocked by framework.

### [SYNTHESIZER] Verdict for H-04 -- 2026-03-21T12:38:00Z

**Prosecution**: Empty Origin check returns true in both live.go and ws.go.

**Defense**: Browsers always send Origin on WebSocket upgrades. Requires misconfigured reverse proxy.

**Pre-FP Gate**: failed on check-4: requires non-default reverse proxy misconfiguration

**Verdict: DROP**
**Rationale**: Browsers always send Origin on WebSocket upgrades. Attack requires misconfigured reverse proxy stripping Origin, which is not default. LOW severity -- dropped per policy.

### [SYNTHESIZER] Verdict for H-05 -- 2026-03-21T12:39:00Z

**Prosecution**: Global singleton cancelFunc causes cross-org DoS.

**Defense**: GrafanaAdmin has instance-level access already.

**Pre-FP Gate**: failed on check-4: requires GrafanaAdmin

**Verdict: DROP**
**Rationale**: GrafanaAdmin already has instance-level control. Cross-org DoS is not privilege escalation. Data race is code quality bug.

### [SYNTHESIZER] Verdict for H-06 -- 2026-03-21T12:40:00Z

**Prosecution**: X-DS-Authorization overwrites stored BasicAuth.

**Defense**: Intentional documented feature.

**Verdict: FALSE POSITIVE**
**Rationale**: By-design feature for datasource proxy authentication.

### [SYNTHESIZER] Verdict for H-07 -- 2026-03-21T12:41:00Z

**Prosecution**: Avatar endpoint accessible to anonymous users.

**Defense**: Only fetches from hardcoded Gravatar URL. Not SSRF.

**Verdict: FALSE POSITIVE**
**Rationale**: URL is hardcoded to Gravatar. Hash validated as 32 hex chars. No SSRF. LOW severity proxy amplification dropped per policy.

### Prior Finding: EF-006 / p9-073 -- CONFIRMED_PRIOR

Cloud Migration SSRF via presigned URL confirmed still present. No duplicate draft needed. H-01 extends with encryption key substitution angle.

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-01 | VALID | HIGH | p8-020-cloud-migration-encryption-key-substitution.md |
| H-02 | DROP | -- | -- |
| H-03 | FALSE POSITIVE | -- | -- |
| H-04 | DROP | -- | -- |
| H-05 | DROP | -- | -- |
| H-06 | FALSE POSITIVE | -- | -- |
| H-07 | FALSE POSITIVE | -- | -- |
| EF-006/p9-073 | CONFIRMED_PRIOR | HIGH | p9-073 (no duplicate) |

Findings written: 1
Patterns added to registry: 1
Variant candidates: 0

Chamber closed: 2026-03-21T12:45:00Z
