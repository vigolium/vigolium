# Grafana Security Advisory Report — EXPANDED PHASE 1

**Phase 1 Intelligence Gathering - Advisory Inventory (Expanded)**
**Audit ID:** 2026-03-21T00:00:00.000Z
**Generated:** 2026-03-21
**Repository:** github.com/grafana/grafana
**Current Commit:** 40a9cd68ff8efc62da02d30bf4b3e8ae3a1017ab
**Current Version (in-tree):** 13.0.0-pre (development branch)

---

## Executive Summary

This report documents all published security advisories, CVEs, and patch information for Grafana and its key dependencies. The analysis covers the core Grafana platform (2024–2026), published plugins, and direct Go/npm dependencies. This is the expanded Phase 1 report that supersedes the prior 22-CVE report.

**Scope:** Advisories published from 2024-01-01 through 2026-03-21.

**Collection Statistics:**
- Source 1 (CHANGELOG/git log): 22 unique CVE IDs (2024–2026)
- Source 2 (GitHub Security Advisories API): 20 historical GHSAs (all pre-2024), 0 new 2024+ repo advisories
- Source 3 (OSV API): Not indexed by package name for grafana
- Source 4 (NVD): Confirmed via Grafana advisory page
- Source 5 (Grafana Security Advisory Page): Full 2024–2026 advisory list with 23 core Grafana CVEs + 4 plugin CVEs + 5 dependency CVEs

**Total unique CVEs collected (2024–2026): 40 (exceeds 30-CVE target)**

---

## Advisory Inventory — CRITICAL Severity

| CVE ID | CVSS | Component | Affected Versions | Patched Version | Published | Description |
|--------|------|-----------|-------------------|-----------------|-----------|-------------|
| CVE-2025-41115 | 10.0 | SCIM (Enterprise) | 12.0.0–12.2.0 | >=12.3.0, >=12.2.1, >=12.1.3, >=12.0.6 | 2025-11-19 | Incorrect privilege assignment via SCIM numeric externalId — allows user impersonation and full admin escalation |
| CVE-2025-11539 | 9.9 | Image Renderer Plugin | 1.0.0–4.0.16 | >=4.0.17 | 2025-10-09 | Arbitrary code execution in Image Renderer — /render/csv endpoint lacks filePath validation enabling arbitrary file write and Chromium RCE |
| CVE-2024-8986 | 9.1 | Grafana Plugin SDK (Go) | <=0.249.0 | >=0.250.0 | 2024-10-22 | Build credentials leaked in compiled plugin binaries — SDK embeds git remote URL (with credentials) into binary metadata |
| CVE-2025-41118 | 9.1 | Pyroscope Plugin | (see advisory) | (see advisory) | 2026-01-02 | Exposure of storage secret in Pyroscope plugin configuration endpoint |
| CVE-2024-9264 | 9.4 | Grafana Core (SQL Expressions) | 11.0.0–11.0.4, 11.1.0–11.1.5, 11.2.0 | 11.0.5+sec, 11.1.6+sec, 11.2.1+sec | 2024-10-17 | RCE via SQL Expressions — unsanitized duckdb query parameters allow command injection and local file inclusion (VIEWER permission required) |
| CVE-2024-45337 | 9.1 | golang.org/x/crypto (dep) | <0.31.0 | >=0.31.0 | 2024-12-11 | SSH auth bypass via PublicKeyCallback misuse — attacker can authenticate with key A while app authorizes based on key B |

---

## Advisory Inventory — HIGH Severity

| CVE ID | CVSS | Component | Affected Versions | Patched Version | Published | Description |
|--------|------|-----------|-------------------|-----------------|-----------|-------------|
| CVE-2025-3260 | 8.3 | Dashboard API | 11.6.0–11.6.1 | >=11.6.1+security-01 | 2025-04-22 | Authorization bypass in /apis/dashboard.grafana.app/* — missing scope check allows viewers/editors to access all dashboards/folders |
| CVE-2026-21721 | 8.1 | Dashboard Permissions | 10.2.0–11.6.8, 12.0.0–12.3.0 | >=12.3.1+sec, >=12.2.3, >=12.1.5, >=12.0.8, >=11.6.9 | 2026-01-27 | Cross-dashboard privilege escalation — permission manager on one dashboard can modify permissions of any other dashboard |
| CVE-2025-6023 | 7.6 | Scripted Dashboards | <12.0.2+sec, <11.6.3+sec | >=12.0.2+sec, >=11.6.3+sec | 2025-07-18 | XSS via scripted dashboards — open redirect chained with path traversal enables XSS without editor permissions |
| CVE-2025-4123 | 7.6 | Frontend Plugin Loader | <10.4.18+sec, <11.2.9+sec, <11.6.1+sec, <12.0.0+sec | >=12.0.0+sec | 2025-05-21 | XSS via frontend plugin open redirect — client path traversal + open redirect loads malicious plugin; SSRF if Image Renderer installed |
| CVE-2026-21720 | 7.5 | Avatar Cache | 3.0.0–11.6.8, 12.0.0–12.3.0 | >=12.3.1+sec, >=12.2.3, >=12.1.5, >=12.0.8, >=11.6.9 | 2026-01-27 | Unauthenticated DoS in avatar cache — unauthenticated requests to avatar endpoint exhaust goroutines via non-terminating Gravatar timeouts |
| CVE-2026-28377 | 7.5 | Tempo Plugin | (see advisory) | (see advisory) | 2026-03-16 | S3 SSE-C encryption key exposed in plaintext via Tempo plugin config endpoint |
| CVE-2024-8975 | 7.3 | Grafana Alloy | <1.3.3 (Windows) | >=1.3.3 | 2024-10-04 | Privilege escalation via unquoted Windows service path — local user can escalate to SYSTEM level |
| CVE-2024-8996 | 7.3 | Grafana Agent Flow | <0.43.3 (Windows) | >=0.43.3 | 2024-10-04 | Privilege escalation via unquoted Windows service path in Agent Flow mode (same root cause as CVE-2024-8975) |
| CVE-2024-5526 | 7.7 | Grafana OnCall | 1.1.37–<1.5.2 | >=1.5.2 | 2024-06-26 | SSRF in Grafana OnCall webhooks — authenticated users can pivot to internal network resources via webhook URL |
| CVE-2024-45338 | 5.3–8.7 | golang.org/x/net (dep) | <0.33.0 | >=0.33.0 | 2024-12-11 | DoS in HTML parser — non-linear parsing of case-insensitive content allows O(n^2) CPU exhaustion |
| CVE-2025-30204 | 7.5 | golang-jwt/jwt (dep) | 3.2.0–<5.2.2, <4.5.2 | >=5.2.2, >=4.5.2 | 2025-03-21 | DoS via JWT with many period characters — ParseUnverified calls strings.Split on attacker-controlled input causing O(n) allocations |
| CVE-2025-29786 | 7.5 | expr-lang/expr (dep) | <1.17.0 | >=1.17.0 | 2025-03-12 | DoS via unbounded expression input — AST node allocation per character enables memory exhaustion/OOM crash |

---

## Advisory Inventory — MEDIUM Severity

| CVE ID | CVSS | Component | Affected Versions | Patched Version | Published | Description |
|--------|------|-----------|-------------------|-----------------|-----------|-------------|
| CVE-2025-2703 | 6.8 | XY Chart Plugin | 11.1.0–11.6.0 (pre-patch) | >=11.6.0+sec, >=11.5.3+sec, >=11.4.3+sec | 2025-04-23 | DOM XSS in XY Chart plugin — editor can inject JavaScript via panel configuration |
| CVE-2025-41117 | 6.8 | Explore Stack Trace | <12.3.2+sec, <12.2.4+sec | >=12.3.2+sec | 2026-02-12 | XSS in Explore stack trace rendering — unsanitized HTML in TraceView component |
| CVE-2024-1313 | 6.5 | Snapshots | 9.5.0–9.5.17, 10.0.0–10.0.12, 10.1.0–10.1.8, 10.2.0–10.2.5, 10.3.0–10.3.4 | >=9.5.18, >=10.0.13, >=10.3.5 | 2024-03-27 | Snapshot deletion auth bypass — users from different orgs can delete snapshots via DELETE /api/snapshots/ with view key |
| CVE-2024-1442 | 6.0 | Data Sources | 8.5.0–<9.5.7, 10.0.0–<10.3.4 | >=9.5.7, >=10.3.4 | 2024-03-07 | Privilege escalation via wildcard datasource UID — creates datasource with `*` UID granting access to all org datasources |
| CVE-2025-3580 | 5.5 | Admin Management | 10.4.x–12.0.x | >=12.0.1, >=11.6.2, >=11.5.5 | 2025-05-22 | Org admin can delete server admin — DELETE /api/org/users/ lacks server-admin guard, rendering instance unmanageable |
| CVE-2024-8118 | 5.1 | Alerting API | 8.5.0–11.2.0 | >=11.2.1, >=10.4.9, >=10.3.10 | 2024-09-26 | Alerting permission bypass — external alert instance write permission incorrectly allows creating/modifying alert rules |
| CVE-2026-21722 | 5.3 | Public Dashboards | >=9.3.0, <12.3.2+sec | >=12.3.2+sec, >=12.2.4, >=12.1.6, >=11.6.10 | 2026-02-12 | Public dashboard annotation timerange bypass — from/to parameters accepted even when time selection disabled |
| CVE-2024-9476 | 5.1 | Cloud Migration Assistant | 11.2.0–11.3.0 | >=11.3.0+sec, >=11.2.3+sec | 2024-11-12 | Cross-org resource access via Cloud Migration Assistant — users can access other organization's resources during migration |
| CVE-2024-6322 | 4.4 | Plugin Data Sources | (many versions) | see advisory | 2024-07-23 | Plugin data source access control bypass — ReqActions validation bypassed when user has query access to any other datasource |
| CVE-2025-3454 | 5.0 | Datasource Proxy | <10.4.17+sec, <11.6.0+sec | >=10.4.17+sec, >=11.6.0+sec | 2025-04-22 | Auth bypass via double-slash URL path — extra slash bypasses route-level permission checks on Prometheus/Alertmanager datasource endpoints |
| CVE-2025-3415 | 4.3 | DingDing Integration | <10.4.19+sec, <12.0.1+sec | >=12.0.1+sec, >=11.6.2+sec | 2025-06-13 | Info disclosure in DingDing alerting integration — Viewer can read contact point secrets including DingDing API keys |
| CVE-2025-6197 | 4.2 | Organization Switching | <12.0.2+sec | >=12.0.2+sec, >=11.6.3+sec | 2025-07-18 | Open redirect in org switching — attacker constructs URL to redirect victim to malicious site during org switch |
| CVE-2026-21726 | 5.3 | Loki Plugin | (see advisory) | (see advisory) | 2026-01-26 | Open redirect bypass in Loki — path traversal bypasses CVE-2021-36156 fix |
| CVE-2025-48371 | 3.1 (High impact) | openfga (dep) | 1.8.0–1.8.12 | >=1.8.13 | 2025-05-20 | OpenFGA authorization bypass — Check/ListObjects with contextual tuples + usersets + public access combinations yield incorrect authorization decisions |
| CVE-2024-11741 | 4.3 | Alerting VictorOps | 10.4.x–11.4.x pre-patch | >=11.5.0, >=11.4.1, >=11.3.3, >=10.4.15 | 2024-12-10 | Info disclosure in VictorOps alerting integration — Viewer permission exposes sensitive integration configuration to non-admins |
| CVE-2025-29923 | ~5.0 | go-redis (dep) | <9.5.5, <9.6.3, <9.7.3 | >=9.7.3 | 2025-03-20 | Out-of-order responses in go-redis — CLIENT SETINFO timeout causes response mismatch, potential data confusion |
| CVE-2025-8341 | 6.1 | Infinity Plugin | (see advisory) | (see advisory) | 2025-08-04 | SSRF in Infinity Plugin — user-controlled URL in Infinity datasource leads to server-side request forgery |

---

## Advisory Inventory — LOW Severity

| CVE ID | CVSS | Component | Affected Versions | Patched Version | Published | Description |
|--------|------|-----------|-------------------|-----------------|-----------|-------------|
| CVE-2026-21727 | 3.3 | Correlations | <12.3.2, <12.2.4, <12.1.6, <12.0.9, <11.6.10 | >=12.3.2 | 2026-01-29 | Cross-tenant legacy correlation exposure — org_id=0 correlations accessible and deletable by other tenants |
| CVE-2026-21725 | 2.6 | Datasource Deletion | <12.4.1 | >=12.4.1 | 2026-02-25 | TOCTOU in datasource deletion — former admin can delete recreated datasource within 30s window; stringent preconditions limit impact |
| CVE-2025-41116 | 2.1 | Databricks Plugin | (see advisory) | (see advisory) | 2025-11-11 | Incorrect OAuth passthrough in Databricks datasource plugin |
| CVE-2025-3717 | 2.1 | Snowflake Plugin | (see advisory) | (see advisory) | 2025-11-11 | Incorrect OAuth passthrough in Snowflake datasource plugin |
| CVE-2025-10630 | 4.3 | Zabbix Plugin | (see advisory) | (see advisory) | 2025-09-19 | Regex DoS in Zabbix plugin |
| CVE-2025-1088 | 2.7 | Core | <11.6.2 | >=11.6.2 | 2025-06-17 | DoS via long dashboard title — causes Chromium unresponsiveness; requires admin privilege |
| CVE-2024-10452 | 2.2 | Invitations | (see advisory) | (see advisory) | 2024-10-28 | Cross-org invitation removal — org admin can remove pending invitations created in orgs they don't belong to |

---

## Go Stdlib / Tracked Advisory IDs (Non-CVE)

| ID | Severity | Package | Patched Via | Commit | PR | Description |
|----|----------|---------|-------------|--------|-----|-------------|
| GO-2026-4602 | Medium | Go stdlib (os.Root) | nanogit v0.7.0 (go 1.25.8) | 4bc3b94077e | #120290 | FileInfo can escape from os.Root sandbox |
| GO-2026-4601 | Medium | Go stdlib (net/url) | nanogit v0.7.0 | 4bc3b94077e | #120290 | Incorrect parsing of IPv6 host literals |
| GO-2026-4600 | Medium | Go stdlib (crypto/x509) | nanogit v0.7.0 | 4bc3b94077e | #120290 | Panic in malformed certificate checking |
| GO-2026-4599 | Medium | Go stdlib (crypto/x509) | nanogit v0.7.0 | 4bc3b94077e | #120290 | Incorrect email constraint enforcement |
| CVE-2026-25536 | Unknown | @grafana/llm | 1.0.3 | 219e4b3907d | #120154 | LLM package vulnerability fixed in v1.0.3 |

---

## Patch Commit Mapping

### CVE-2024-9264: SQL Expressions RCE (CRITICAL 9.4)
- **PR:** #94959 (v11.2.x backport)
- **Related:** ea71201ddc66 (main), 5221584143a (v11.3.x backport — git log present)
- **Fix:** Removed duckdb dependency entirely; disabled SQL Expressions feature to prevent RCE/LFI
- **Root cause:** duckdb CLI invoked with unsanitized user query input

### CVE-2025-3260: Dashboard API AuthZ Bypass (HIGH 8.3)
- **Commits:** 393de2d7c66 (patch version), 5a62f35f5b6 (#116885)
- **Backport commits:** b0865c03739 (11.6.10), 852ced7e016 (12.0.9), 00d95b43e16 (12.1.6), 5b73bf4c34e (12.2.4), df2547decd5 (12.3.2)
- **Fix:** Added missing resource scope UID to permission evaluation on /apis/dashboard.grafana.app/* endpoints

### CVE-2026-21721: Cross-Dashboard Permission Escalation (HIGH 8.1)
- **Commit:** 1fa4fdf0adc
- **Fix:** Added `dashUIDScope`/`dashIDScope` to GET/POST `/permissions` routes; evaluation now scoped to specific dashboard

### CVE-2026-21720: Unauthenticated Avatar Cache DoS (HIGH 7.5)
- **Commit:** 86c2e52464f
- **Fix:** Avatar endpoint requires authentication; goroutine queue removed; timeout enforced

### CVE-2026-21727: Cross-Tenant Legacy Correlation (LOW 3.3)
- **Commit:** e702db6096e
- **Fix:** SQL JOIN changed from `(org_id = 0 OR dss.org_id = org_id)` to strict equality

### CVE-2026-21722: Public Dashboard Timerange Bypass (MEDIUM 5.3)
- **Commits:** e97fa5f587c (main); multiple backports
- **PR:** #117854
- **Fix:** Forces annotation queries to use dashboard's locked timerange when timeSelectionEnabled=false

### CVE-2025-41117: XSS in TraceView (MEDIUM 6.8)
- **Commit:** 8dfa6446942
- **PR:** #117853
- **Fix:** Added DOMPurify sanitization to TraceView stack trace HTML rendering

### CVE-2025-3580: Admin Deletion Escalation (MEDIUM 5.5)
- **Commit:** 5963be6f317
- **PR:** #105976
- **Fix:** DELETE /api/org/users/ now checks if target is a server admin before allowing deletion

### CVE-2024-8118: Alerting Permission Bypass (MEDIUM 5.1)
- **Commit:** c2799b4901d
- **PR:** #93940
- **Fix:** Changed permission on POST external rule groups endpoint from external alert write to alert rules write

### CVE-2025-6197 + CVE-2025-6023: Open Redirect + Scripted Dashboard XSS (MEDIUM+HIGH)
- **Commit:** 4669b586e98
- **PR:** #108330
- **Fix:** Sanitized redirect URL validation in org switching and scripted dashboard execution paths

### CVE-2025-3454: Datasource Proxy Double-Slash (MEDIUM 5.0)
- **Note:** Multiple security releases across branches; fix normalizes URL path before route permission checking

### CVE-2025-48371: OpenFGA Auth Bypass (dep)
- **Commits:** c4c4faff1ee (#106064) and backports to 11.3.8, 11.4.6, 11.5.6, 11.6.3, 12.0.2
- **Fix:** Upgraded openfga to v1.8.13; current go.mod is at v1.11.3

### CVE-2025-30204: JWT Library DoS (dep, HIGH 7.5)
- **Commits:** e862fb3cd78 (#102715), b2605ed2926 (#102727), and other branch backports
- **Fix:** Upgraded golang-jwt/jwt to v4.5.2; current go.mod has v4.5.2

### CVE-2025-29786: expr-lang/expr DoS (dep, HIGH 7.5)
- **Commit:** fef74521e98 (#102533)
- **Fix:** Upgraded expr-lang/expr to v1.17.0

### CVE-2025-29923: go-redis Out-of-Order Responses (dep)
- **Commits:** 797c0850059 (#102865, 11.5), 798a546f242 (#102863, 11.6)
- **Fix:** Upgraded go-redis to 9.6.3/9.7.3

### CVE-2024-45337: golang.org/x/crypto SSH Auth Bypass (dep, CRITICAL 9.1)
- **Commit:** 0a390cc069f (#97823)
- **Fix:** Bumped golang.org/x/crypto to v0.31.0

### CVE-2024-45338: golang.org/x/net HTML DoS (dep, HIGH)
- **Commit:** 5a2344ed0ca (#98340)
- **Fix:** Bumped golang.org/x/net to v0.33.0

### GO-2026-4602/4601/4600/4599: Go Stdlib CVEs (via nanogit)
- **Commit:** 4bc3b94077e (#120290)
- **Fix:** Bumped nanogit to v0.7.0 which uses Go 1.25.8; current go.mod uses nanogit v0.13.0

---

## Vulnerability Timeline

### 2024
| Date | CVE | Severity |
|------|-----|----------|
| 2024-03-07 | CVE-2024-1442 (datasource wildcard privilege escalation) | MEDIUM |
| 2024-03-27 | CVE-2024-1313 (snapshot auth bypass) | MEDIUM |
| 2024-06-26 | CVE-2024-5526 (OnCall SSRF) | HIGH |
| 2024-07-23 | CVE-2024-6322 (plugin datasource access control bypass) | MEDIUM |
| 2024-09-26 | CVE-2024-8118 (alerting permission bypass) | MEDIUM |
| 2024-10-04 | CVE-2024-8975, CVE-2024-8996 (Alloy/Agent privilege escalation) | HIGH, HIGH |
| 2024-10-17 | CVE-2024-9264 (SQL Expressions RCE) | CRITICAL |
| 2024-10-22 | CVE-2024-8986 (Plugin SDK info disclosure) | CRITICAL |
| 2024-10-28 | CVE-2024-10452 (invitation removal cross-org) | LOW |
| 2024-11-12 | CVE-2024-9476 (Cloud Migration privilege escalation) | MEDIUM |
| 2024-12-10 | CVE-2024-11741 (VictorOps info disclosure) | MEDIUM |
| 2024-12-11 | CVE-2024-45337 (golang.org/x/crypto SSH auth bypass), CVE-2024-45338 (golang.org/x/net HTML DoS) | CRITICAL, HIGH |

### 2025
| Date | CVE | Severity |
|------|-----|----------|
| 2025-03-12 | CVE-2025-29786 (expr-lang/expr DoS) | HIGH |
| 2025-03-20 | CVE-2025-29923 (go-redis out-of-order) | MEDIUM |
| 2025-03-21 | CVE-2025-30204 (golang-jwt DoS) | HIGH |
| 2025-04-22 | CVE-2025-3260 (Dashboard API auth bypass), CVE-2025-3454 (proxy double-slash), CVE-2025-2703 (XY Chart XSS) | HIGH, MEDIUM, MEDIUM |
| 2025-05-20 | CVE-2025-48371 (OpenFGA auth bypass) | MEDIUM |
| 2025-05-21 | CVE-2025-4123 (plugin open-redirect XSS) | HIGH |
| 2025-05-22 | CVE-2025-3580 (admin deletion escalation) | MEDIUM |
| 2025-06-13 | CVE-2025-3415 (DingDing info disclosure), CVE-2025-1088 (DoS dashboard titles) | MEDIUM, LOW |
| 2025-07-18 | CVE-2025-6023 (scripted dashboard XSS), CVE-2025-6197 (org switching open redirect) | HIGH, MEDIUM |
| 2025-08-04 | CVE-2025-8341 (Infinity Plugin SSRF) | MEDIUM |
| 2025-09-19 | CVE-2025-10630 (Zabbix Plugin ReDoS) | LOW |
| 2025-10-09 | CVE-2025-11539 (Image Renderer RCE) | CRITICAL |
| 2025-11-11 | CVE-2025-41116 (Databricks OAuth), CVE-2025-3717 (Snowflake OAuth) | LOW, LOW |
| 2025-11-19 | CVE-2025-41115 (SCIM privilege escalation) | CRITICAL |

### 2026
| Date | CVE | Severity |
|------|-----|----------|
| 2026-01-02 | CVE-2025-41118 (Pyroscope storage secret) | CRITICAL |
| 2026-01-26 | CVE-2026-21726 (Loki open redirect bypass) | MEDIUM |
| 2026-01-27 | CVE-2026-21721 (dashboard permission escalation), CVE-2026-21720 (avatar cache DoS), CVE-2026-21727 (cross-tenant correlation) | HIGH, HIGH, LOW |
| 2026-02-12 | CVE-2026-21722 (public dashboard timerange), CVE-2025-41117 (TraceView XSS) | MEDIUM, MEDIUM |
| 2026-02-25 | CVE-2026-21725 (datasource deletion TOCTOU) | LOW |
| 2026-03-16 | CVE-2026-28377 (Tempo S3 key exposure) | HIGH |

---

## CVE Count Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 6 (CVE-2025-41115, CVE-2025-11539, CVE-2024-8986, CVE-2025-41118, CVE-2024-9264, CVE-2024-45337) |
| HIGH | 12 (CVE-2025-3260, CVE-2026-21721, CVE-2025-6023, CVE-2025-4123, CVE-2026-21720, CVE-2026-28377, CVE-2024-8975, CVE-2024-8996, CVE-2024-5526, CVE-2024-45338, CVE-2025-30204, CVE-2025-29786) |
| MEDIUM | 17 |
| LOW | 7 |
| **Total** | **42** |

---

## Highest-Risk Flows for Phase 2 Analysis

### Tier 1 — Prior Audit Confirmed Findings (Residual Bypass Risk)
1. **CVE-2026-21721 + CVE-2025-3260** — Dashboard permission scope binding; other sub-routes likely still missing scope
2. **CVE-2026-21722** — Public dashboard timerange bypass (confirmed H1 in prior audit); residual authenticated bypass at M12
3. **CVE-2025-3454** — Datasource proxy double-slash; other path encoding variants may still work

### Tier 2 — New 2024 CVEs with In-Tree Bypass Potential
4. **CVE-2024-9264** — SQL Expressions RCE; fix removed feature entirely — check if any path still invokes duckdb or SQL expression execution
5. **CVE-2024-8118** — Alerting permission bypass at POST external rule groups; verify fix covers all external alerting endpoints
6. **CVE-2024-1313** — Snapshot auth bypass via DELETE with view key; check if similar pattern exists in other snapshot operations
7. **CVE-2024-1442** — Datasource wildcard UID; verify all UID creation/validation paths reject wildcard characters
8. **CVE-2024-45337** — Go x/crypto SSH auth bypass; check if Grafana uses ServerConfig.PublicKeyCallback in any SSH-enabled datasource or provisioning path

### Tier 3 — New High-Severity Dependency CVEs
9. **CVE-2025-30204** — JWT ParseUnverified DoS; Grafana uses JWT in many auth flows — check all ParseUnverified call sites
10. **CVE-2025-29786** — expr-lang/expr DoS via unbounded input; check if attacker can provide unbounded expressions via API
