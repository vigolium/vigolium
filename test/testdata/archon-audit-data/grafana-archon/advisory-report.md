# Grafana Security Advisory Report
**Repository**: grafana/grafana  
**Commit**: bb41ac0c85d854e32cb19874fb4b3f17163179a8  
**Report Date**: 2026-04-11  
**Analyst**: Advisory Hunter (Phase 1)

---

## Collection Metadata

- **Tier Reached**: Tier 1 (2-year window) was sufficient — 15+ advisories found; supplementary low/medium pass run
- **Historical Coverage**: 2024–2026 primary; all-time data included from OSV/GitHub sources
- **Total Advisories Collected**: 40+ unique first-party Grafana CVEs/GHSAs (focusing last 2 years)
- **Severity Distribution (2024–2026)**:
  - CRITICAL: 4
  - HIGH: 8
  - MEDIUM: 18
  - LOW: 4

---

## Advisory Inventory (2024–2026, All Severity)

### CRITICAL Severity

| ID | GHSA | Published | CVSS | Affected Versions | Patched | CWE | Component | Description |
|----|------|-----------|------|-------------------|---------|-----|-----------|-------------|
| CVE-2024-9264 | GHSA-q99m-qcv4-fpm7 | 2024-10-18 | 9.9 (CVSS:3.1) | 11.0.0–11.2.x | 11.2.2+security-01 | CWE-78/CWE-22 | SQL Expressions (expr/sql) | Command injection and local file inclusion via SQL expressions using DuckDB; arbitrary OS command execution and file reads possible for authenticated users |
| CVE-2025-41115 | GHSA-w62r-7c53-fmc5 | 2025-11-21 | 9.8 (CVSS:3.1) | <12.2.1+security-01 | 12.2.1+security-01 | CWE-266 | SCIM (Enterprise) | Incorrect privilege assignment in SCIM identity provisioning — unauthenticated users could gain elevated roles |
| CVE-2022-39328 | GHSA-vqc4-mpj8-jxch | 2022-11-08 | 9.8 (CVSS:3.1) | All < 9.2.4 | 9.2.4 | CWE-362 | Auth/Session | Race condition in auth token rotation allowing privilege escalation |
| CVE-2022-41912 | GHSA-5hcf-rqj9-xh96 | 2023-01-26 | 8.3 (CVSS:3.1) | <9.3.0 | 9.3.0 | CWE-269 | SAML (Enterprise) | SAML privilege escalation — attacker could gain org-admin with user or viewer role |

### HIGH Severity

| ID | GHSA | Published | CVSS | Affected Versions | Patched | CWE | Component | Description |
|----|------|-----------|------|-------------------|---------|-----|-----------|-------------|
| CVE-2025-6023 | GHSA-vqph-p5vc-g644 | 2025-07-18 | 8.1 (CVSS:3.1) | < 12.0.2+security-01 | 12.0.2+security-01 | CWE-79/CWE-22 | Login/URL handling | XSS attacks through open redirects and path traversal in login/routing logic |
| CVE-2025-4123 | GHSA-q53q-gxq9-mgrj | 2025-05-22 | 8.2 (CVSS:3.1) | < 12.0.0+security-01 | 12.0.0+security-01 | CWE-79 | Plugin frontend loader | XSS via custom loaded frontend plugin — unauthenticated attack vector |
| CVE-2024-9476 | — | 2024-11-12 | ~7.5 | 11.2.x–11.3.x | 11.3.0+security-01 | CWE-unknown | MigrationAssistant | Migration Assistant privilege escalation vulnerability |
| CVE-2024-8118 | — | 2024-09-27 | 7.1 | <11.2.1, <10.4.9, <10.3.8 | Multiple | CWE-862 | Alerting API | Incorrect permission check on POST /api/ruler/grafana/api/v1/rules/{Namespace} — unauthenticated rule modification |
| CVE-2024-6322 | GHSA-hh8p-374f-qgr5 | 2024-08-20 | 7.2 | < 10.4.8, < 11.0.4, < 11.1.2 | Multi-version | CWE-284 | Plugin datasources | Plugin datasource access control bypass — authenticated users could access datasources from other organizations |
| CVE-2025-3260 | GHSA-3px7-c4j3-576r | 2025-06-02 | 8.3 (CVSS:3.1) | < fixes | 12.0+ | CWE-863 | Dashboard/Folder RBAC | Authenticated users could bypass dashboard and folder permission checks |
| CVE-2025-3454 | GHSA-9j65-rv5x-4vrf | 2025-06-02 | 7.7 (CVSS:3.1) | < fixes | 12.0+ | CWE-284 | Datasource Proxy API | Authorization checks bypassable in datasource proxy API; cross-org data exposure |
| CVE-2022-31107 | GHSA-mx47-6497-3fv2 | 2022-07-14 | 7.1 (CVSS:3.1) | <8.3.5, <8.4.3, <8.5.3, <9.0.3 | Multi | CWE-287 | OAuth login | OAuth account takeover — attacker could log in as another user if email matches |

### MEDIUM Severity

| ID | GHSA | Published | CVSS | Affected Versions | Patched | CWE | Component | Description |
|----|------|-----------|------|-------------------|---------|-----|-----------|-------------|
| CVE-2026-27877 | GHSA-3q27-7qjq-p9c5 | 2026-03-27 | 6.5 (CVSS:3.1) | 9.3.0–12.3.x | 12.3.6/12.4.2 | CWE-200 | Public Dashboards | Public dashboards expose all direct-mode datasources in frontend settings — information disclosure |
| CVE-2026-28375 | — | 2026-03-31 | ~6.0 | < 12.4.2 | 12.4.2 | CWE-89/CWE-22 | SQL Expressions | SQL expression engine's allowlist bypassed via INTO clauses enabling file write |
| CVE-2026-27876 | — | 2026-03-31 | 6.5 | < 12.3.6 | 12.3.6/12.4.2 | CWE-200 | Public Dashboards | Public dashboard datasource information disclosure (FrontendSettings API) |
| CVE-2026-27879 | — | 2026-03-31 | ~5.0 | < 12.4.2 | 12.4.2 | CWE-400 | Testdata datasource | Testdata datasource scenario data points unbounded — DoS potential |
| CVE-2026-27880 | — | 2026-03-31 | ~5.0 | < 12.4.2 | 12.4.2 | CWE-400 | Math expressions (Resample) | Resample upsample size unbounded — triggers OOM/DoS in math expression engine |
| CVE-2026-21722 | — | 2026-02-11 | ~6.5 | < 12.3.2+security-01 | 12.3.2+security-01 | CWE-unknown | Unknown (Enterprise) | Enterprise security fix (no public description at time of analysis) |
| CVE-2025-41117 | — | 2026-02-11 | ~6.5 | < 12.3.2+security-01 | 12.3.2+security-01 | CWE-unknown | Unknown (Enterprise?) | Paired with CVE-2026-21722 in same security release |
| CVE-2025-6197 | — | 2025-07-18 | ~6.5 | < 12.0.2+security-01 | 12.0.2+security-01 | CWE-601 | Login/org redirect middleware | Open redirect in login and org redirect flows (paired with CVE-2025-6023) |
| CVE-2025-3580 | — | 2025-05-27 | ~5.5 | < 12.0.1+security-01 | 12.0.1+security-01 | CWE-269 | Org management | Privilege escalation: server admin could be removed from org, affecting admin-only operations; also ShouldDeleteOrphanedUser logic allowed admin deletion |
| CVE-2025-3415 | GHSA-46m5-8hpj-p5p5 | 2025-07-17 | 4.3 (CVSS:3.1) | All versions | 12.0.1+security-01 | CWE-200 | DingDing alert notifier | DingDing alert integration exposes access token in plain text in requests/logs |
| CVE-2025-2703 | — | 2025-03+ | ~5.0 | Unknown | Unknown | CWE-unknown | Unknown | Referenced in CHANGELOG but no public description at analysis time |
| CVE-2025-1088 | GHSA-crvv-6w6h-cv34 | 2025-06-18 | 2.7 (CVSS:3.1) | < fixes | Patched | CWE-400 | Dashboard title/panel rendering | Long dashboard title or panel name causes frontend unresponsiveness (DoS for admins) |
| CVE-2024-11741 | GHSA-wxcc-2f3q-4h58 | 2025-01-31 | 4.3 (CVSS:3.1) | < 11.3.3+security-01 | 11.3.3+security-01 | CWE-200 | Alerting notifiers | VictorOps alerting integration token exposed to Viewer permission users |
| CVE-2024-10452 | GHSA-66c4-2g2v-54qw | 2024-10-29 | 4.3 (CVSS:3.1) | < 10.4.11 | 10.4.11 | CWE-639 | Org management (invites) | Org admin can delete pending invitations from a different organization (IDOR) |
| CVE-2024-6837 | — | 2024-08+ | ~5.0 | Unknown | Patched | CWE-unknown | Unknown component | Referenced in CHANGELOG, exact details not public |
| CVE-2024-1442 | GHSA-5mxf-42f5-j782 | 2024-03-07 | 6.4 (CVSS:3.1) | < 10.2.6 | 10.2.6 | CWE-284 | Datasource API | Users with datasource create permission can CRUD all data sources (broken access control) |
| CVE-2024-1313 | GHSA-67rv-qpw2-6qrr | 2024-04-05 | 6.5 (CVSS:3.1) | < 10.2.3 | 10.2.3 | CWE-639 | Snapshot management | Users outside an org can delete snapshots using the snapshot key (IDOR) |

### LOW Severity / DoS

| ID | GHSA | Published | CVSS | Component | Description |
|----|------|-----------|------|-----------|-------------|
| CVE-2026-33375 | — | 2026-03-25 | ~3.0 | Unknown | Referenced in latest security release; no public description at analysis time |
| CVE-2025-30204 | — | 2025-03+ | ~4.0 | JWT library (golang-jwt) | Dependency CVE — JWT processing vulnerability fixed by upgrading golang-jwt |
| CVE-2025-29923 | — | 2025-03+ | ~5.0 | Redis client (go-redis) | Dependency CVE — redis client vulnerability fixed by upgrade |
| CVE-2025-29786 | — | 2025-03+ | ~5.0 | expr-lang/expr | Dependency CVE — expression evaluator vulnerability fixed by upgrade |

---

## Key Dependency CVEs (Third-Party)

| CVE | Dependency | Fixed In | Severity | Impact |
|-----|-----------|----------|----------|--------|
| CVE-2025-48371 | github.com/openfga/openfga | v1.8.13 | HIGH | OpenFGA authorization engine — auth bypass potential |
| CVE-2024-45338 | golang.org/x/net | v0.33.0 | MEDIUM | HTTP request smuggling in golang.org/x/net/http2 |
| CVE-2024-45337 | golang.org/x/crypto | v0.31.0 | MEDIUM | Misuse of ServerConfig.PublicKeyCallback in go ssh |
| CVE-2025-30204 | github.com/golang-jwt/jwt | v5.2.2 | MEDIUM | JWT algorithm confusion attack |
| CVE-2024-4067 | micromatch (npm) | > 4.0.5 | MEDIUM | ReDoS in micromatch package |
| CVE-2024-22363 | thanos.io deps | Various | MEDIUM | Thanos dependency vulnerability |
| GHSA-9763-4f94-gfch | cloudflare/circl | >1.3.7 | HIGH | Cryptographic library vulnerability |
| CVE-2022-31022 | bleve | Pinned version | MEDIUM | App platform search library path traversal |

---

## Patch Commit Registry

| Commit SHA | CVE(s) | Component | Description |
|-----------|--------|-----------|-------------|
| `0e5d9e01ef3` | CVE-2026-27876, CVE-2026-27877, CVE-2026-28375, CVE-2026-27879, CVE-2026-27880 | Public Dashboards, SQL Expressions, Math Expressions, Testdata | Multi-fix: datasource info disclosure in public dashboards, SQL INTO clause allowlist bypass, Resample DoS cap, testdata data point limit |
| `52a0636bf88` | CVE-2026-33937 (handlebars) | Frontend templating deps | Upgrade handlebars to fix prototype pollution |
| `a05df357dc2` | CVE-2026-27903, CVE-2026-27904 (minimatch) | Frontend build deps | Upgrade minimatch npm package |
| `4bc3b94077e` | Go stdlib CVEs | nanogit dependency | Bump nanogit to v0.7.0 fixing 4 Go stdlib CVEs |
| `219e4b3907d` | CVE-2026-25536 | @grafana/llm | Upgrade LLM plugin to 1.0.3 |
| `8dfa6446942` | (no CVE) | TraceView (Jaeger/Tempo) | Sanitize HTML in SpanDetail/KeyValuesTable — XSS prevention |
| `e97fa5f587c` | (no CVE assigned publicly) | Public Dashboards service | Enforce dashboard timerange when time selection disabled on public dashboards |
| `4669b586e98` | CVE-2025-6197, CVE-2025-6023 | Login, Org redirect middleware | Fix open redirect XSS via login.go and org_redirect.go path handling |
| `c4c4faff1ee` | CVE-2025-48371 | openfga dependency | Bump openfga to v1.8.13 |
| `5963be6f317` | CVE-2025-3580 | Org management (orgimpl/store.go) | Fix privilege escalation via org store user deletion logic; protect IsAdmin users |
| `e862fb3cd78` | CVE-2025-30204 | golang-jwt/jwt dependency | Upgrade JWT library |
| `bff75e15616` | CVE (undici) | Frontend/Node fetch | Upgrade undici npm package |
| `c2799b4901d` | CVE-2024-8118 | Alerting API (ngalert/api/authorization.go) | Fix incorrect permission on alerting rule group POST endpoint |
| `ea71201ddc6` | CVE-2024-9264 | SQL Expressions (expr/reader.go, go.mod) | Disable SQL expressions (DuckDB) entirely to prevent RCE/LFI |
| `5a2344ed0ca` | CVE-2024-45338 | golang.org/x/net | Bump net to v0.33.0 |
| `0a390cc069f` | CVE-2024-45337 | golang.org/x/crypto | Bump crypto to v0.31.0 |
| `f1ba609b348` | CVE-2024-4067 | micromatch (npm) | Upgrade micromatch |
| `709d78b8b51` | CVE-2024-22363 | thanos/prometheus deps | Fix dependency vulnerability |
| `a8dec1916bb` | GHSA-9763-4f94-gfch | cloudflare/circl | Upgrade circl cryptographic library |
| `7bba1514166` | axios CVE | axios (npm) | Upgrade axios to fix known CVE |
| `9b3b6fcdb23` | (no CVE) | Dependabot GitHub Actions workflow | Fix actor spoofing vulnerability in CI workflow |
| `2c404dcae67` | (no CVE) | Provisioning file operations | Fix authorization security issues in provisioning file ops |
| `5b9265ee475` | (no CVE) | Unified storage auth | Check auth before value retrieval |
| `ccaa3642403` | (multiple) | go-mysql-server fork | Sync with upstream including security fixes, disable CGo |

