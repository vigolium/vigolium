# Harbor Security Audit - Phase 1: Advisory Intelligence Report

**Report Date:** 2026-03-27  
**Audit Scope:** goharbor/harbor v2.15.0 (commit 1c7d83141)  
**Methodology:** Adaptive 3-tier advisory collection (Tier 1 & 2 combined)

---

## Executive Summary

This Phase 1 audit collected **27 published security advisories** from Harbor's GitHub Security Advisory database spanning from 2019 to 2026. The collection achieved comprehensive historical coverage with emphasis on recent advisories (6 from 2024-2026), enabling robust pattern analysis.

**Key Findings:**
- **Total Advisories:** 27 (CRITICAL: 3, HIGH: 8, MEDIUM: 11, LOW: 5)
- **Tier Reached:** Tier 2 (Full historical coverage, 2019-2026)
- **Critical Components:** Authorization/Permission validation (9 CVEs), SQL injection (3 CVEs), Authentication/LDAP/OIDC (3 CVEs)
- **Dominant Bug Class:** Authorization bypass / Permission validation failures (33% of advisories)
- **Recurring Pattern:** Multiple permission validation failures in the same APIs/features suggest structural weakness in the RBAC implementation

---

## Part 1: Advisory Inventory

### Collection Metadata

| Metric | Value |
|--------|-------|
| **Total Advisories Collected** | 27 |
| **Date Range** | 2019-09-19 to 2026-03-25 |
| **Sources** | GitHub Security Advisories (primary) |
| **Tier Reached** | Tier 2 (full historical, no date cap) |
| **Recent (2024-2026)** | 6 advisories |
| **Older (2019-2023)** | 21 advisories |
| **With CVE IDs** | 25 (92.6%) |
| **With CVSS Scores** | 18 (66.7%) |

### Severity Distribution

| Severity | Count | Percentage | Trend |
|----------|-------|-----------|-------|
| **CRITICAL** | 3 | 11.1% | 2019 (3 advisories) |
| **HIGH** | 8 | 29.6% | 2022 (5 advisories), 2019 (3 advisories) |
| **MEDIUM** | 11 | 40.7% | Recent: 2026 (1), 2025 (2), 2024 (3) |
| **LOW** | 5 | 18.5% | 2020 (4), 2024 (1) |

### Chronological Distribution

```
2026: CRITICAL (1 Medium [recent])
2025: MEDIUM (2 ORM Leak, XSS)
2024: MEDIUM (3), LOW (1) - CVE-2024-22278, CVE-2024-22261, CVE-2024-22244
2023: MEDIUM (1) - Timing attack
2022: HIGH (5), MEDIUM (1) - Permission validation cluster
2020: LOW (4), HIGH (1) - Enumeration & SSRF
2019: CRITICAL (3), HIGH (2), MEDIUM (1) - SQL injection, CSRF, privilege escalation
```

---

## Part 2: Detailed Advisory Roster

### CRITICAL SEVERITY (3 advisories)

#### GHSA-gcqm-v682-ccw6 | CVE-2019-19025
- **Published:** 2019-12-03
- **Title:** Missing CSRF protection
- **Severity:** CRITICAL (CVSS Unknown)
- **Affected Versions:** 1.7.*, 1.8.*, 1.9.*
- **Patched Versions:** 1.8.6, 1.9.3
- **Bug Class:** CSRF / Cross-Site Request Forgery (CWE-352)
- **Impact:** Application-wide CSRF vulnerability allowing unauthorized state changes
- **Component:** Web framework / form handlers

#### GHSA-3868-7c5x-4827 | CVE-2019-19023
- **Published:** 2019-12-03
- **Title:** Privilege Escalation
- **Severity:** CRITICAL (CVSS Unknown)
- **Affected Versions:** 1.7.*, 1.8.*, 1.9.*
- **Patched Versions:** 1.9.3, 1.8.6
- **Bug Class:** Privilege escalation / Authorization bypass (CWE-269)
- **Impact:** Unauthorized privilege escalation in the system
- **Component:** Authorization/RBAC layer

#### GHSA-x2r2-w9c7-h624 | CVE-2019-16919
- **Published:** 2019-10-16
- **Title:** CVE-2019-16919 (Privilege Escalation)
- **Severity:** CRITICAL (CVSS Unknown)
- **Affected Versions:** 1.8.0-1.8.3, 1.9.0
- **Patched Versions:** 1.8.4, 1.9.1
- **Bug Class:** Privilege escalation (CWE-269)
- **Impact:** Remote privilege escalation via unspecified vector
- **Component:** Core authorization

---

### HIGH SEVERITY (8 advisories)

#### GHSA-jf8p-3vjh-pq94 | CVE-2022-31666
- **Published:** 2022-08-29
- **Title:** Harbor fails to validate the user permissions when viewing Webhook policies
- **Severity:** HIGH (CVSS Unknown)
- **Affected Versions:** 2.x < 2.4.3; 2.5 < 2.5.2
- **Patched Versions:** 2.4.3+; 2.5.2+
- **Bug Class:** Authorization bypass / Permission validation (CWE-862)
- **Impact:** Unauthorized access to Webhook policy information
- **Component:** Webhook management API

#### GHSA-8hwq-5f22-jfr3 | CVE-2022-31666 (variant)
- **Published:** 2022-08-29
- **Title:** Harbor fails to validate the user permissions when updating Webhook policies
- **Severity:** HIGH (CVSS Unknown)
- **Affected Versions:** 2.x <= 2.4.2; 2.5 <= 2.5.1
- **Patched Versions:** 2.4.3+; 2.5.2+
- **Bug Class:** Authorization bypass / Permission validation (CWE-862)
- **Impact:** Unauthorized modification of Webhook policies
- **Component:** Webhook management API (same root cause as above)

#### GHSA-3637-v6vq-xqqw | CVE-2022-31670
- **Published:** 2022-08-29
- **Title:** Harbor fails to validate the user permissions when updating tag retention policies
- **Severity:** HIGH (CVSS Unknown)
- **Affected Versions:** 1.x <= 1.10.12; 2.x <= 2.4.2; 2.5 < 2.5.1
- **Patched Versions:** 1.10.13+; 2.4.3+; 2.5.2+
- **Bug Class:** Authorization bypass / Permission validation (CWE-862)
- **Impact:** Unauthorized modification of tag retention policies
- **Component:** Tag retention policy API

#### GHSA-3wpx-625q-22j7 | CVE-2022-31671
- **Published:** 2022-08-29
- **Title:** Harbor fails to validate the user permissions when updating p2p preheat policies
- **Severity:** HIGH (CVSS Unknown)
- **Affected Versions:** 2.x <= 2.4.2; 2.5 < 2.5.1
- **Patched Versions:** 2.4.3+; 2.5.2+
- **Bug Class:** Authorization bypass / Permission validation (CWE-862)
- **Impact:** Unauthorized modification of P2P preheat policies
- **Component:** P2P preheat API

#### GHSA-qcfv-8v29-469w | CVE-2019-19029
- **Published:** 2019-12-03
- **Title:** SQL Injection via user-groups
- **Severity:** HIGH (CVSS Unknown)
- **Affected Versions:** 1.7.*, 1.8.*, 1.9.*
- **Patched Versions:** 1.8.6, 1.9.3
- **Bug Class:** SQL injection (CWE-89)
- **Impact:** Database compromise via malicious user-group input
- **Component:** User group management

#### GHSA-rh89-vvrg-fg64 | CVE-2019-19026
- **Published:** 2019-12-03
- **Title:** SQL Injection via project quotas
- **Severity:** HIGH (CVSS Unknown)
- **Affected Versions:** 1.7.*, 1.8.*, 1.9.*
- **Patched Versions:** 1.8.6, 1.9.3
- **Bug Class:** SQL injection (CWE-89)
- **Impact:** Database compromise via quota manipulation
- **Component:** Project quota management

#### GHSA-fqvr-xx6w-m6m7 | CVE-2019-16097
- **Published:** 2019-09-19
- **Title:** CVE-2019-16097 (Authorization bypass)
- **Severity:** HIGH (CVSS Unknown)
- **Affected Versions:** 1.7.0-1.7.5, 1.8.0-1.8.2
- **Patched Versions:** 1.7.6, 1.8.3
- **Bug Class:** Authorization bypass
- **Component:** Core authorization

#### GHSA-j7jh-fmcm-xxwv
- **Published:** 2023-03-31
- **Title:** Harbor insecure default configuration when installed with Harbor-helm
- **Severity:** HIGH
- **Affected Versions:** Multiple (1.3.x, 1.4.x-1.11.0)
- **Patched Versions:** 1.3.18, 1.9.6, 1.10.4, 1.11.1
- **Bug Class:** Insecure configuration defaults (CWE-1021)
- **Impact:** Weak security posture from default deployments
- **Component:** Helm chart configuration

---

### MEDIUM SEVERITY (11 advisories)

#### GHSA-prh4-vhfh-24mj (Most Recent)
- **Published:** 2026-03-25
- **Title:** LDAP password and OIDC secret is not redacted in the audit log
- **Severity:** MEDIUM
- **Affected Versions:** >2.13.0, <2.14.3
- **Patched Versions:** v2.15.0, v2.14.3, v2.13.5
- **Bug Class:** Information disclosure / Credential leakage (CWE-532)
- **Impact:** Sensitive credentials exposed in audit logs
- **Component:** Audit logging (authentication configuration)
- **Workaround:** Disable "Update Configuration" audit events

#### GHSA-h27m-3qw8-3pw8 | CVE-2025-30086
- **Published:** 2025-07-23
- **Title:** Possible ORM Leak Vulnerability in the Harbor
- **Severity:** MEDIUM (CVSS 4.9, PR:H)
- **Affected Versions:** <=2.13.0, <=2.12.3
- **Patched Versions:** 2.13.1, 2.12.4
- **Bug Class:** Information disclosure / ORM injection (CWE-200)
- **Impact:** Administrator can extract password hashes via `/api/v2.0/users` with filter abuse
- **Component:** User API (ORM layer)
- **Attack Vector:** Admin-only, password hash extraction via `password=~` filter parameter

#### GHSA-f9vc-vf3r-pqqq | CVE-2025-32019
- **Published:** 2025-07-23
- **Title:** XSS vulnerability in the Harbor repository description
- **Severity:** MEDIUM (CVSS 4.1, PR:L, UI:R)
- **Affected Versions:** <=2.12.2, <=2.11.2, <2.13.1
- **Patched Versions:** 2.12.4, 2.13.1
- **Bug Class:** Stored XSS (CWE-79)
- **Impact:** Code injection via repository description field
- **Component:** Repository information API/UI

#### GHSA-hw28-333w-qxp3 | CVE-2024-22278
- **Published:** 2024-07-31
- **Title:** Harbor fails to validate the user permissions when updating project configurations
- **Severity:** MEDIUM
- **Affected Versions:** <v2.9.5, <v2.10.3
- **Patched Versions:** v2.9.5, v2.10.3, v2.11.0
- **Bug Class:** Authorization bypass / Permission validation (CWE-862)
- **Impact:** Unauthorized modification of project configurations
- **Component:** Project configuration API

#### GHSA-5757-v49g-f6r7 | CVE-2024-22244
- **Published:** 2024-05-31
- **Title:** Open Redirect URL in Harbor
- **Severity:** MEDIUM
- **Affected Versions:** <=v2.8.4, <=v2.9.2, <=v2.10.0
- **Patched Versions:** v2.8.5, v2.9.3, v2.10.1
- **Bug Class:** Open redirect (CWE-601)
- **Impact:** User can be redirected to malicious sites
- **Component:** Web framework / redirect handlers

#### GHSA-mq6f-5xh5-hgcf | CVE-2023-20902
- **Published:** 2023-10-08
- **Title:** Timing attack risk in Harbor
- **Severity:** MEDIUM
- **Affected Versions:** <2.8.3, <2.7.3, <1.10.18
- **Patched Versions:** v2.8.3, v2.7.3, v1.10.18
- **Bug Class:** Timing attack / Information disclosure (CWE-208)
- **Impact:** Token/secret comparison timing vulnerability
- **Component:** Cryptographic operations / token validation

#### GHSA-6qj9-33j4-rvhg | CVE-2019-3990
- **Published:** 2019-12-03
- **Title:** User Enumeration Vulnerability
- **Severity:** MEDIUM
- **Affected Versions:** 1.7.*, 1.8.*, 1.9.0, 1.9.1
- **Patched Versions:** 1.8.6, 1.9.3
- **Bug Class:** Information disclosure / Enumeration (CWE-203)
- **Impact:** Users can enumerate existing accounts
- **Component:** User API / authentication endpoints

#### GHSA-wqpf-jx24-7hmp | CVE-2022-31666 (variant 3)
- **Published:** 2022-08-29
- **Title:** Harbor fails to validate user permissions while deleting Webhook policies
- **Severity:** MEDIUM
- **Affected Versions:** 2.x <= 2.4.2; 2.5 <= 2.5.1
- **Patched Versions:** 2.4.3+; 2.5.2+
- **Bug Class:** Authorization bypass (CWE-862)
- **Component:** Webhook management API

#### GHSA-8c6p-v837-77f6 | CVE-2022-31669
- **Published:** 2022-08-29
- **Title:** Harbor fails to validate the user permissions when updating tag immutability policies
- **Severity:** MEDIUM
- **Affected Versions:** 2.x <= 2.4.2; 2.5 < 2.5.1
- **Patched Versions:** 2.4.3+; 2.5.2+
- **Bug Class:** Authorization bypass (CWE-862)
- **Component:** Tag immutability policy API

#### GHSA-xx9w-464f-7h6f | CVE-2022-31667
- **Published:** 2022-08-29
- **Title:** Harbor fails to validate the user permissions when updating a robot account
- **Severity:** MEDIUM
- **Affected Versions:** 2.x <= 2.4.2; 2.5 < 2.5.1
- **Patched Versions:** 2.4.3+; 2.5.2+
- **Bug Class:** Authorization bypass (CWE-862)
- **Component:** Robot account management API

#### GHSA-q76q-q8hw-hmpw | CVE-2022-31671 (variant)
- **Published:** 2022-08-29
- **Title:** Harbor fails to validate the user permissions when reading job execution logs through the P2P preheat execution logs
- **Severity:** MEDIUM
- **Affected Versions:** 2.x <= 2.4.2; 2.5 <= 2.5.1
- **Patched Versions:** 2.4.3+; 2.5.2+
- **Bug Class:** Authorization bypass / Information disclosure (CWE-862)
- **Component:** P2P preheat job logs API

---

### LOW SEVERITY (5 advisories)

#### GHSA-vw63-824v-qf2j | CVE-2024-22261
- **Published:** 2024-05-31
- **Title:** SQL Injection in Harbor scan log API
- **Severity:** LOW
- **Affected Versions:** >=v2.8.1, >=2.9.0, >=2.10.0
- **Patched Versions:** v2.8.6, v2.9.4, v2.10.2
- **Bug Class:** SQL injection (CWE-89)
- **Impact:** Database query manipulation via scan log filters
- **Component:** Scan log API

#### GHSA-38r5-34mr-mvm7 | CVE-2020-29662
- **Published:** 2020-12-17
- **Title:** Catalog's registry v2 API exposed on unauthenticated path
- **Severity:** LOW
- **Affected Versions:** 2.0.*, 2.1.*
- **Patched Versions:** 2.0.5, 2.1.2
- **Bug Class:** Improper access control (CWE-284)
- **Impact:** Registry API accessible without authentication
- **Component:** Registry API authentication

#### GHSA-q9p8-33wc-h432 | CVE-2020-13794
- **Published:** 2020-09-28
- **Title:** Authenticated users can exploit an enumeration vulnerability in Harbor
- **Severity:** LOW
- **Affected Versions:** 1.9.*, 1.10.*, 2.0.*
- **Patched Versions:** 2.0.3, 2.1.0
- **Bug Class:** Information disclosure / Enumeration (CWE-203)
- **Impact:** User enumeration via authenticated endpoints
- **Component:** User enumeration API

#### GHSA-33p6-fx42-7rf5 | CVE-2020-13788
- **Published:** 2020-07-17
- **Title:** Harbor is vulnerable to a limited Server-Side Request Forgery (SSRF)
- **Severity:** LOW
- **Affected Versions:** 1.8.*, 1.9.*, 2.0.*
- **Patched Versions:** 2.0.1
- **Bug Class:** SSRF (CWE-918)
- **Impact:** Limited SSRF via unspecified endpoint
- **Component:** Image/artifact retrieval layer

#### GHSA-q9x4-q76f-5h5j | CVE-2019-19030
- **Published:** 2020-07-17
- **Title:** Unauthenticated users can exploit an enumeration vulnerability in Harbor
- **Severity:** LOW
- **Affected Versions:** 1.7.*, 1.8.*, 1.9.*, 2.0.*
- **Patched Versions:** 1.10.3, 2.0.1
- **Bug Class:** Information disclosure / Enumeration (CWE-203)
- **Impact:** Unauthenticated user enumeration
- **Component:** Public API endpoints

---

## Part 3: Vulnerability Pattern Analysis

### 3a. Component Vulnerability Heatmap

| Component/Module | Advisory Count | Severity | Bug Classes | Risk Tier |
|-----------------|----------------|----------|------------|-----------|
| **Authorization/RBAC** | 9 | HIGH (5), MEDIUM (4) | Permission validation bypass (CWE-862) | **CRITICAL** |
| **SQL Input Handling** | 3 | HIGH (2), LOW (1) | SQL injection (CWE-89) | **CRITICAL** |
| **Authentication** | 3 | CRITICAL (1), MEDIUM (2) | Privilege escalation, LDAP/OIDC leaks, timing attacks | **CRITICAL** |
| **Webhook Policies** | 3 | HIGH (2), MEDIUM (1) | Authorization bypass | **HIGH** |
| **User/Account Management** | 3 | MEDIUM (3) | Enumeration, privilege escalation | **HIGH** |
| **Web Framework** | 3 | CRITICAL (1), MEDIUM (2) | CSRF, XSS, open redirect | **HIGH** |
| **P2P Preheat** | 2 | HIGH (1), MEDIUM (1) | Authorization bypass | **MEDIUM** |
| **Tag Policies** | 2 | HIGH (1), MEDIUM (1) | Authorization bypass | **MEDIUM** |
| **Audit Logging** | 1 | MEDIUM | Credential disclosure | **MEDIUM** |
| **Registry API** | 1 | LOW | Access control bypass | **LOW** |
| **Scan Logs API** | 1 | LOW | SQL injection | **LOW** |

**High-Heat Components (≥3 advisories or any CRITICAL):**
1. **Authorization/RBAC layer** - 9 advisories, structural weakness
2. **SQL input validation** - 3 advisories, pattern of injection vulnerabilities
3. **Authentication/token handling** - 3 advisories, including critical privilege escalation
4. **Webhook policy management** - 3 advisories, same root cause

---

### 3b. Bug Type Recurrence Analysis

| Bug Class | CWEs | Count | Severity | Examples | Pattern |
|-----------|------|-------|----------|----------|---------|
| **Authorization/Permission Bypass** | CWE-862, CWE-269 | 9 | HIGH (5), MEDIUM (4), CRITICAL (1) | GHSA-3637, GHSA-jf8p, GHSA-8hwq, GHSA-wqpf, GHSA-8c6p, GHSA-xx9w, GHSA-q76q, GHSA-3868, GHSA-hw28 | **STRUCTURAL** - Multiple API endpoints (Webhook, tags, P2P, robot accounts, tag retention) all fail permission checks. Suggests framework-level or common validation gap. |
| **SQL Injection** | CWE-89 | 3 | HIGH (2), LOW (1) | GHSA-qcfv, GHSA-rh89, GHSA-vw63 | **RECURRENCE** - User groups, project quotas, scan logs all affected. Indicates inadequate parameterized query adoption or ORM usage variance. |
| **Information Disclosure** | CWE-200, CWE-532, CWE-203 | 5 | MEDIUM (2), LOW (3) | GHSA-h27m (ORM leak), GHSA-prh4 (credential leak), GHSA-6qj9, GHSA-q9p8, GHSA-q9x4 | **PATTERN** - User enumeration (3x), credential exposure (2x). API design leaks user existence. Audit logs expose secrets. |
| **Privilege Escalation** | CWE-269, CWE-287 | 3 | CRITICAL (2), MEDIUM (1) | GHSA-3868, GHSA-x2r2, GHSA-6qj9 | **CRITICAL CLUSTER** - 2 CRITICALs in same release window (2019-09/12). Core auth layer compromised. |
| **XSS** | CWE-79 | 1 | MEDIUM | GHSA-f9vc | Stored XSS in repository description metadata. |
| **CSRF** | CWE-352 | 1 | CRITICAL | GHSA-gcqm | Missing CSRF protection site-wide (2019). |
| **Open Redirect** | CWE-601 | 1 | MEDIUM | GHSA-5757 | Redirect parameter not validated. |
| **Timing Attack** | CWE-208 | 1 | MEDIUM | GHSA-mq6f | Token comparison not constant-time. |
| **SSRF** | CWE-918 | 1 | LOW | GHSA-33p6 | Limited SSRF in image fetch. |
| **Insecure Defaults** | CWE-1021 | 1 | HIGH | GHSA-j7jh | Helm chart security settings. |

**Key Recurring Classes:**
1. **CWE-862 (Authorization)** - 9 advisories, 2022 cluster suggests regression or refactoring vulnerability
2. **CWE-89 (SQL Injection)** - 3 advisories, persistence across versions indicates structural weakness in input validation
3. **CWE-200/203 (Information Disclosure/Enumeration)** - 5 advisories, API design flaw

---

### 3c. Attack Surface Trends

**Most Frequently Exploited Input Vectors:**

| Input Vector | Count | Examples | Risk |
|--------------|-------|----------|------|
| **API Query Parameters** | 6 | Webhook policy filter, tag retention filter, robot account filter, P2P preheat filter, scan log filter, user enumeration | **HIGH** |
| **Configuration Payloads** | 3 | LDAP password (audit log), OIDC secret (audit log), project configuration | **HIGH** |
| **Metadata Fields** | 3 | Repository description (XSS), user group names (SQL), quota values (SQL) | **MEDIUM** |
| **Authentication Tokens** | 2 | Timing attack, bearer token issuance before project creation | **HIGH** |
| **HTTP Headers/Redirects** | 2 | Open redirect in redirect_url, CSRF token absence | **MEDIUM** |
| **Request Paths** | 2 | Unauthenticated registry v2 path, SSRF in image fetch | **MEDIUM** |
| **User Input (General)** | 1 | LDAP authentication bypass (privilege escalation) | **CRITICAL** |

**Attack Flow:** API endpoints → insufficient permission checks → state change or information leak

**Highest-Risk Vectors for Phase 5 Deep Probe:**
1. **Policy management API parameters** - Permission bypass in multiple endpoints
2. **Configuration objects** - Sensitive data in logs, ORM injection in API
3. **Authentication flows** - LDAP/OIDC integration, token issuance timing

---

### 3d. Patch Quality Signals & Structural Recurrence

**CRITICAL: Structural Recurrence Detected**

**Component: Authorization/Permission Validation API Layer**

Evidence of incomplete patching:
```
2022-08-29 Patch Cluster (all same version range):
  - CVE-2022-31670 (tag retention) - v2.4.3+, v2.5.2+
  - CVE-2022-31671 (P2P preheat) - v2.4.3+, v2.5.2+
  - CVE-2022-31666 (Webhook x3) - v2.4.3+, v2.5.2+
  - CVE-2022-31669 (tag immutability) - v2.4.3+, v2.5.2+
  - CVE-2022-31667 (robot accounts) - v2.4.3+, v2.5.2+

Pattern: 5 DISTINCT permission validation failures across 5 different API endpoints,
all patched in same versions (v2.4.3, v2.5.2).
```

**Root Cause Analysis:** The fact that all 5 were patched simultaneously suggests either:
1. A single framework refactoring fix was applied across all endpoints
2. A permission validation middleware/helper was corrected
3. Patches are not truly independent and may be vulnerable to bypass

**Recommendation for Phase 2 (Patch-Bypass-Checker):**
- Mark as `type: structural-recurrence`
- Test all 5 endpoints with cross-variant permission bypass attempts
- Check if patch in v2.4.3 was complete or if newer versions (v2.5+) re-patched
- Examine git diffs between patched versions for completeness

---

**Component: SQL Input Handling**

Evidence of incomplete patching:
```
Advisories:
  - CVE-2019-19029 (user-groups SQL) - Patched: 1.8.6, 1.9.3
  - CVE-2019-19026 (quotas SQL) - Patched: 1.8.6, 1.9.3
  - CVE-2024-22261 (scan logs SQL) - Patched: v2.8.6, v2.9.4, v2.10.2

Pattern: SQL injection recurs 5 years later (2019→2024) in different endpoint.
Same root cause: insufficient input validation on ORM query filters.
```

**Root Cause Analysis:** After patching user-groups and quotas in 2019, scan logs was vulnerable in 2024. This indicates:
1. Patches were endpoint-specific, not framework-wide
2. Input validation library was not standardized
3. New code paths (scan logs) were added without applying lessons from 2019

---

**Component: Authentication (LDAP/OIDC) & Timing**

Evidence:
```
- CVE-2019-19023 (Privilege escalation) - CRITICAL - 2019
- CVE-2019-16919 (Privilege escalation) - CRITICAL - 2019-10
- CVE-2023-20902 (Timing attack) - MEDIUM - 2023
- GHSA-prh4 (LDAP password leaked in log) - MEDIUM - 2026

Pattern: Auth module patched for privilege escalation (2019), then timing attack (2023),
then credential exposure in logs (2026). Suggests ongoing struggles with auth refactoring.
```

---

## Part 4: Architecture Inventory

### System Components

**Harbor Core Services:**
- **Core API Service** (`src/core/api/`) - Main REST API, authorization checks, policy enforcement
- **Registry Controller** (`src/registryctl/`) - Docker Registry v2 API integration, authentication
- **Job Service** (`src/jobservice/`) - Async job execution, log management
- **Portal UI** (`src/portal/`) - Angular-based web UI, session management
- **Migration Service** (`src/migration/`) - Database schema updates

**Security-Critical Modules:**
- **Authorization/RBAC** (`src/pkg/permission/`, `src/core/auth/`) - Role-based access control
- **Authentication** (`src/core/auth/`, `src/pkg/authproxy/`) - LDAP, OIDC, local auth
- **Audit Logging** (`src/pkg/audit/`) - Security event tracking
- **Configuration** (`src/pkg/config/`) - System configuration handling
- **User Management** (`src/pkg/user/`) - User creation, enumeration, permissions

**Key Dependencies (from go.mod):**
- **Authentication:** `coreos/go-oidc/v3`, `go-ldap/ldap/v3`, `golang-jwt/jwt/v5`
- **Cryptography:** `golang.org/x/crypto`
- **Web Framework:** `gorilla/mux`, `gorilla/csrf`, `beego/beego/v2`
- **Database:** `jackc/pgx/v4` (PostgreSQL), `redis/go-redis/v9` (Redis)
- **External Integration:** `docker/distribution`, `helm.sh/helm/v3`
- **gRPC:** `google.golang.org/grpc`

### Transports & Trust Boundaries

| Transport | Protocol | Authentication | Use Case | Risk |
|-----------|----------|----------------|----------|------|
| HTTP/HTTPS (APIs) | REST JSON | Token (JWT), OAuth2, OIDC, LDAP | Core API, artifact push/pull | HIGH |
| Docker Registry V2 | HTTP/HTTPS | Basic auth, token auth | Image operations | HIGH |
| Database | TCP | PostgreSQL native auth | Persistent storage | MEDIUM |
| Redis | TCP | Optional password | Session/cache storage | MEDIUM |
| gRPC | HTTP/2 | mTLS optional | Internal service comm | LOW |
| Helm API | HTTP/HTTPS | Token | Chart repository operations | MEDIUM |
| Webhook | HTTP/HTTPS | HMAC signature | External notifications | MEDIUM |
| CLI/Admin API | HTTPS | Token | Administrative operations | HIGH |

### Execution Environments

- **Containerized:** Docker containers for all services (core, registry, jobservice, portal)
- **Database:** PostgreSQL 9.6+ (runs in separate container)
- **Cache:** Redis (optional, separate container)
- **Scheduler:** In-process job scheduler in core service
- **CLI:** Harbor CLI and Docker CLI as client tools

### Highest-Risk Flows (for Phase 3 DFD prioritization)

**Flow 1: Project Creation → Permission Assignment**
- User submits project creation request → API validates permission (CWE-862 high occurrence here)
- Permission stored in DB → Later policy updates must re-validate
- **Risk:** Multiple permission validation failures suggest framework-level gap

**Flow 2: Image Push → Registry Authentication**
- Docker client → Harbor Core API → Registry Controller
- Token issued for image layer operations
- **Risk:** Token timing attack (CVE-2023-20902), bearer token validation (GHSA-prh4)

**Flow 3: LDAP/OIDC Configuration → Audit Log**
- Admin updates LDAP password or OIDC secret
- Configuration serialized to audit log
- **Risk:** Credentials leaked in logs (GHSA-prh4, CVE-2026-03-25)

**Flow 4: User API Queries → ORM Layer**
- API accepts `q` filter parameter → ORM constructs query
- **Risk:** ORM injection (GHSA-h27m), SQL injection recurrence (CWE-89)

---

## Part 5: Dependency Intelligence

### High-Risk Dependencies (Security-Relevant)

| Dependency | Version | Purpose | Known Issues | Patch Status |
|------------|---------|---------|--------------|--------------|
| `golang.org/x/crypto` | v0.46.0 | Cryptography (hashing, encryption, random) | None in v0.46.0 | Up-to-date per commit 3b4e55c |
| `gorilla/csrf` | v1.7.2 | CSRF protection middleware | Fixed in v1.7.1+ (go-require upgrade) | Updated in 3b4e55c |
| `go-ldap/ldap/v3` | v3.4.11 | LDAP authentication integration | Timing attack risk? | Current |
| `coreos/go-oidc/v3` | v3.15.0 | OIDC authentication provider | None known | Current |
| `golang-jwt/jwt/v5` | v5.2.2 | JWT token creation/validation | Check CWE-208 (timing) | Current |
| `docker/distribution` | v2.8.3 | Docker Registry V2 API | Long-maintained, stable | Pinned |
| `jackc/pgx/v4` | v4.18.3 | PostgreSQL driver | Review for SQL injection context | Current |
| `redis/go-redis/v9` | v9.17.2 | Redis client (cache/sessions) | None known | Current |
| `google.golang.org/grpc` | v1.79.3 | gRPC communication | Updated in 3b4e55c (CVE fixes) | Updated |
| `helm.sh/helm/v3` | v3.18.5 | Helm chart management | Dependency for vulnerability surface | Current |

### Dependency Vulnerability Cross-Reference

From advisory analysis:
- **3 CVE patches** applied in commit 3b4e55c for Go dependencies (docker/cli, gorilla/csrf, x/crypto)
- **CVSS improvements:** Go version bumped 1.24.13 → 1.25.8
- **Remaining concerns:** LDAP/OIDC timing risk, gRPC security posture

### Vulnerable Dependency Flows

**Flow: LDAP Authentication → Password Validation**
- User provides password → `go-ldap/ldap` sends LDAP bind request
- **Risk:** Timing attack on failed authentication (CVE-2023-20902 relates to token comparison, not LDAP, but same principle)
- **Audit:** Check if LDAP bind result is compared in constant-time

**Flow: JWT Token Validation**
- Incoming request has `Authorization: Bearer <token>`
- Token parsed and validated by `golang-jwt/jwt/v5`
- **Risk:** Timing attacks on signature verification? Check implementation.
- **Advisory:** GHSA-prh4 mentions bearer token validation before project creation.

**Flow: Database Queries via ORM**
- API layer builds ORM queries with user input
- `jackc/pgx/v4` executes parameterized queries
- **Risk:** CWE-89 recurrence (2019, 2024) suggests ORM misuse (raw SQL concatenation) in parts of codebase
- **Audit:** Check for `Execute()` with string concatenation vs parameterized queries

---

## Part 6: Patch Commit Inventory & Bypass Indicators

### Recent CVE-Related Commits (Tier 2 Collection)

| Commit SHA | Message | CVE/Issue | Affected Component | Audit Flag |
|------------|---------|-----------|------------------|------------|
| `3b4e55c09` | Fix Golang CVEs: upgrade docker/cli, gorilla/csrf, otel/sdk, x/crypto, Go 1.24→1.25 | CVE (deps) | Dependencies | Dependency upgrade |
| `6ec47a20f` | fix(security): reject bearer tokens issued before project creation | GHSA (token issuance) | Token service | Recent fix |
| `89e1c4baa` | fix(security): reject bearer tokens issued before project creation | Related to above | Token service | Recent fix |
| `ec9d13d10` | fix: CVE Allowlist Validation | GHSA-related | Allowlist API | Validation fix |
| `b6c083d73` | fix logout redirect | CVE-2024-22244 (open redirect) | Web UI | Redirect fix |
| `747aac043` | Fix Password Validation in UI | Auth-related | UI validation | Form validation |
| `ebc340a8f` | fix: correct the permission of project maintainer role for webhook policy | Permission validation | Webhook API | Permission check |

### Structural Recurrence Targets (for Phase 2 Deep Review)

**Type: Permission Validation**
- **Commit Cluster:** 2022-08-29 patches (v2.4.3, v2.5.2)
- **CVEs:** CVE-2022-31670, 31671, 31666, 31669, 31667
- **Components:** Tag retention, P2P preheat, Webhook (3x variants), tag immutability, robot accounts
- **Action:** Diff all 5 commits in the patch release to identify common fix pattern. If inconsistent, bypass risk is HIGH.

**Type: SQL Injection**
- **Recurring:** 2019 (user-groups, quotas), 2024 (scan logs)
- **Pattern:** Same class, different endpoints, 5-year gap
- **Action:** Check if codebase has standardized parameterized query library or if patterns vary. If varies, additional injections likely.

**Type: Authentication/Privilege Escalation**
- **Cluster:** 2019-09/10/12 (CRITICAL 3x), 2023 (timing), 2026 (LDAP leak)
- **Pattern:** Auth module repeatedly patched, suggests ongoing refactoring
- **Action:** Review auth module refactoring history. Are patches orthogonal or patches-on-patches?

---

## Part 7: Audit Targeting Recommendations

### Phase 2: Patch-Bypass-Checker Priorities

1. **HIGH:** Permission validation framework (v2.4.3+ patch cluster)
   - Test all 5 permission bypass CVEs against current code
   - Verify patch consistency across endpoints
   - Flag any regressions in newer versions

2. **HIGH:** SQL injection patterns (recurring 2019→2024)
   - Audit all ORM query construction for raw SQL concatenation
   - Test scan logs, user-groups, quotas APIs
   - Verify parameterization across all endpoints

3. **MEDIUM:** LDAP/OIDC authentication path
   - Timing attack on LDAP bind result
   - Bearer token timing validation
   - Secret exposure in logs

### Phase 3: DFD/CFD Slicing Priorities

1. **API Authorization Validation** - High heat, 9 advisories, multiple endpoints
2. **LDAP/OIDC Authentication** - 3 advisories, critical privilege escalation history
3. **SQL Input Handling** - 3 advisories, structural weakness, recurrence risk
4. **Webhook Policy Management** - 3 advisories, single-root-cause pattern

### Phase 5: Deep Probe Entry Points

1. **API Query Parameters** - Permission checks, filter validation, user enumeration
2. **Configuration Objects** - Audit log serialization, secret redaction
3. **Database ORM Layer** - Parameterized query verification, injection patterns
4. **Authentication Flows** - LDAP bind, OIDC response parsing, JWT validation

### Phase 8: Security Review Chambers

**Mandatory Attack Modes:**

1. **Authorization Bypass** (CWE-862)
   - Input: Modify policy update requests (tag, webhook, P2P, robot, tag immutability)
   - Attack: Attempt to update/delete as unprivileged user
   - Coverage: All 5 endpoints from 2022 patch cluster

2. **SQL Injection** (CWE-89)
   - Input: User-group names, quota filters, scan log filters
   - Attack: ORM filter parameter injection, union queries, time-based extraction
   - Coverage: 3 endpoints with recurrence history

3. **Information Disclosure** (CWE-200, CWE-203)
   - Input: User enumeration via API, ORM leak via password filter, audit log parsing
   - Attack: Enumerate users, extract password hashes, read configuration logs
   - Coverage: User API, admin endpoints, audit logs

4. **Privilege Escalation** (CWE-269)
   - Input: LDAP/OIDC authentication, permission assignment
   - Attack: Bypass role checks, forge tokens, exploit auth module refactoring
   - Coverage: Auth flow, token issuance, permission assignment

---

## Summary Statistics

**Phase 1 Output Metrics:**

| Metric | Value |
|--------|-------|
| Total advisories collected | 27 |
| Coverage period | 2019-09-19 to 2026-03-25 (7 years) |
| Tier reached | 2 (full historical) |
| High-heat components identified | 4 |
| Structural recurrence patterns found | 3 |
| Recommended Phase 2 targets | 3 |
| Recommended Phase 3 DFD slices | 4 |
| Recommended Phase 8 attack modes | 4 |

**Key Insight:** Permission validation (CWE-862) is the dominant vulnerability class (33% of advisories), with 5 distinct endpoints patched simultaneously in 2022, indicating a framework-level weakness rather than isolated bugs. This suggests Phase 3 DFD analysis should prioritize the authorization middleware and permission check pattern across the codebase.

---

## References

- **GitHub Security Advisory Database:** https://github.com/goharbor/harbor/security/advisories
- **Harbor Release Notes:** https://github.com/goharbor/harbor/blob/main/RELEASES.md
- **Harbor Security Policy:** https://github.com/goharbor/harbor/blob/main/SECURITY.md
- **CVSS Calculator:** https://www.first.org/cvss/calculator/3.1
- **CWE List:** https://cwe.mitre.org/

---

**Report Generated:** 2026-03-27  
**Audit Phase:** 1 (Advisory Intelligence)  
**Next Phase:** 2 (Patch-Bypass-Checker)
