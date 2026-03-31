# Grafana Security Audit - Phase 1 Intelligence Gathering

**Status:** PHASE 1 COMPLETE
**Date:** 2026-03-20
**Repository:** github.com/grafana/grafana
**Current Commit:** 40a9cd68ff8efc62da02d30bf4b3e8ae3a1017ab

---

## Quick Navigation

### Phase 1 Deliverables

1. **[PHASE-1-SUMMARY.md](PHASE-1-SUMMARY.md)** - Executive summary and findings overview
   - Key statistics and findings
   - Critical vulnerabilities summary
   - Phase 1 → Phase 2 transition
   - Recommendations

2. **[advisory-report.md](advisory-report.md)** - Complete CVE inventory
   - 8 CVEs with CVSS scores
   - Affected versions and patch information
   - Patch commit mappings
   - Vulnerability timeline
   - Critical attack surfaces

3. **[architecture-inventory.md](architecture-inventory.md)** - System architecture mapping
   - 13 backend service components
   - Frontend structure (React, Redux, RTK Query)
   - Trust boundaries and data flows
   - 5 highest-risk flows for Phase 2
   - Execution environments
   - External service dependencies

4. **[phase-2-patch-list.md](phase-2-patch-list.md)** - Structured bypass analysis framework
   - 9 security patches prioritized
   - Bypass considerations for each CVE
   - Specific Phase 2 analysis tasks
   - Dependency vulnerability assessment
   - Patch analysis evaluation framework

5. **[audit-state.json](audit-state.json)** - Audit state tracking
   - Phase 1 completion status
   - Summary statistics
   - Artifact references

---

## Key Findings

### Critical Vulnerabilities

| CVE ID | Severity | Component | Attack Vector | Impact |
|--------|----------|-----------|----------------|--------|
| CVE-2025-11539 | CRITICAL | Image Renderer | /render/csv filePath validation | RCE via Chromium |
| CVE-2025-41115 | CRITICAL | SCIM (Enterprise) | Numeric externalId mapping | Privilege escalation |

### High Severity

| CVE ID | Severity | Component | Attack Vector | Impact |
|--------|----------|-----------|----------------|--------|
| CVE-2025-4123 | HIGH | Frontend Plugins | Path traversal + open redirect | XSS, arbitrary JS execution |
| CVE-2026-21721 | HIGH | Dashboard Permissions | Context escape | Cross-dashboard privilege escalation |

### Medium Severity (3 CVEs)
- CVE-2025-3454: Datasource proxy double-slash bypass
- CVE-2026-21722: Public dashboard timerange bypass
- CVE-2025-41117: TraceView HTML XSS

### Low Severity
- CVE-2026-21725: TOCTOU datasource deletion (30-second window)

### Dependency Vulnerabilities (5)
- CVE-2026-25536 (@grafana/llm)
- CVE-2025-48371 (OpenFGA authorization library)
- 4x Go stdlib CVEs (nanogit v0.7.0)
- CVE-2025-6197, CVE-2025-6023 (Go stdlib)

---

## Architecture Summary

### Backend (Go Monolith)
- **Services:** 39 packages with clear responsibilities
- **DI Pattern:** Wire (dependency injection)
- **Storage:** PostgreSQL/MySQL/SQLite
- **Plugins:** gRPC-based backend plugins
- **Multi-tenancy:** Organization-level isolation in single process

### Frontend (React/TypeScript)
- **State:** Redux Toolkit + RTK Query
- **Modules:** Dashboard, Alerting, Explore, Users, Org, Auth
- **Plugins:** React components (NO SANDBOX)
- **Architecture:** Component-based with hooks

### Critical Trust Boundaries
1. Internet-facing HTTP API
2. Datasource proxy (external service routing)
3. Plugin execution (frontend & backend)
4. SCIM provisioning (user identity)
5. Database access (credential encryption)

### Execution Environments
- **Backend:** Single Go process (all orgs share memory)
- **Frontend:** Browser-based (origin isolation)
- **Plugins:** Separate go-plugin processes
- **Image Renderer:** Separate Chromium process

---

## Highest-Risk Flows (Phase 2 Focus)

### Flow 1: Datasource Proxy Authorization Bypass (CVE-2025-3454)
**File:** `pkg/services/datasourceproxy`
**Risk:** Double-slash bypasses permission checks
**Phase 2 Task:** Analyze route matching regex, test encoding variants

### Flow 2: SCIM User Identity Override (CVE-2025-41115)
**File:** `pkg/services/scimutil`
**Risk:** Numeric externalId → privilege escalation
**Phase 2 Task:** Analyze type validation, test type coercion

### Flow 3: Image Renderer Arbitrary Write (CVE-2025-11539)
**File:** `grafana-image-renderer` (separate repo)
**Risk:** Unvalidated filePath → RCE
**Phase 2 Task:** Analyze path validation, test traversal variants

### Flow 4: Dashboard Permission Escape (CVE-2026-21721)
**File:** `pkg/services/dashboards`
**Risk:** Permission context isolation failure
**Phase 2 Task:** Analyze context binding, test isolation

### Flow 5: Admin Deletion Bypass (CVE-2025-3580)
**File:** `pkg/services/org`
**Risk:** Org admin can delete server admin
**Phase 2 Task:** Analyze access control, test alternative endpoints

---

## Statistics

| Metric | Count |
|--------|-------|
| Total CVEs | 8 |
| CRITICAL | 2 |
| HIGH | 2 |
| MEDIUM | 3 |
| LOW | 1 |
| Dependency CVEs | 5 |
| Patch Commits Identified | 12+ |
| Backend Services | 39 |
| Frontend Modules | 8+ |
| Highest-Risk Flows | 5 |

---

## Files in This Directory

```
security/
├── README.md                      (This file)
├── PHASE-1-SUMMARY.md             (Executive summary)
├── advisory-report.md             (CVE inventory - 157 lines)
├── architecture-inventory.md      (Architecture mapping - 633 lines)
├── phase-2-patch-list.md          (Bypass analysis framework - 298 lines)
├── audit-state.json               (State tracking)
└── (subdirectories from previous work)
    ├── bypass-analysis/
    ├── chamber-workspace/
    └── findings-draft/
```

---

## Phase 2 Readiness

All Phase 1 deliverables are complete and ready for Phase 2 analysis:

### What Phase 2 Will Do
1. Detailed bypass analysis for each patch
2. Code-level verification of patch completeness
3. Validation strength assessment (encoding, normalization)
4. Regression risk analysis
5. Proof-of-concept development (where applicable)

### Critical Components for Phase 2
**HIGHEST PRIORITY:**
- `pkg/services/datasourceproxy` (CVE-2025-3454)
- `pkg/services/scimutil` (CVE-2025-41115)
- `grafana-image-renderer` (CVE-2025-11539)

**HIGH PRIORITY:**
- `pkg/services/dashboards` (CVE-2026-21721)
- `pkg/services/org` (CVE-2025-3580)
- `public/app/features/plugins` (CVE-2025-4123)

**MEDIUM PRIORITY:**
- `pkg/services/publicdashboards` (CVE-2026-21722)
- `pkg/api` TraceView (CVE-2025-41117)
- `pkg/services/datasources` (CVE-2026-21725)

---

## References

- **Grafana Security Advisories:** https://grafana.com/security/security-advisories/
- **Grafana Documentation:** https://grafana.com/docs/grafana/latest/
- **Repository:** https://github.com/grafana/grafana

---

## Document Versions

| File | Version | Lines | Updated |
|------|---------|-------|---------|
| PHASE-1-SUMMARY.md | 1.0 | - | 2026-03-20 |
| advisory-report.md | 1.0 | 157 | 2026-03-20 |
| architecture-inventory.md | 1.0 | 633 | 2026-03-20 |
| phase-2-patch-list.md | 1.0 | 298 | 2026-03-20 |
| audit-state.json | 1.0 | - | 2026-03-20 |

---

**Phase 1 Complete:** 2026-03-20
**Status:** Ready for Phase 2 Bypass Analysis

