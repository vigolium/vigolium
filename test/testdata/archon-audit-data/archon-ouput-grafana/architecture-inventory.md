# Grafana Architecture Inventory

**Phase 1 Intelligence Gathering - Architecture Mapping**
**Audit ID:** 2026-03-21T00:00:00.000Z
**Generated:** 2026-03-21
**Repository:** github.com/grafana/grafana (commit 40a9cd68ff8efc62da02d30bf4b3e8ae3a1017ab)
**Version in tree:** 13.0.0-pre

---

## System Architecture Overview

Grafana is a distributed monitoring and observability platform with:
- **Backend**: Go monolith (`pkg/`) with Wire DI pattern; Go 1.25.8 toolchain
- **Frontend**: TypeScript/React (`public/app/`) with Redux Toolkit + RTK Query
- **Execution Model**: Monolithic HTTP server + gRPC plugin system + optional remote services
- **Storage**: Primary DB (PostgreSQL/MySQL/SQLite) + optional Redis cache + optional object storage (S3/GCS/Azure)
- **Plugin Architecture**: In-process (frontend) + out-of-process gRPC (backend datasources)

---

## Backend Components (`pkg/`)

### 1. API Gateway and Routing Layer
**Location:** `pkg/api/`, `pkg/middleware/`
**Trust Boundary:** Internet-facing HTTP
**Ports:** :3000 (default)

Key responsibilities:
- Route registration via `routing.RouteRegister`
- Middleware pipeline: auth, RBAC, CORS, rate limiting, observability
- Static asset serving, reverse proxy for frontend dev server

Authentication entry points:
- Session cookie (`grafana_session`)
- Bearer token / API key (`Authorization: Bearer`)
- Basic auth (`Authorization: Basic`)
- OAuth2 callback (`/login/<provider>`)
- SAML ACS (`/saml/acs`)
- SCIM provisioning (`/scim/v2/`)

Public (unauthenticated) endpoints:
- `/api/health` — health check
- `/api/public/dashboards/:accessToken` — public dashboard data
- `/api/public/dashboards/:accessToken/annotations` — public dashboard annotations (PATCHED CVE-2026-21722)
- `/login`, `/logout` — login flow
- `/api/frontend-metrics` — client-side metrics
- `/avatar/:hash` — avatar (WAS unauthenticated, PATCHED CVE-2026-21720)
- Grafana Image Renderer (`/render/`) — separate service

### 2. Authentication and Authorization (`pkg/services/auth*`, `pkg/services/accesscontrol`)
**Location:** `pkg/services/auth/`, `pkg/services/authn/`, `pkg/services/authz/`, `pkg/login/`
**Trust Boundary:** Identity provider boundary; internal permission enforcement

Components:
- **authn**: Authentication pipeline — session, JWT, OAuth2 (Google, GitHub, Azure AD, GitLab, Okta), LDAP, SAML, SCIM
- **authz**: Authorization — RBAC via OpenFGA v1.11.3, legacy team/folder permissions
- **accesscontrol**: Permission evaluation and caching (`pkg/services/accesscontrol/`)
- **extsvcauth**: External service authentication tokens
- **contexthandler**: Request context enrichment (identity injection)

Key security services:
- `authn.Service` — authentication pipeline orchestrator
- `accesscontrol.AccessControlService` — permission enforcement, cached evaluator
- `login.Service` — login flow, lockout enforcement
- `auth.OAuthTokenService` — OAuth2 token management
- SCIM service (`pkg/services/scimutil/`) — Enterprise identity provisioning

Security-relevant configuration:
- `[auth]` section: disable_login_form, oauth_auto_login, sigv4_auth_enabled
- `[auth.jwt]` section: jwt_secret, algorithm, url_login
- `[auth.generic_oauth]` section: client_id, client_secret, scopes, allow_assign_grafana_admin
- `[security]` section: secret_key, cookie_secure, cookie_samesite, content_security_policy
- `[server]` section: domain, root_url, enable_gzip

Default secrets (HIGH RISK if unchanged):
- `secret_key = SW2YcwTIb9zpOOhoPsMm` — used for cookie signing and secrets encryption
- Image renderer JWT: `-` (single dash) — default in older installations
- `admin_password = admin` — initial admin password

### 3. Data Handling (`pkg/services/datasources`, `pkg/services/datasourceproxy`)
**Location:** `pkg/services/datasources/`, `pkg/services/datasourceproxy/`, `pkg/services/query/`
**Trust Boundary:** Data-plane; credentials are secrets; proxy must enforce route-level RBAC

Components:
- **datasources**: Datasource registry, credential storage/encryption
- **datasourceproxy**: HTTP proxy for remote datasource APIs with route-based ACL
- **query**: Query execution pipeline, expression evaluation (`pkg/expr/`)
- **encryption**: AES-256 encryption of datasource credentials using `secret_key`

Attack surface:
- Double-slash bypass on proxy routes (PATCHED CVE-2025-3454)
- TOCTOU on datasource deletion (PATCHED CVE-2026-21725)
- Parser differential between route matching and URL forwarding (M7 finding)
- Query expression evaluation — potential code execution via SQL expressions (blocked by feature toggle)

Supported datasources (built-in):
- Prometheus, Loki, Tempo, Pyroscope, Jaeger, Zipkin (observability)
- Elasticsearch, CloudWatch, Azure Monitor, Google Cloud Monitoring (cloud)
- PostgreSQL, MySQL, MSSQL, InfluxDB (databases)
- ~50 additional via plugin system

### 4. Plugin System (`pkg/plugins/`)
**Location:** `pkg/plugins/`, `pkg/pluginproxy/`
**Trust Boundary:** Plugin sandbox boundary; out-of-process gRPC

Components:
- Plugin loader: signature verification, manifest validation
- Plugin runner: in-process (core) vs out-of-process gRPC (backend plugins)
- Plugin proxy: HTTP proxy with plugin-specific auth injection
- Plugin store: artifact management

Security surface:
- Plugin signature verification bypass (historical CVEs)
- Plugin zip symlink traversal (M8 finding) during install
- gRPC transport between Grafana server and plugin process

### 5. Alerting Engine (`pkg/services/ngalert`)
**Location:** `pkg/services/ngalert/`, `pkg/services/notifications/`
**Trust Boundary:** Internal scheduler; outbound webhooks to external services

Components:
- Alert rule storage and evaluation scheduler
- Alertmanager integration (built-in + remote)
- Notification dispatching (Slack, PagerDuty, Email, Webhook, etc.)
- Provisioning API for alert rules

Security surface:
- Webhook URL injection via alert contact points (admin-controlled but SSRF risk)
- Alert rule expression evaluation (data-plane)
- Provisioning file path traversal (`pkg/services/provisioning/`)

### 6. Cloud Migration Service (`pkg/services/cloudmigration`)
**Location:** `pkg/services/cloudmigration/`
**Trust Boundary:** Outbound to Grafana Managed Service (GMS) control plane

Components:
- Migration token management
- Resource serialization and upload to GMS
- Snapshot creation and upload

Security surface:
- SSRF via presigned URL from GMS (H4 finding — confirmed EXECUTED)
- Post-creation GMS operation SSRF (M6/M20 findings)

### 7. Image Renderer Service (Separate Process)
**Location:** Not in main repo; `grafana-image-renderer` plugin
**Trust Boundary:** Localhost gRPC or HTTP; renders dashboards to PNG/PDF

Components:
- HTTP endpoint: `/render/csv`, `/render/`, `/metrics`
- Chromium-based browser rendering
- File system write for CSV export

Security surface:
- RCE via `/render/csv` filePath parameter (CVE-2025-11539 — CRITICAL)
- Default JWT auth token `-` enables bypass (H2 finding — confirmed EXECUTED)
- ServeFile without directory confinement (M11 finding)

### 8. Unified Storage / App Platform (`pkg/services/store/`)
**Location:** `apps/`, `pkg/apiserver/`, `pkg/services/storage/`
**Trust Boundary:** Internal Kubernetes-like API server; multi-tenant

Components:
- Storage backend (SQL, object storage)
- Resource server with versioning (Kubernetes-compatible API)
- Git sync via `nanogit` library (provisioning)

Security surface:
- Provisioning file authorization issues (fixed in commit 2c404dcae67)
- Nanogit Go stdlib CVEs (patched in 4bc3b94077e)

### 9. SCIM Provisioning (Enterprise, `pkg/services/scimutil`)
**Location:** `pkg/services/scimutil/` (Enterprise)
**Trust Boundary:** IdP-to-Grafana provisioning API

Security surface:
- Privilege escalation via numeric externalId (CVE-2025-41115 — CRITICAL)
- SCIM+SAML duplicate user auth record (commit f1b77b82db5)

---

## Frontend Architecture (`public/app/`)

### Component Map

| Component | Location | Trust Boundary |
|-----------|----------|----------------|
| Plugin Loader | `public/app/features/plugins/` | Browser sandbox; loads external plugin assets |
| Dashboard Renderer | `public/app/features/dashboard/` | Browser DOM; renders panel data from datasources |
| Explore View | `public/app/features/explore/` | Browser; includes TraceView (XSS surface CVE-2025-41117) |
| Alerting UI | `public/app/features/alerting/unified/` | Browser; contact point and rule management |
| XY Chart Panel | `public/app/plugins/panel/xychart/` | Browser DOM; XSS surface (CVE-2025-2703) |
| Public Dashboards | `public/app/features/dashboard/components/PublicDashboard/` | Internet-facing; unauthenticated |
| Avatar Component | `public/app/core/components/Avatar/` | Unauthenticated URL (patched CVE-2026-21720) |

### Frontend Security Controls

- Content Security Policy (CSP) — configurable; `unsafe-eval` present when Vega enabled (SPEC-GAP-006)
- DOMPurify sanitization — used in most HTML rendering contexts
- `dangerouslySetInnerHTML` patterns — audited in Phase 4 SAST
- Redux store — contains auth tokens; XSS can exfiltrate via Redux state

---

## Transport Layer

| Transport | Used For | Authentication | Notes |
|-----------|----------|---------------|-------|
| HTTP/HTTPS | Main API, datasource proxy, plugin proxy | Session/JWT/API key | Internet-facing |
| gRPC (TLS) | Plugin backend communication | Internal service token | Localhost or cluster |
| WebSocket | Live dashboard updates, streaming queries | Session cookie | Requires authentication |
| SCIM v2 (HTTP) | Identity provisioning | Bearer token (Enterprise) | Privileged operations |
| Centrifuge (WebSocket) | Real-time events | Session token | Internal |
| gRPC (xDS) | xDS AuthZ (Enterprise) | mTLS | Admin credential injection risk (M5) |

---

## Trust Boundaries

```
Internet
    |
    v
[Load Balancer / TLS termination]
    |
    v
[Grafana HTTP Server :3000]
    |-- Public endpoints (no auth): /api/health, /api/public/dashboards/*
    |-- Authenticated endpoints: most /api/* routes
    |-- Admin endpoints: /api/admin/*, /api/orgs/*, /api/datasources/*
    |
    v (datasource proxy)
[External datasources: Prometheus, Loki, CloudWatch, PostgreSQL, etc.]
    |
    v (plugin gRPC)
[Plugin processes: image-renderer, datasource plugins]
    |
    v (cloud migration)
[Grafana Managed Service (GMS): external control plane]
```

### Boundary Risk Assessment

| Boundary | Risk Level | Notes |
|----------|-----------|-------|
| Internet → Grafana HTTP | HIGH | Public dashboard endpoints; avatar DoS; plugin open redirect |
| Grafana → Datasource | HIGH | SSRF via proxy; credential exposure; double-slash bypass |
| Grafana → Plugin gRPC | MEDIUM | Default auth token; file path traversal |
| Grafana → GMS (cloud) | HIGH | SSRF via presigned URLs (H4 confirmed) |
| Grafana → SCIM IdP | MEDIUM | Privilege escalation via numeric externalId |
| Browser → Grafana API | MEDIUM | CSRF (patched); XSS in multiple components |

---

## Execution Environments

| Environment | Runtime | Sandbox | Notes |
|-------------|---------|---------|-------|
| Grafana Server | Go 1.25.8 | OS process | Wire DI; monolithic |
| Image Renderer | Node.js + Chromium | Headless browser | High-risk RCE surface |
| Plugin (backend) | Go/Python/Java (per plugin) | gRPC sandboxed process | Plugin signature verification |
| Frontend | Browser JS (React/Redux) | Browser sandbox | CSP enforcement |
| Provisioning (nanogit) | Go + Git | OS filesystem | File path traversal risk |
| SQL Expression Engine | Go (dolthub/go-mysql-server) | In-process | Previously allowed RCE — disabled by feature toggle |

---

## Highest-Risk Data Flows for Phase 2 DFD Analysis

### Flow 1: Public Dashboard Annotation Query (CVE-2026-21722 / H1)
```
Browser (unauthenticated)
  → GET /api/public/dashboards/:token/annotations
  → pkg/api/annotations.go → GetAnnotations()
  → pkg/services/annotations/ → timerange from request (NOT dashboard)
```
**Risk:** Timerange lockout bypass; patch residual risk if authenticated bypass remains

### Flow 2: Datasource Proxy Authorization (CVE-2025-3454 / M7)
```
Browser (authenticated)
  → GET /api/datasources/proxy/uid/:uid//api/v1/targets (double-slash)
  → pkg/api/datasourceproxy.go → ProxyDataSourceRequest()
  → pkg/services/datasourceproxy/ → route matching
  → External datasource (Prometheus/Alertmanager)
```
**Risk:** Route ACL bypass; parser differential between matching and forwarding

### Flow 3: Dashboard Permission Management (CVE-2026-21721 / CVE-2025-3260)
```
Browser (authenticated editor)
  → POST /api/dashboards/uid/:uid/permissions
  → pkg/api/api.go → authorize(EvalPermission(ActionDashboardsPermissionsWrite, scope))
  → pkg/services/accesscontrol/ → permission check
  → pkg/services/dashboards/ → UpdateDashboardPermissions()
```
**Risk:** Scope binding was missing; can scoped users still target dashboards outside their permission?

### Flow 4: Cloud Migration SSRF via Presigned URLs (H4 — Confirmed)
```
Authenticated admin
  → POST /api/cloudmigration/migration/:uid/snapshot
  → pkg/services/cloudmigration/ → CreateSnapshot()
  → GMS API → returns presigned URL
  → Grafana server → fetches presigned URL (arbitrary)
```
**Risk:** SSRF to internal network; instance metadata endpoints; lateral movement

### Flow 5: Image Renderer CSV Download (CVE-2025-11539 / H2)
```
Unauthenticated (default token '-')
  → POST /render/csv?filePath=../../etc/passwd
  → Image Renderer service → file write
  → Chromium process → code execution
```
**Risk:** RCE if renderer deployed without auth token change

### Flow 6: SCIM User Provisioning (CVE-2025-41115)
```
IdP → SCIM v2 API
  → POST /scim/v2/Users {"externalId": "1"}
  → pkg/services/scimutil/ → maps to internal user ID 1 (admin)
  → Privilege escalation to admin
```
**Risk:** Enterprise only; numeric externalId coercion

### Flow 7: Plugin Installation Zip Extraction (M8)
```
Admin
  → POST /api/plugins/install/:pluginId
  → pkg/plugins/ → download zip
  → pkg/plugins/manager/ → extract zip (symlink traversal)
  → Grafana filesystem → arbitrary file write
```

### Flow 8: xDS AuthZ Credential Injection (M5)
```
Authenticated service account (with xDS access)
  → xDS server API
  → Inject malicious credential header into AuthZ filter
  → Downstream requests use injected credentials
```

---

## Key Services Registry (pkg/services/)

| Service | Package | Owner | Security Relevance |
|---------|---------|-------|-------------------|
| accesscontrol | `pkg/services/accesscontrol/` | @grafana/identity-access-team | Permission enforcement; caching |
| authn | `pkg/services/authn/` | @grafana/identity-access-team | Auth pipeline |
| authz | `pkg/services/authz/` | @grafana/identity-access-team | OpenFGA RBAC |
| datasources | `pkg/services/datasources/` | @grafana/grafana-backend-group | Credential storage |
| datasourceproxy | `pkg/services/datasourceproxy/` | @grafana/grafana-backend-group | Proxy routing |
| ngalert | `pkg/services/ngalert/` | @grafana/alerting-backend | Alert evaluation |
| cloudmigration | `pkg/services/cloudmigration/` | @grafana/grafana-operator-experience-squad | GMS integration; SSRF |
| encryption | `pkg/services/encryption/` | @grafana/identity-access-team | AES-256 credential encryption |
| correlations | `pkg/services/correlations/` | @grafana/grafana-datasources-core-services | Cross-tenant exposure |
| annotations | `pkg/services/annotations/` | @grafana/grafana-backend-group | Timerange enforcement |
| dashboards | `pkg/services/dashboards/` | @grafana/grafana-backend-group | Permission management |
| login | `pkg/login/` | @grafana/identity-access-team | Login flow |
| provisioning | `pkg/services/provisioning/` | @grafana/grafana-as-code | File operations security |

