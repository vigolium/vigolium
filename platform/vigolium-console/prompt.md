# Vigolium Workbench — Plan Review & Optimizations

## Issue 1: Vite + Next.js is Impossible

**This is a showstopper.** Vite and Next.js are competing build systems — you cannot use both in the same project. Next.js uses Webpack/Turbopack internally.

**Recommendation: Pick one.**

| | **Next.js (App Router)** | **Vite + React** |
|---|---|---|
| Routing | File-based (`/1`, `/2`, etc. trivial) | Need `react-router-dom` |
| SSR/SEO | Built-in (unnecessary for dashboard) | None (fine for dashboard) |
| Build speed | Slower | Faster |
| Bundle size | Heavier | Lighter |
| Complexity | More moving parts | Minimal |

For a **dashboard SPA** with no SEO needs, **Vite + React** is the better fit — faster dev server, simpler setup, lighter bundle. But if you prefer Next.js's file-based routing for the 5 designs, that works too.

---

## Issue 2: Outdated Library Versions

| Library | Your Spec | Actual Latest | Impact |
|---|---|---|---|
| AG Grid | 33.x | **35.1.0** | Missing 2 major versions of features |
| Recharts | 3.x | **3.7.0** | Correct range, just pin latest |
| Tailwind | not specified | **4.2.1** | v4 is a major rewrite (CSS-first config, Rust engine) |
| Next.js | "latest" | **16.1.6** | — |

---

## Issue 3: Backend API is Rich — Plan Underutilizes It

Your backend at `localhost:9002` exposes **10+ endpoint groups**. The plan only mentions "HTTP traffic and findings." Here's what's actually available for charting/tables:

| Endpoint | Dashboard Value |
|---|---|
| `GET /api/stats` | Severity breakdown pie chart, module counts, totals |
| `GET /api/findings` | Finding table with severity/confidence filters |
| `GET /api/http-records` | HTTP traffic table with method/status/domain filters |
| `GET /api/modules` | Module registry list (active vs passive) |
| `GET /api/scan/status` | Live scan progress indicator |
| `GET /server-info` | Uptime, queue depth, DB driver, record/finding totals |
| `GET /api/scope` | Scope configuration viewer |
| `GET /api/source-repos` | Source code repository inventory |

---

## Issue 4: Five Completely Different Designs = Massive Scope

Five distinct dashboards is ~5x the work. Without constraints, this will produce superficial variants.

**Recommendation:** Define clear aesthetic themes upfront so each design has a strong identity:

| Route | Theme Suggestion |
|---|---|
| `/1` | **Dark Cyber** — Neon accents on near-black, terminal/hacker aesthetic |
| `/2` | **Clean Corporate** — Light, professional, lots of whitespace, muted blues |
| `/3` | **Glassmorphism** — Frosted glass cards, gradient backgrounds, blur effects |
| `/4` | **Data-Dense Terminal** — Monospace font, minimal chrome, maximum data density |
| `/5` | **Warm Minimal** — Earth tones, rounded corners, friendly/accessible feel |

---

## Issue 5: Missing Architectural Decisions

Things unaddressed in the plan:

1. **API client layer** — How to handle fetch calls, error states, loading states? (recommend `@tanstack/react-query` or `swr`)
2. **CORS** — The backend supports configurable CORS. Dev proxy needed in Vite/Next config.
3. **Auth** — Backend supports Bearer token auth. How should the dashboard handle this? (token input? env var?)
4. **Shared components** — 5 designs should share data-fetching hooks and API types, only differ in presentation.
5. **State management** — Not needed beyond react-query cache for a read-heavy dashboard.

---

## Optimized Stack Recommendation

```
Runtime:        Bun (as requested)
Framework:      Vite 6 + React 19   (or Next.js 16 if you prefer)
Styling:        Tailwind CSS 4.2
Data Table:     AG Grid Community 35
Charts:         Recharts 3.7
Icons:          lucide-react (latest)
Data Fetching:  @tanstack/react-query 5
Routing:        react-router-dom 7   (if Vite) or file-based (if Next.js)
TypeScript:     5.x (latest)
```

---

## Optimized Project Structure (Vite variant)

```
src/
├── api/              # API client, types, react-query hooks
│   ├── client.ts     # fetch wrapper with base URL + auth
│   ├── types.ts      # TypeScript types matching backend models
│   └── hooks.ts      # useFindings(), useHttpRecords(), useStats()...
├── components/       # Shared components (AG Grid wrapper, chart wrappers)
├── layouts/          # Per-design layout shells
│   ├── design-1/     # Dark Cyber
│   ├── design-2/     # Clean Corporate
│   ├── design-3/     # Glassmorphism
│   ├── design-4/     # Terminal
│   └── design-5/     # Warm Minimal
├── pages/            # Route pages (each imports its design layout)
└── App.tsx           # Router setup
```

Key principle: **data logic is shared, only visual presentation differs per design.**

---

## Backend API Reference

### Authentication
- **Mechanism:** HTTP Bearer Token (`Authorization: Bearer <token>`)
- Public endpoints (no auth): `/`, `/health`, `/metrics`, `/swagger`
- All `/api/*` endpoints require auth (unless `no_auth: true` in server config)

### Endpoints

#### Info & Health (Public)
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | App info (name, version, author, build_time, commit) |
| `GET` | `/health` | Health check (status, timestamp) |
| `GET` | `/server-info` | Server details (uptime, queue_depth, total_records, total_findings, db_driver) |
| `GET` | `/metrics` | Prometheus metrics |

#### Statistics
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/stats` | Scan statistics: http_records.total, modules (active/passive counts), findings (total + by_severity breakdown) |

#### Findings
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/findings` | Paginated findings list |

**Query Parameters:**
- `limit` (int, default: 50, max: 500)
- `offset` (int, default: 0)
- `domain` (string, supports wildcards)
- `severity` (string, comma-separated: critical, high, medium, low, info)
- `module_name` (string)
- `scan_id` (string)
- `search` (string, searches description/module_id/matched_at)
- `sort` (string: found_at, created_at, severity, module_name, module_id, confidence)
- `order` (string: asc/desc, default: desc)

**Finding Model:**
```json
{
  "id": 1,
  "http_record_uuids": ["uuid"],
  "scan_uuid": "scan-abc123",
  "module_id": "xss_scanner",
  "module_name": "XSS Scanner",
  "description": "Reflected XSS found...",
  "severity": "high",
  "confidence": "firm",
  "tags": ["xss", "reflected"],
  "matched_at": ["/api/users?id=<script>"],
  "extracted_results": ["<script>alert('xss')</script>"],
  "request": "GET /api/users?id=test HTTP/1.1\r\nHost: example.com",
  "response": "HTTP/1.1 200 OK\r\n...",
  "finding_hash": "hash123abc",
  "found_at": "2025-03-01T12:00:00Z",
  "created_at": "2025-03-01T12:00:00Z"
}
```

#### HTTP Records
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/http-records` | Paginated HTTP records list |

**Query Parameters:**
- `limit` (int, default: 50, max: 500)
- `offset` (int, default: 0)
- `domain` (string, supports wildcards)
- `status_code` (string, comma-separated)
- `method` (string, comma-separated)
- `path` (string, supports wildcards)
- `content_type` (string)
- `source` (string: scanner, ingest-cli, ingest-server, ingest-proxy)
- `min_risk` (int)
- `remark` (string)
- `search` (string, searches URLs and paths)
- `sort` (string: uuid, created_at, sent_at, method, path, status_code, response_time, source, risk_score)
- `order` (string: asc/desc, default: desc)

**HTTPRecord Model:**
```json
{
  "uuid": "550e8400-...",
  "scheme": "https",
  "hostname": "example.com",
  "port": 443,
  "ip": "1.2.3.4",
  "method": "GET",
  "path": "/api/users",
  "url": "https://example.com/api/users",
  "http_version": "HTTP/1.1",
  "request_headers": {"User-Agent": ["Mozilla/5.0..."]},
  "request_content_type": "application/json",
  "request_content_length": 256,
  "request_authorization": "Bearer token123",
  "status_code": 200,
  "status_phrase": "OK",
  "response_headers": {"Content-Type": ["application/json"]},
  "response_content_type": "application/json",
  "response_content_length": 512,
  "response_time_ms": 145,
  "response_words": 50,
  "has_response": true,
  "response_title": "Users API",
  "parameters": [
    {"name": "user_id", "value": "123", "type": "query"}
  ],
  "sent_at": "2025-03-01T12:00:00Z",
  "created_at": "2025-03-01T12:00:00Z",
  "source": "ingest-server",
  "remarks": ["interesting_response"],
  "risk_score": 25
}
```

#### Modules
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/modules` | List scanner modules (query: `search`) |

**Module Response:**
```json
{
  "modules": [
    {
      "id": "xss_scanner",
      "name": "XSS Scanner",
      "description": "Detects XSS vulnerabilities...",
      "short_description": "XSS detection",
      "severity": "high",
      "type": "active"
    }
  ],
  "total": 42
}
```

#### Scan Management
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan` | Trigger scan (body: `{force, enable_modules}`) |
| `GET` | `/api/scan/status` | Get scan status |
| `DELETE` | `/api/scan` | Cancel running scan |

#### Scope Configuration
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/scope` | Get scope config |
| `POST` | `/api/scope` | Update scope config |

#### Configuration
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/config` | Get config (query: `filter`, `show_sensitive`) |
| `POST` | `/api/config` | Update config (dot-notation keys) |

#### Source Repositories
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/source-repos` | List repos (query: `limit`, `offset`, `hostname`) |
| `POST` | `/api/source-repos` | Create repo |
| `GET` | `/api/source-repos/:id` | Get repo |
| `PUT` | `/api/source-repos/:id` | Update repo |
| `DELETE` | `/api/source-repos/:id` | Delete repo |

#### Agent
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/agent/run` | Trigger agent run (supports SSE streaming) |
| `GET` | `/api/agent/status/list` | List all agent runs |
| `GET` | `/api/agent/status/:id` | Get agent run status |

#### Ingestion
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/ingest-http` | Ingest HTTP data (burp_base64, curl, openapi, swagger, postman, url, url_file) |

### Pagination Format (all list endpoints)
```json
{
  "data": [...],
  "total": 1500,
  "limit": 50,
  "offset": 0,
  "has_more": true
}
```

### Error Format
```json
{
  "error": "error message",
  "code": 400,
  "details": "additional details..."
}
```

---

## Decisions Needed

1. **Vite + React** or **Next.js**? (Recommended: Vite for this SPA use case)
2. **AG Grid 35** (latest) or stick with **33.x**?
3. **Are the 5 theme suggestions good**, or different aesthetics in mind?
4. **Add `@tanstack/react-query`** for data fetching? (strongly recommended)
5. **Auth handling** — prompt for Bearer token, or assume no auth for dev?
