# Deparos — Modern Adaptive Content Discovery

Deparos is an intelligent content discovery engine that performs directory enumeration, directory fuzzing, and endpoint discovery against web applications. It goes beyond static wordlist brute-forcing by learning from every response — adapting its strategy, growing its wordlists dynamically, and filtering false positives through fingerprint-based soft-404 detection.

## How It Works

```
Target URL
  │
  ▼
┌──────────────────────────────────────────────────────┐
│  Initialization                                      │
│  1. Probe target, extract host components            │
│  2. Fetch robots.txt                                 │
│  3. Learn baseline fingerprints (3-sample soft-404)  │
│  4. Load prior session data (if resuming)            │
│  5. Generate initial tasks from wordlists + observed │
└──────────────────┬───────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────┐
│  Priority Queue                                      │
│  ┌────┬────┬────┬────┬─────┬──────┬──────┬────────┐ │
│  │ P0 │ P1 │ P2 │ P4 │ P5  │ P7   │ P11  │ P12   │ │
│  │Spdr│Obs │Obs │Obs │Short│ExtVar│Long  │Fuzz   │ │
│  │ JS │Name│File│Dir │Word │Numric│Word  │       │ │
│  └────┴────┴────┴────┴─────┴──────┴──────┴────────┘ │
└──────────────────┬───────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────┐
│  Payload Coordinator                                 │
│  Expander pulls tasks → Expand() yields payloads     │
│  N workers execute payloads concurrently             │
│                                                      │
│  For each response:                                  │
│    Fingerprint check (soft-404?) ──→ discard         │
│    WAF detection ──→ track/backoff                   │
│    Real discovery ──→ callbacks                      │
└──────────────────┬───────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────┐
│  Discovery Callbacks                                 │
│  OnDirectoryDiscovered():                            │
│    • Learn new fingerprints for directory             │
│    • Create recursive tasks (wordlists + observed)   │
│    • Extract breadcrumb directories                  │
│  OnFileDiscovered():                                 │
│    • Extract extension → trigger extension tasks     │
│    • Numeric segment → fuzz ±10 variations           │
│    • Queue extension variant probes (.bak, .old, …)  │
└──────────────────┬───────────────────────────────────┘
                   ▼
        ┌──── loop back to Priority Queue ────┐
        │  (new tasks from discoveries)       │
        └─────────────────────────────────────┘
```

## What Makes It Adaptive

### 1. Fingerprint-Based Soft-404 Detection

Before scanning, the engine requests 3 random non-existent paths and extracts response attributes (status code, content-type, headers, body hash, content-length ranges). Only attributes **stable across all 3 samples** become the baseline signature. During scanning, responses matching this signature are discarded as false positives.

When an unknown response pattern appears, a 4-strategy wildcard validation (prefix, suffix, extension, middle) confirms whether the discovery is real or a new soft-404 variant — and learns the new pattern.

### 2. Observed Collection System

Four data pools grow continuously during the scan:

| Pool | Source | Priority |
|------|--------|----------|
| Observed Names | Spider links, JS parsing, response body tokenization | P1 |
| Observed Files | Complete filenames from discoveries | P2 |
| Observed Extensions | File extensions from discoveries | P5 |
| Observed Paths | Full path segments from URLs | P4 |

Every newly discovered directory is probed with ALL observed values as high-priority tasks. When a new extension is found for the first time, it triggers tasks across ALL known directories.

### 3. JavaScript Intelligence

Two layers of JS analysis feed endpoints back into the discovery queue:

- **JSScan** (embedded binary): Deobfuscates bundled JS, resolves string concatenation, traces variable assignments, and extracts `fetch()` / `XMLHttpRequest` / `$.ajax` call sites into full HTTP request specs.
- **Spider extractors**: Parse inline `<script>` tags and JS string literals for URL patterns.

Extracted endpoints become priority-0 tasks — tested before any wordlist fuzzing.

### 4. Dynamic Wordlist Growth

Response bodies are tokenized (content-type-aware for HTML, JSON, JS, CSS) to extract candidate words. These feed into the observed name pool and are replayed against every directory.

### 5. Recursive Directory Expansion

When a file is found at `/a/b/c/file.txt`, the engine extracts `/a/`, `/a/b/`, `/a/b/c/` as directories to test. Each new directory triggers its own full task set (wordlists + observed + modules).

## Task Types

| Task | Priority | Description |
|------|----------|-------------|
| Spider/JS Extracted | 0 | URLs from link extraction and JS analysis |
| Observed Names | 1 | Filenames seen during scan, replayed per directory |
| Observed Files | 2 | Complete name+extension pairs |
| Observed Paths | 4 | Full path segments from URLs |
| Short Wordlist (files) | 5 | Common filenames from short wordlist × extensions |
| Short Wordlist (dirs) | 6 | Common directory names from short wordlist |
| Extension Variants | 7 | Backup/alternate extensions (.bak, .old, .zip, .tar.gz) |
| Numeric Fuzz | 7 | ±10 variations of numeric path segments |
| Long Wordlist (files) | 9 | Extended filename dictionary × extensions |
| Long Wordlist (dirs) | 11 | Extended directory dictionary |
| FUZZ | 12 | Template-based fuzzing (`FUZZ` marker replacement) |

## Deduplication

Multiple layers prevent redundant work:

- **Task-level**: FNV-1a hash prevents duplicate task enqueueing
- **Request-level**: Cache prevents sending the same HTTP request twice
- **URL-level**: DiskSet tracks processed URLs
- **Body-level**: Hash prevents re-analyzing identical responses with JSScan
- **Directory/file trackers**: Prevent re-processing the same discovery

## Built-In Modules

YAML-configured modules trigger specialized tasks when matching directories are found:

| Module | Triggers On | What It Does |
|--------|-------------|--------------|
| `backup` | Any directory | Tests backup extensions (.bak, .old, .zip, .tar.gz) |
| `js` | Any directory | Tests .js, .mjs, .map extensions |
| `api` | `/api/`, `/v1/`, etc. | REST/GraphQL/SOAP endpoint wordlists |
| `admin` | `/admin/`, `/manage/` | Admin panel paths |
| `docs` | `/docs/`, `/api-docs/` | Swagger, OpenAPI, GraphQL playground |
| `static` | `/static/`, `/assets/` | Blocks recursion to avoid noise |

## Supporting Systems

| Component | Purpose |
|-----------|---------|
| **WAF Detection** | Identifies Cloudflare, Akamai, AWS WAF, F5, Imperva, Sucuri, ModSecurity. Tracks consecutive blocks for backoff/early exit |
| **Scope Enforcement** | Three modes: `any` (no check), `subdomain` (same eTLD+1), `exact` (same host). Checked on every discovery and redirect |
| **Case Sensitivity Detection** | Auto-detected on first file discovery by re-requesting with altered casing |
| **Storage** | SQLite-backed sitemap with semantic dedup (FNV-1a-64). Supports session comparison for differential scanning across runs |

## Integration with Vigolium

Deparos runs as an input source (`DeparosDiscoverySource`) in the scanning pipeline. Each discovery is converted to an `httpmsg.HttpRequestResponse` and fed to the executor as a work item — where it flows through active and passive vulnerability scanning modules.

```
DeparosDiscoverySource.Next()
  → Engine.Start() → discoveries stream out
  → Convert to httpmsg.HttpRequestResponse
  → Save to DB (optional)
  → Return as WorkItem → Executor → Scanner Modules
```
