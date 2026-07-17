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
│  │ P0 │ P1 │ P2 │ P4 │ P5-6 │ P7   │ P8-11│ P12 │ │
│  │Spdr│JSReq│Obs │Obs │Short │ExtVar│Long  │Fuzz │ │
│  │ JS │Name │File│Path│Words │Numeric│Words │     │ │
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
│    • Numeric segment → optional ±10 fuzz variations  │
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
| Observed Names | Spider links, JS parsing, response body tokenization | P1-P3 depending on extension source |
| Observed Files | Complete filenames from discoveries | P2 |
| Observed Extensions | File extensions confirmed from application evidence | Combined with observed/short/long file tasks at P3, P6, and P11 |
| Observed Paths | Full paths from URLs | P4 |

Every newly discovered directory is probed with ALL observed values as high-priority tasks. When a new extension is found for the first time, it triggers tasks across ALL known directories.

### 3. JavaScript Intelligence

Two layers of JS analysis feed the discovery graph:

- **JSTangle** uses a shared, memory-bounded worker pool. It emits typed HTTP
  templates plus JavaScript chunks/workers/source maps, GraphQL operations,
  WebSocket/SSE metadata, client routes, and browser-side flow evidence.
- **Spider/LinkFinder extractors** retain a cheap URL-string fallback for code
  that cannot or should not enter full AST analysis.

Request facts keep their source script, method, body, confidence, and source
span. High-confidence facts use exact replay. Medium-confidence facts are only
replayed when `replay_mode: conservative`; low-confidence strings remain hints.
Sensitive or browser-controlled headers are never copied into replay traffic.

Asset references form a bounded recursive graph, so lazy chunks, workers, and
service workers are fetched and analyzed once. Source maps are fetched under the
normal scope/auth/rate policy; recovered sources are retained as immutable scan
artifacts. WebSocket/SSE handshakes are opt-in and never pass through ordinary
HTTP variant generation.

Large input degrades visibly: transformed output is dropped first, then a
bounded lexical endpoint/asset pass is used. Hard-limit input is rejected with a
diagnostic. A summary reports worker jobs, cache hits, extracted fact confidence,
fallbacks, and worker restarts when discovery stops.

### 4. Dynamic Wordlist Growth

Response bodies are tokenized (content-type-aware for HTML, JSON, JS, CSS) to extract candidate words. These feed into the observed name pool and are replayed against every directory.

### 5. Recursive Directory Expansion

When a file is found at `/a/b/c/file.txt`, the engine extracts `/a/`, `/a/b/`, `/a/b/c/` as directories to test. Each new directory triggers its own full task set (wordlists + observed + modules).

## Task Types

| Task | Priority | Description |
|------|----------|-------------|
| Spider, JS fetch, form submission | 0 | Highest-confidence URLs and assets from browser/link extraction |
| JS extracted requests | 1 | Typed requests recovered from JavaScript |
| Observed filenames without extension | 1 | Server-leaked names replayed per directory |
| Observed files/directories/literal filenames | 2 | Complete observed resources and directories |
| Observed names × observed extensions | 3 | Confirmed application names combined with confirmed extensions |
| Observed paths | 4 | Full paths recovered from URLs |
| Short files without extension | 5 | Common short filename dictionary |
| Short directories/files with extensions | 6 | Common directory names and short filename combinations |
| Extension variants | 7 | Backup/alternate extensions (`.bak`, `.old`, `.zip`, `.tar.gz`) |
| Numeric fuzz | 7 | ±10 variants of numeric path segments when `enable_numeric_fuzzing` is enabled (off by default) |
| Long files without extension | 8 | Extended filename dictionary |
| Long directories/files with configured extensions | 9 | Extended wordlist combinations |
| Malformed-path probe | 10 | Detects path-normalization and routing behavior |
| Long files with observed extensions | 11 | Lowest-priority long-wordlist extension combinations |
| FUZZ | 12 | Template-based fuzzing (`FUZZ` marker replacement) |

## Deduplication

Multiple layers prevent redundant work:

- **Task-level**: FNV-1a hash prevents duplicate task enqueueing
- **Request-level**: Cache prevents sending the same HTTP request twice
- **URL-level**: DiskSet tracks processed URLs
- **Body-level**: Hash prevents re-analyzing identical responses with JSTangle
- **Directory/file trackers**: Prevent re-processing the same discovery

## Discovery Modules

The only compiled-in discovery module is `wildcard`, which suppresses work under wildcard/catch-all paths. Additional modules are user-defined in YAML through `module-definitions.custom`; they can match paths, segments, filenames, extensions, or globs and then stop recursion, skip default logic, enqueue wordlist tasks, or block matching tasks. Names such as `backup`, `api`, or `static` are examples of custom policy, not guaranteed built-ins.

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
