# SPA — Single Page Application Scanning

SPA scanning extends Spitolas's browser-based crawling with specific handling for JavaScript-heavy applications where traditional crawling fails. SPAs render content client-side, load data via async API calls, and manage navigation through framework routers — none of which is visible to a static HTTP crawler.

## Why SPA Scanning Matters

Traditional crawlers see only the initial HTML shell of an SPA. The actual application state — routes, forms, authenticated views, API interactions — only materializes after JavaScript execution. SPA scanning bridges this gap by driving a real browser and interacting with the rendered DOM.

## How It Works

```
Target URL (SPA)
  │
  ▼
┌─────────────────────────────────────────────────┐
│  Browser Engine (Chromium via rod)               │
│  • Full JS execution, framework router support   │
│  • CDP network capture (all XHR/fetch traffic)   │
│  • DOM mutation observation                      │
└────────────────────┬────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────┐
│  State Discovery                                 │
│  • DOM snapshot → SHA256 state ID                │
│  • Near-duplicate detection (Levenshtein 10%)    │
│  • Fragment-based visual page segmentation       │
└────────────────────┬────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────┐
│  Interaction Engine                              │
│  • Click buttons, links, [ng-click], [v-on] etc  │
│  • Fill and submit forms (field-aware values)    │
│  • Trigger hover, keyboard, custom events        │
│  • Traverse iframes and popups                   │
└────────────────────┬────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────┐
│  Traffic Capture → Scanning Pipeline             │
│  CDP events → HttpRequestResponse                │
│  → Executor → Active + Passive Modules           │
└─────────────────────────────────────────────────┘
```

## Key Capabilities

### Client-Side Route Discovery

SPAs use framework routers (React Router, Vue Router, Angular Router) that don't generate server requests on navigation. The crawler detects route changes by comparing DOM snapshots after each interaction, building a state graph of all reachable application views.

### Async API Capture

All `fetch()`, `XMLHttpRequest`, and WebSocket traffic generated during crawling is captured at the CDP level. This surfaces the real API surface — REST endpoints, GraphQL queries, authentication flows — that the SPA communicates with behind the scenes.

### Form Handling

The form handler generates context-aware values for SPA form fields:

- Field-name pattern matching (email, password, phone, URL, date)
- HTML5 constraint compliance (`pattern`, `min`/`max`, `minlength`/`maxlength`)
- Pairwise fallback when batch filling fails
- File upload with type-aware file selection

### Adaptive Exploration

Two strategies control how the crawler prioritizes unexplored actions:

| Strategy | Description |
|----------|-------------|
| Default (BFS/DFS) | Deterministic traversal with fragment-based prioritization |
| `adaptive` | Exp3.1 multi-armed bandit — balances exploitation of known-good actions with exploration of untried ones via reward-based probability sampling |

### JavaScript Analysis

Two layers extract endpoints from JavaScript code:

- **JSScan**: Deobfuscates bundled JS, resolves string concatenation, traces variable assignments, extracts `fetch()`/`XMLHttpRequest`/`$.ajax` call sites
- **Spider extractors**: Parse inline `<script>` tags and JS string literals for URL patterns

Extracted endpoints become priority-0 discovery tasks — tested before any wordlist fuzzing.

## Integration

SPA scanning feeds into the main pipeline through Spitolas's `RecordSaver` interface. Every captured request/response pair is converted to `HttpRequestResponse` and passed to the executor, where it flows through the full active and passive module stack — the same as any other traffic source.

```
Spitolas SPA Crawl
  → CDP network capture
  → HttpRequestResponse conversion
  → RecordSaver (database)
  → Executor → Scanner Modules
```
