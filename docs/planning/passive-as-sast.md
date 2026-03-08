# Passive Modules as SAST: ScanScopeFile

## Problem Statement

Passive modules already perform pattern matching on HTTP response body content without sending traffic. This is functionally identical to what a static analysis tool does on source files. By adding a filesystem scanning scope, passive modules can naturally double as source-aware scanners — treating file contents the same way they treat response bodies.

## Current Architecture

### ScanScope (bitmask, `uint8` in `pkg/modules/modkit/types.go`)

| Constant | Value | Description |
|---|---|---|
| `ScanScopeInsertionPoint` | `1 << 0` (0x01) | Called per parameter/injection point |
| `ScanScopeRequest` | `1 << 1` (0x02) | Called once per unique request |
| `ScanScopeHost` | `1 << 2` (0x04) | Called once per unique host |

### PassiveScanScope (what data a passive module reads)

| Constant | Description |
|---|---|
| `PassiveScanScopeRequest` | Analyzes request only |
| `PassiveScanScopeResponse` | Analyzes response only |
| `PassiveScanScopeBoth` | Needs both request and response |

### How Passive Modules Work Today

1. Module declares `ScanScopeRequest` and `PassiveScanScopeResponse`
2. Executor feeds `*httpmsg.HttpRequestResponse` to `ScanPerRequest()`
3. Module calls `ctx.Response().BodyToString()` and runs regex/pattern matching
4. Returns `[]*output.ResultEvent` findings

Key insight: **passive modules never send traffic**. They are pure pattern matchers on byte content. The HTTP wrapping is incidental.

### Existing Source-Analysis Passive Modules

These modules already scan JS/TS/HTML response bodies for source-code patterns:

| Module | ID | What it scans |
|---|---|---|
| `unsafe_html_sink` | `passive-unsafe-html-sink` | `dangerouslySetInnerHTML`, `v-html`, `eval()`, `.innerHTML` |
| `insecure_token_storage` | `passive-insecure-token-storage` | `localStorage`/`sessionStorage` auth token patterns |
| `env_secret_exposure` | `passive-env-secret-exposure` | `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*` secrets, `.env` files |
| `build_misconfig_detect` | `passive-build-misconfig-detect` | Source maps, dev mode flags, dangerous SVG patterns |
| `dom_xss_detect` | `passive-dom-xss-detect` | Source-to-sink DOM XSS flows in `<script>` blocks |
| `secret_detect` | `passive-secret-detect` | Leaked secrets via Kingfisher engine |
| `ssr_data_exposure` | `passive-ssr-data-exposure` | `__NEXT_DATA__`, `__NUXT__` state blobs with sensitive data |

All of these would work on filesystem content with zero changes to their scanning logic.

## Design Decision: Option C (Hybrid)

### Approach

Add `ScanScopeFile` as a new scope bit for opt-in declaration, but dispatch file items through the existing `ScanPerRequest()` method. No new interface method needed.

### How It Works

1. **New scope bit**: `ScanScopeFile ScanScope = 1 << 3` (0x08)
2. **Every passive module** gets `ScanScopeFile` added to its scope bitmask (since passive modules are inherently pattern matchers that work on content)
3. **File content is wrapped** as a synthetic `HttpRequestResponse`:
   - File path → URL (using `file://` scheme)
   - File content → response body
   - Content-Type → inferred from file extension
4. **Dispatch reuses `ScanPerRequest()`** — the module sees a response body and scans it
5. **Dedup** uses content hash (not request hash) for file items
6. **ResultEvent** uses `Type: "file"` and `Matched` contains `filepath:line`

### Why Not the Other Options

**Option A (new `ScanPerFile` method):** Requires changing the `PassiveModule` interface, which is a breaking change for all 30+ passive modules. Adds a method that would largely duplicate `ScanPerRequest` logic.

**Option B (pure synthetic, no scope bit):** No way for modules to opt out of file scanning. No way to distinguish file vs HTTP in the executor. Modules can't have file-specific `CanProcess` logic.

**Option C wins** because: explicit opt-in via scope bit, no interface changes, existing scan methods reused, modules can distinguish file context via the `file://` scheme in the URL.

## Implementation Plan

### Files to Modify

#### 1. `pkg/modules/modkit/types.go` — Add ScanScopeFile constant

```go
const (
    ScanScopeInsertionPoint ScanScope = 1 << iota
    ScanScopeRequest
    ScanScopeHost
    ScanScopeFile // NEW: called once per file (filesystem content scanning)
)
```

Update `ScanScope.String()` to handle the new case (`"PER_FILE"`).

#### 2. `pkg/modules/types.go` — Re-export ScanScopeFile

```go
const (
    ScanScopeInsertionPoint = modkit.ScanScopeInsertionPoint
    ScanScopeRequest        = modkit.ScanScopeRequest
    ScanScopeHost           = modkit.ScanScopeHost
    ScanScopeFile           = modkit.ScanScopeFile
)
```

#### 3. `pkg/modules/modkit/defaults.go` — Update BasePassiveModule

- `NewBasePassiveModule` automatically ORs `ScanScopeFile` into the scan scope for all passive modules
- This makes every passive module file-capable by default since they already pattern-match on response content

#### 4. `pkg/output/output.go` — Add file-specific fields to ResultEvent

```go
type ResultEvent struct {
    // ... existing fields ...

    // File scanning fields
    FilePath   string `json:"file_path,omitempty"`   // Source file path
    LineNumber int    `json:"line_number,omitempty"`  // Line number in source file
}
```

- `Type` set to `"file"` for filesystem findings
- `Matched` uses `filepath:line` format
- `FilePath` and `LineNumber` are first-class fields for file findings

#### 5. `pkg/httpmsg/` — File-to-HttpRequestResponse adapter

Create a helper function to wrap file content as a synthetic `HttpRequestResponse`:

```go
func NewFileRequestResponse(filePath string, content []byte, contentType string) *HttpRequestResponse
```

- Constructs a synthetic `HttpRequest` with `file://` scheme, file path as URL path
- Constructs an `HttpResponse` with file content as body, inferred Content-Type
- Service uses `host: "localhost"`, `protocol: "file"`

#### 6. `pkg/core/executor.go` — Add file dispatch path

- Add `perFilePassive []modules.PassiveModule` field
- Filter passive modules by `ScanScopeFile` in `NewExecutor`
- Add `runPassivePerFile()` method following the same pattern as `runPassivePerRequest()`
- In `processItem`, detect file items (via `file://` scheme) and route to file dispatch
- `assignModuleInfo` handles `Type="file"` — skips URL extraction from request bytes

#### 7. Default registry — Passive modules get ScanScopeFile automatically

Since `NewBasePassiveModule` auto-ORs `ScanScopeFile`, no changes needed to individual module registrations. All passive modules automatically support file scanning.

### Dedup Strategy for Files

- Use **content hash** (SHA-256 of file content) as the dedup key
- Existing per-module `DiskSet` dedup works as-is — modules already key on host+path, which for files becomes the file path
- Modules using `dedup.Lazy[dedup.DiskSet]` keyed by `utils.Sha1(host)` will naturally group files under `localhost`

### CanProcess for File Items

- `BasePassiveModule.CanProcess` checks `PassiveScanScope` compatibility — file items have a synthetic response, so `PassiveScanScopeResponse` check passes
- Modules with custom `CanProcess` (e.g., `env_secret_exposure` checks content types) will work because the synthetic response carries inferred Content-Type headers
- Active modules' `BaseActiveModule.CanProcess` will reject file items (no valid HTTP URL, `file://` scheme) — this is correct behavior since active modules can't fuzz files

### Content-Type Inference

Map file extensions to MIME types for the synthetic response:

| Extension | Content-Type |
|---|---|
| `.js`, `.mjs` | `application/javascript` |
| `.ts`, `.tsx` | `text/typescript` |
| `.jsx` | `text/jsx` |
| `.html`, `.htm` | `text/html` |
| `.json` | `application/json` |
| `.env` | `text/plain` |
| `.vue` | `text/html` |
| `.svelte` | `text/html` |
| `.css` | `text/css` |
| `.xml` | `application/xml` |
| default | `text/plain` |

### Input Source for Files

A new `FileSystemSource` implementing `source.InputSource`:

- Walks a directory tree
- Reads each file, wraps via `NewFileRequestResponse()`
- Returns `*work.WorkItem` with the synthetic `HttpRequestResponse`
- Respects `.gitignore` patterns and configurable exclude globs
- Skips binary files (detected via `net/http.DetectContentType`)

### Verification

1. **Unit test**: Create a passive module, feed it a file-wrapped `HttpRequestResponse`, verify it finds patterns
2. **Integration test**: Use `env_secret_exposure` module on a real `.env` file, verify finding with `Type: "file"` and correct `FilePath`/`LineNumber`
3. **Executor test**: Feed `FileSystemSource` through executor, verify passive modules run on file items and active modules skip them
