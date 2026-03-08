# Module Development Guide

This guide explains how to write new scanner modules for Vigolium. It covers the module interfaces, the scanning pipeline, and walks through creating both active and passive modules with complete examples.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [YAML / JS Extensions vs Go Modules](#yaml--js-extensions-vs-go-modules)
- [Module Interfaces](#module-interfaces)
- [Base Types](#base-types)
- [Key Concepts](#key-concepts)
- [Creating an Active Module](#creating-an-active-module)
- [Creating a Passive Module](#creating-a-passive-module)
- [ResultEvent: Reporting Findings](#resultevent-reporting-findings)
- [Deduplication](#deduplication)
- [Registration](#registration)
- [Testing](#testing)
- [Checklist](#checklist)

---

## Architecture Overview

The scanning pipeline flows through these stages:

```
InputSource → Executor.feedItems() → Worker Pool → processItem()
                                                      │
                                   ┌──────────────────┘
                                   ▼
                            Fetch baseline response
                                   │
                            Run pre-hooks (JS/YAML, optional)
                                   │
                            Scope check
                                   │
                            Save to database (optional)
                                   │
                     ┌─────────────┼──────────────┐
                     ▼             ▼              ▼
              Passive modules  Active modules  Active modules
              (per-host,       (per-host,      (per-insertion-point)
               per-request)     per-request)
                     │             │              │
                     └─────────────┼──────────────┘
                                   ▼
                            processResults()
                                   │
                            assignModuleInfo() → fills ModuleID, severity, etc.
                                   │
                            Run post-hooks (JS/YAML, optional)
                                   │
                            emitResult() → output writer, database, notifications
```

Key points:

- **Modules are registered in a `Registry`** at program startup. The `DefaultRegistry` in `pkg/modules/default_registry.go` contains all built-in modules. Extension modules (JS and YAML) are loaded at runtime via the `jsext.Engine` and registered alongside built-in modules.
- **The Executor groups modules by `ScanScope`** at construction time for efficient dispatch.
- **Each module's `CanProcess()` is called before scanning** — modules can skip items they cannot handle.
- **For per-insertion-point modules**, the executor creates all insertion points from the request, then calls `ScanPerInsertionPoint` for each (module, insertion-point) pair where the insertion point type is in the module's `AllowedInsertionPointTypes()`.
- **Modules must be thread-safe** — multiple workers call scan methods concurrently.
- **The executor auto-fills `ModuleID`, `Info.Name`, `Info.Severity`, `Info.Confidence`** from the module metadata if not set in the `ResultEvent`. Modules only need to set fields specific to the finding.
- **Hooks** can be defined as JS extensions, YAML extensions (`.vgm.yaml`), or both. They run in registration order — all pre-hooks execute before modules, all post-hooks execute after.
- **OAST and mutation** are available via `ScanContext.OASTProv()` and `ScanContext.MutGen()` — modules can generate out-of-band callback URLs and value-aware mutations without importing those packages directly.

---

## YAML / JS Extensions vs Go Modules

Before writing a Go module, consider whether a **YAML extension** (`.vgm.yaml`) or **JavaScript extension** (`.js`) would suffice. Extensions don't require recompiling and are loaded at runtime from `~/.vigolium/extensions/`.

| Approach | Best for | Limitations |
|----------|----------|-------------|
| **YAML extension** | Declarative payload+matcher patterns, header hooks, request filtering, severity escalation | No custom HTTP calls, no state, no dedup |
| **JS extension** | Programmatic logic, custom HTTP calls, complex multi-step checks | ES5.1 only, no imports, no dedup |
| **Go module** | Performance-critical scanning, dedup integration, OAST/mutation support, complex analysis | Requires recompile, registration in registry |

Use a Go module when you need:
- **Deduplication** via `RequestHashManager` or `DiskSet` — extensions run on every matching item
- **OAST integration** — out-of-band callback URL generation via `ScanContext.OASTProv()`
- **Mutation engine** — value-aware payload generation via `ScanContext.MutGen()`
- **Baseline comparison** — `ScanContext.GetOrFetchBaseline()` for differential analysis
- **Complex stateful analysis** — e.g., buffering data across requests with `Flusher`

For the extension approach, see [Writing Extensions](./writing-extensions.md).

---

## Module Interfaces

All interfaces live in `pkg/modules/`.

### Base Module

Every module (active or passive) implements the `Module` interface:

```go
// pkg/modules/module.go
type Module interface {
    ID() string                                        // e.g. "active-crlf-injection"
    Name() string                                      // e.g. "CRLF Injection"
    Description() string                               // Detailed description (may contain markdown)
    ShortDescription() string                          // One-line summary for listings
    ConfirmationCriteria() string                      // How this module confirms a finding
    Severity() severity.Severity                       // severity.Info | Low | Medium | High | Critical
    Confidence() severity.Confidence                   // severity.Tentative | Firm | Certain
    ScanScopes() ScanScope                     // Bitmask: when the module runs
    Tags() []string                                    // Classification tags (e.g. "spring", "xss", "light")
    CanProcess(ctx *httpmsg.HttpRequestResponse) bool   // Per-item filter
}
```

The `Tags()` method returns classification tags for the module. Tags are used by the `--module-tag` CLI flag and `?tag=` API parameter to filter which modules run. Common tag conventions:

- **Framework tags**: `spring`, `rails`, `django`, `flask`, `laravel`, `express`, `nextjs`, `aspnet`, `firebase`
- **Vulnerability type tags**: `xss`, `sqli`, `injection`, `ssrf`, `ssti`, `rce`, `misconfiguration`
- **Weight tags**: `light` (fast, low request count), `moderate`, `heavy` (slow, many requests)

### Active Module

Active modules send HTTP requests to detect vulnerabilities:

```go
// pkg/modules/active.go
type ActiveModule interface {
    Module

    AllowedInsertionPointTypes() InsertionPointTypeSet

    ScanPerInsertionPoint(
        ctx *httpmsg.HttpRequestResponse,
        ip httpmsg.InsertionPoint,
        httpClient *http.Requester,
        scanCtx *ScanContext,
    ) ([]*output.ResultEvent, error)

    ScanPerRequest(
        ctx *httpmsg.HttpRequestResponse,
        httpClient *http.Requester,
        scanCtx *ScanContext,
    ) ([]*output.ResultEvent, error)

    ScanPerHost(
        ctx *httpmsg.HttpRequestResponse,
        httpClient *http.Requester,
        scanCtx *ScanContext,
    ) ([]*output.ResultEvent, error)
}
```

You only need to implement the scan method(s) matching your `ScanScopes()`. The base type provides panic stubs for the others.

### Passive Module

Passive modules analyze existing HTTP traffic without sending additional requests:

```go
// pkg/modules/passive.go
type PassiveModule interface {
    Module

    Scope() PassiveScanScope

    ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *ScanContext) ([]*output.ResultEvent, error)
    ScanPerHost(ctx *httpmsg.HttpRequestResponse, scanCtx *ScanContext) ([]*output.ResultEvent, error)
}
```

### Flusher (optional)

Passive modules that buffer data across requests can implement `Flusher` for end-of-scan finalization:

```go
// pkg/modules/passive.go
type Flusher interface {
    Flush(scanCtx *ScanContext)
}
```

The executor calls `Flush` after all workers finish processing.

---

## Base Types

The `pkg/modules/modkit` package provides base structs that implement most of the `Module` interface for you. You almost always want to embed one of these.

### BaseActiveModule

```go
// pkg/modules/modkit/defaults.go
type BaseActiveModule struct {
    BaseModule
    AllowedIPTypes InsertionPointTypeSet
}
```

**Provides for free:**
- `ID()`, `Name()`, `Description()`, `ShortDescription()`, `ConfirmationCriteria()`, `Severity()`, `Confidence()`, `ScanScopes()` — all return values from struct fields
- `AllowedInsertionPointTypes()` — returns `AllowedIPTypes` (or `AllInsertionPointTypes` if zero)
- `CanProcess()` — skips media/JS files and `OPTIONS`/`CONNECT`/`HEAD`/`TRACE` methods
- Panic stubs for `ScanPerInsertionPoint`, `ScanPerRequest`, `ScanPerHost` — override only the ones matching your `ScanScopes`

**Constructor:**

```go
modkit.NewBaseActiveModule(
    id string,                     // Must start with "active-", kebab-case, lowercase
    name string,
    description string,            // Detailed markdown description (see Description Format below)
    shortDesc string,              // One-line summary for listings
    confirmationCriteria string,   // How this module confirms a finding
    sev severity.Severity,
    conf severity.Confidence,
    scanTypes ScanScope,
    allowedIPTypes InsertionPointTypeSet,
)
```

The constructor validates the ID format at startup (panics on violations).

### BasePassiveModule

```go
// pkg/modules/modkit/defaults.go
type BasePassiveModule struct {
    BaseModule
    ModuleScope PassiveScanScope
}
```

**Provides for free:**
- All `Module` methods (same as `BaseActiveModule`)
- `Scope()` — returns `ModuleScope` (or `PassiveScanScopeBoth` if zero)
- `CanProcess()` — checks scope compatibility (e.g., response required but not available)
- Panic stubs for `ScanPerRequest`, `ScanPerHost`

**Constructor:**

```go
modkit.NewBasePassiveModule(
    id string,                     // Must start with "passive-", kebab-case, lowercase
    name string,
    description string,            // Detailed markdown description
    shortDesc string,              // One-line summary
    confirmationCriteria string,   // How this module confirms a finding
    sev severity.Severity,
    conf severity.Confidence,
    scanTypes ScanScope,
    scope PassiveScanScope,
)
```

---

## Key Concepts

### ScanScope

Bitmask that controls when the executor invokes your module. Defined in `pkg/modules/modkit/types.go`:

| Constant | Value | Called | Use Cases |
|----------|-------|--------|-----------|
| `ScanScopeInsertionPoint` | `1` | For each insertion point in each request | XSS, SQLi, CRLF, SSTI, command injection |
| `ScanScopeRequest` | `2` | Once per unique request | Missing headers, auth bypass, DOM XSS |
| `ScanScopeHost` | `4` | Once per unique host | Server fingerprinting, common path discovery |

Combine with bitwise OR: `ScanScopeInsertionPoint | ScanScopeRequest`.

### InsertionPointTypeSet

Controls which insertion point types your active module accepts. Only applies when `ScanScopeInsertionPoint` is set.

**Presets** (defined in `pkg/modules/modkit/types.go`):

| Preset | Includes |
|--------|----------|
| `AllInsertionPointTypes` | Everything (default if zero) |
| `URLParamTypes` | `INS_PARAM_URL`, `INS_PARAM_NAME_URL`, `INS_URL_PATH_FOLDER`, `INS_URL_PATH_FILENAME` |
| `BodyParamTypes` | `INS_PARAM_BODY`, `INS_PARAM_NAME_BODY`, `INS_PARAM_JSON`, `INS_PARAM_XML`, `INS_PARAM_XML_ATTR`, `INS_PARAM_MULTIPART_ATTR`, `INS_ENTIRE_BODY` |
| `CookieTypes` | `INS_PARAM_COOKIE` |
| `HeaderTypes` | `INS_HEADER` — covers both existing injectable headers and synthetic headers (X-Forwarded-For, X-Forwarded-Host, Referer, True-Client-IP, X-Real-IP) |
| `AllParamTypes` | `URLParamTypes \| BodyParamTypes \| CookieTypes \| HeaderTypes` |

**Custom set:**

```go
modkit.NewInsertionPointTypeSet(
    httpmsg.INS_PARAM_URL,
    httpmsg.INS_PARAM_BODY,
    httpmsg.INS_PARAM_JSON,
)
```

### Severity and Confidence

Defined in `pkg/types/severity/severity.go`:

**Severity levels:** `Info` < `Low` < `Medium` < `High` < `Critical`

**Confidence levels:**
| Level | Meaning |
|-------|---------|
| `Tentative` | Possible but unconfirmed (heuristic-based) |
| `Firm` | Likely confirmed by behavioral analysis |
| `Certain` | Definitively confirmed (payload executed, error matched) |

### PassiveScanScope

Controls what parts of the HTTP transaction a passive module needs:

| Scope | Value | Meaning |
|-------|-------|---------|
| `PassiveScanScopeRequest` | `1` | Analyze request only |
| `PassiveScanScopeResponse` | `2` | Analyze response only |
| `PassiveScanScopeBoth` | `3` | Analyze both request and response |

The base `CanProcess()` uses this to skip items where the required data is not available.

### ScanContext

Shared resources passed to every scan method:

```go
// pkg/modules/modkit/context.go
type ScanContext struct {
    DedupManager        *dedup.Manager          // Deduplication storage
    RiskScoreUpdater    RiskScoreUpdater        // Update risk scores in DB
    RequestUUIDResolver RequestUUIDResolver     // Map request hash → DB UUID
    OASTProvider        OASTProvider            // Generate OAST callback URLs
    MutationGen         MutationGenerator       // Value-aware mutation engine
}
```

Safe accessors: `DedupMgr()`, `OASTProv()`, `MutGen()` — all nil-safe, return `nil` (or a default fallback for `MutGen`) if `ScanContext` is `nil`.

#### OASTProvider

Modules can generate out-of-band callback URLs for blind vulnerability detection:

```go
type OASTProvider interface {
    GenerateURL(targetURL, paramName, injectionType, moduleID, requestHash string) string
    Enabled() bool
}
```

Usage in a scan method:

```go
oast := scanCtx.OASTProv()
if oast != nil && oast.Enabled() {
    callbackURL := oast.GenerateURL(urlx.String(), ip.Name(), "ssrf", m.ID(), ctx.Request().Hash())
    // Inject callbackURL as payload
}
```

#### MutationGenerator

Modules can generate type-aware mutations for smarter fuzzing:

```go
type MutationGenerator interface {
    Classify(value string, hint *mutation.SchemaHint) mutation.ValueType
    Generate(value string, vtype mutation.ValueType, opts *mutation.GenerateOptions) mutation.MutationSet
}
```

Usage in a scan method:

```go
mutGen := scanCtx.MutGen()
vtype := mutGen.Classify(ip.BaseValue(), nil)
mutations := mutGen.Generate(ip.BaseValue(), vtype, nil)
for _, m := range mutations.Mutations {
    // m.Value is the mutated value, m.Intent is the mutation intent
}
```

### InsertionPoint

The `httpmsg.InsertionPoint` interface represents a fuzzable location in an HTTP request:

```go
// pkg/httpmsg/insertion_point.go
type InsertionPoint interface {
    Name() string                       // Parameter name (e.g. "id", "username")
    BaseValue() string                  // Original value before injection
    Type() InsertionPointType           // INS_PARAM_URL, INS_PARAM_JSON, etc.
    BuildRequest(payload []byte) []byte // Build new request with payload injected
    PayloadOffsets(payload []byte) []int // Byte offsets of payload in built request
}
```

`BuildRequest` handles encoding automatically based on the insertion point type (URL encoding for query params, JSON escaping for JSON values, etc.).

---

## Creating an Active Module

This walkthrough creates a CRLF injection scanner — a real module from the codebase (`pkg/modules/active/crlf_injection/scanner.go`).

### Step 1: Create the Package

```
pkg/modules/active/crlf_injection/
└── scanner.go
```

Convention: one directory per module under `pkg/modules/active/`, package name matches the directory (snake_case).

### Step 2: Define Constants

Create a `metadata.go` file in your module's directory (e.g., `pkg/modules/active/crlf_injection/metadata.go`):

```go
package crlf_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
    ModuleID    = "active-crlf-injection"
    ModuleName  = "CRLF Injection"
    ModuleShort = "Detects CRLF injection"
)

var (
    ModuleDesc = `## Description
Detects CRLF injection vulnerabilities in HTTP headers by injecting carriage return and
line feed characters and checking if they appear in response headers.

## Notes
- Tests URL parameters for header injection via CRLF sequences
- Can lead to HTTP response splitting and header injection attacks

## References
- https://owasp.org/www-community/vulnerabilities/CRLF_Injection`

    ModuleConfirmation = "Confirmed when injected CRLF sequences appear in HTTP response headers, indicating header injection"
    ModuleSeverity     = severity.Medium
    ModuleConfidence   = severity.Firm
    ModuleTags         = []string{"injection", "header-security", "light"}
)
```

**Constant conventions:**
- `ID` and `Name` remain `const` (short, single-line strings)
- `ShortDescription` remains `const` (one-line summary used in CLI listings)
- `Desc` is a `var` using a backtick multi-line string with structured markdown headings (`## Description`, `## Notes`, `## References`)
- `Confirmation` is a `var` — a single sentence describing **how** the module confirms a finding (e.g. "Confirmed when...", "Indicated when...")
- `Severity` and `Confidence` are `var` since they reference the `severity` package

**ID rules:**
- Must start with `"active-"` (enforced at startup — panics otherwise)
- Must be lowercase kebab-case (no underscores)
- Must be unique across all modules

**Description format:**

Module descriptions use structured markdown with these sections:

| Section | Required | Purpose |
|---------|----------|---------|
| `## Description` | Yes | What the module does and how it works |
| `## Notes` | Yes | Implementation details, limitations, bullet-point list |
| `## References` | No | Links to relevant research, OWASP pages, or tool documentation |

**Confirmation criteria:**

The `Confirmation` constant documents the specific condition that must be met for the module to report a finding. Use one of these prefixes:
- **"Confirmed when..."** — for high-confidence modules (`Certain` or `Firm`) where the finding is definitively verified
- **"Indicated when..."** — for low-confidence modules (`Tentative`) where the signal suggests but does not prove a vulnerability

### Step 3: Define the Module Struct

```go
package crlf_injection

import (
    "fmt"
    "regexp"

    "github.com/pkg/errors"
    "github.com/vigolium/vigolium/pkg/core/hosterrors"
    "github.com/vigolium/vigolium/pkg/dedup"
    "github.com/vigolium/vigolium/pkg/http"
    "github.com/vigolium/vigolium/pkg/httpmsg"
    "github.com/vigolium/vigolium/pkg/modules/modkit"
    "github.com/vigolium/vigolium/pkg/output"
    "github.com/vigolium/vigolium/pkg/utils"
)

type Module struct {
    modkit.BaseActiveModule                            // Embed base type
    randomStr           string                         // Module-specific state
    payloads            []string
    patternCookieTamper *regexp.Regexp
    rhm                 dedup.Lazy[dedup.RequestHashManager]  // Lazy dedup
}
```

### Step 4: Write the Constructor

```go
func New() *Module {
    randomStr := "Tamper=" + utils.RandomString(12)
    payloads := []string{
        "Set-cookie: " + randomStr,
        "any\r\nSet-cookie: " + randomStr,
        "any?\r\nSet-cookie: " + randomStr,
        "any\nSet-cookie: " + randomStr,
        "any?\nSet-cookie: " + randomStr,
        "any\r\nSet-cookie: " + randomStr + "\r\n",
        "any?\r\nSet-cookie: " + randomStr + "\r\n",
    }

    m := &Module{
        BaseActiveModule: modkit.NewBaseActiveModule(
            ModuleID,
            ModuleName,
            ModuleDesc,
            ModuleShort,
            ModuleConfirmation,                     // Confirmation criteria
            ModuleSeverity,
            ModuleConfidence,
            modkit.ScanScopeInsertionPoint,   // Scan check type
            modkit.URLParamTypes,                    // Insertion point filter
        ),
        randomStr:           randomStr,
        payloads:            payloads,
        patternCookieTamper: regexp.MustCompile(`(?mi)\nSet-cookie: ` + randomStr),
        rhm:                 dedup.LazyDefaultRHM("crlf_injection"),
    }
    m.ModuleTags = ModuleTags
    return m
}
```

Tags are assigned after construction by setting the `ModuleTags` field on the embedded `BaseActiveModule`. This pattern is used by all modules.

### Step 5: Implement the Scan Method

Only implement methods matching your `ScanScopes()`. This module uses `ScanScopeInsertionPoint`, so implement `ScanPerInsertionPoint`:

```go
func (m *Module) ScanPerInsertionPoint(
    ctx *httpmsg.HttpRequestResponse,
    ip httpmsg.InsertionPoint,
    httpClient *http.Requester,
    scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
    urlx, err := ctx.URL()
    if err != nil {
        return nil, errors.Wrap(err, "failed to get URL")
    }

    // Dedup check: skip if we already scanned this insertion point
    rhm := m.rhm.Get(scanCtx.DedupMgr())
    if rhm != nil {
        paramName := ip.Name()
        paramType := fmt.Sprintf("%d", ip.Type())
        if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
            return nil, nil
        }
    }

    var results []*output.ResultEvent

    for _, payload := range m.payloads {
        // Append payload to original value
        fullPayload := ip.BaseValue() + payload

        // Build fuzzed request with payload injected
        fuzzedRaw := ip.BuildRequest([]byte(fullPayload))

        // Parse the fuzzed raw request
        fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
        if err != nil {
            continue
        }
        fuzzedReq = fuzzedReq.WithService(ctx.Service())

        // Send the request
        resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
        if err != nil {
            if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
                return results, nil  // Host is down, stop scanning
            }
            continue
        }

        // Check if payload was reflected in response headers
        matches := m.patternCookieTamper.FindStringSubmatch(resp.Headers().String())
        if matches != nil {
            results = append(results, &output.ResultEvent{
                URL:              urlx.String(),
                Request:          string(fuzzedRaw),
                Response:         resp.Headers().String(),
                FuzzingParameter: ip.Name(),
                ExtractedResults: []string{payload},
                Info: output.Info{
                    Description: fmt.Sprintf("String reflected in %q", matches),
                },
            })
            resp.Close()
            return results, nil  // Found — stop testing this insertion point
        }
        resp.Close()
    }

    return results, nil
}
```

**Important patterns in the scan method:**

1. **Always close responses** — call `resp.Close()` after use.
2. **Handle `hosterrors.ErrUnresponsiveHost`** — return immediately when the host is down.
3. **Use `ip.BuildRequest()`** to inject payloads — it handles encoding.
4. **Copy `HttpService`** with `fuzzedReq.WithService(ctx.Service())`.
5. **Return early on first finding** for the insertion point (optional, but common).
6. **Don't set `ModuleID`, `Info.Name`, `Info.Severity`, `Info.Confidence`** — the executor fills these from your module's metadata.

---

## Creating a Passive Module

This walkthrough creates a DOM XSS detector — a real module from the codebase (`pkg/modules/passive/dom_xss_detect/scanner.go`).

### Step 1: Create the Package

```
pkg/modules/passive/dom_xss_detect/
└── scanner.go
```

Convention: one directory per module under `pkg/modules/passive/`.

### Step 2: Define Constants

Create a `metadata.go` file in your module's directory (e.g., `pkg/modules/passive/dom_xss_detect/metadata.go`):

```go
package dom_xss_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
    ModuleID    = "passive-dom-xss-detect"
    ModuleName  = "DOM XSS Detect"
    ModuleShort = "Detects potential DOM-based XSS patterns in responses"
)

var (
    ModuleDesc = `## Description
Passively detects potential DOM-based XSS patterns by analyzing JavaScript code in
responses for dangerous source-to-sink data flows.

## Notes
- Scans response bodies for known DOM XSS source patterns (location.hash, document.referrer, etc.)
- Identifies dangerous sink patterns (innerHTML, eval, document.write, etc.)
- Pattern-based detection; manual verification recommended

## References
- https://owasp.org/www-community/attacks/DOM_Based_XSS`

    ModuleConfirmation = "Indicated when response JavaScript contains known source-to-sink patterns that could enable DOM-based XSS"
    ModuleSeverity     = severity.Medium
    ModuleConfidence   = severity.Firm
    ModuleTags         = []string{"xss", "javascript", "light"}
)
```

ID rules for passive modules:
- Must start with `"passive-"`
- Must be lowercase kebab-case
- Must be unique

### Step 3: Define the Module Struct

```go
package dom_xss_detect

import (
    "fmt"

    "github.com/pkg/errors"
    urlutil "github.com/projectdiscovery/utils/url"
    "github.com/vigolium/vigolium/pkg/dedup"
    "github.com/vigolium/vigolium/pkg/httpmsg"
    "github.com/vigolium/vigolium/pkg/modules/modkit"
    "github.com/vigolium/vigolium/pkg/output"
    "github.com/vigolium/vigolium/pkg/utils"
)

type Module struct {
    modkit.BasePassiveModule
    ds dedup.Lazy[dedup.DiskSet]  // Dedup to avoid re-scanning same page
}
```

### Step 4: Write the Constructor

```go
func New() *Module {
    m := &Module{
        BasePassiveModule: modkit.NewBasePassiveModule(
            ModuleID,
            ModuleName,
            ModuleDesc,
            ModuleShort,
            ModuleConfirmation,                       // Confirmation criteria
            ModuleSeverity,
            ModuleConfidence,
            modkit.ScanScopeRequest,            // Runs once per request
            modkit.PassiveScanScopeResponse,           // Only needs response body
        ),
        ds: dedup.LazyDiskSet("passive_dom_xss_detect"),
    }
    m.ModuleTags = ModuleTags
    return m
}
```

### Step 5: Implement the Scan Method

```go
func (m *Module) ScanPerRequest(
    ctx *httpmsg.HttpRequestResponse,
    scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
    var results []*output.ResultEvent

    urlx, err := ctx.URL()
    if err != nil {
        return nil, errors.Wrap(err, "failed to get URL")
    }

    // Skip media/JS files
    if utils.IsMediaAndJSURL(urlx.Path) {
        return results, nil
    }

    // Require response body
    if ctx.Response() == nil || ctx.Response().BodyToString() == "" {
        return results, nil
    }

    // Dedup: skip if already analyzed this host+path
    diskSet := m.ds.Get(scanCtx.DedupMgr())
    hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
    if diskSet != nil && diskSet.IsSeen(hash) {
        return results, nil
    }

    // Run your analysis
    highlighted := analyse(ctx.Response().BodyToString())
    if highlighted != "" {
        results = append(results, &output.ResultEvent{
            URL:     urlx.String(),
            Host:    urlx.Host,
            Request: string(ctx.Request().Raw()),
            Info: output.Info{
                Description: "Found DOM XSS vulnerabilities\n```" + highlighted + "```",
            },
        })
    }

    return results, nil
}
```

**Passive module patterns:**

1. **No `httpClient`** — passive modules only analyze existing traffic.
2. **Check `ctx.Response()` for nil** — responses may not be available.
3. **Use `PassiveScanScopeResponse`** when you only need the response, or `PassiveScanScopeRequest` for request-only analysis.
4. **DiskSet for dedup** — prevents re-analyzing the same host+path combination.

---

## ResultEvent: Reporting Findings

When your module detects a vulnerability, return a `*output.ResultEvent`. The executor auto-fills several fields from your module's metadata.

```go
// pkg/output/output.go
type ResultEvent struct {
    ModuleID string           // Auto-filled from module.ID()

    Info Info                 // Partially auto-filled (see below)

    Type   string            // Auto-filled: "http"
    Host   string            // Auto-filled from URL if empty
    Scheme string            // Auto-filled from URL if empty
    URL    string            // Set this — used for Host/Matched derivation
    IP     string

    Matched          string  // Auto-filled from URL if empty
    ExtractedResults []string
    MatcherStatus    bool    // Auto-set to true by output writer

    Request  string          // Raw request bytes (for evidence)
    Response string          // Raw response bytes or headers (for evidence)

    Metadata map[string]interface{}

    IsFuzzingResult  bool
    FuzzingParameter string  // Parameter name that was fuzzed

    Error string

    DisableNotify bool       // Skip notification for this finding
}
```

**Fields the executor auto-fills** (only if empty/zero in your result):
- `ModuleID` ← `module.ID()`
- `Info.Name` ← `module.Name()`
- `Info.Description` ← `module.Description()`
- `Info.Severity` ← `module.Severity()`
- `Info.Confidence` ← `module.Confidence()`
- `Type` ← `"http"`
- `Matched` ← `URL`
- `Host`, `Scheme` ← parsed from `URL`

**Fields you should set:**
- `URL` — the target URL
- `Request` — the raw request that triggered the finding (for evidence)
- `Response` — relevant response data (headers, body snippet)
- `Info.Description` — specific description of what was found (overrides module default)
- `FuzzingParameter` — for per-insertion-point findings
- `ExtractedResults` — matched/extracted values
- `Metadata` — any additional context

**Override severity per-finding** when needed (e.g., different severity for different payload types):

```go
results = append(results, &output.ResultEvent{
    URL: urlx.String(),
    Info: output.Info{
        Severity:    severity.Critical,  // Override module default
        Description: "Found RCE via direct command execution",
    },
})
```

---

## Deduplication

Modules should avoid scanning the same insertion point or URL twice. The `pkg/dedup` package provides two mechanisms:

### RequestHashManager (for active modules)

Tracks whether an insertion point has already been checked:

```go
// In your struct
rhm dedup.Lazy[dedup.RequestHashManager]

// In constructor
rhm: dedup.LazyDefaultRHM("my_module_name"),

// In scan method
rhm := m.rhm.Get(scanCtx.DedupMgr())
if rhm != nil {
    paramName := ip.Name()
    paramType := fmt.Sprintf("%d", ip.Type())
    if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
        return nil, nil  // Already checked
    }
}
```

### DiskSet (for passive modules)

Simple seen/unseen tracking by hash:

```go
// In your struct
ds dedup.Lazy[dedup.DiskSet]

// In constructor
ds: dedup.LazyDiskSet("my_module_name"),

// In scan method
diskSet := m.ds.Get(scanCtx.DedupMgr())
hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
if diskSet != nil && diskSet.IsSeen(hash) {
    return results, nil  // Already analyzed
}
```

### Lazy initialization

Both use `dedup.Lazy[T]` which initializes the dedup store on first access via the `ScanContext`'s `DedupManager`. This is nil-safe — if dedup is not configured, the module runs without dedup.

---

## Shared Utility Packages

Reusable helpers are available under `pkg/modules/shared/` for common module patterns.

### `shared/authzutil/` — Authorization Testing

Utilities for IDOR detection and authorization bypass testing:

| File | Purpose |
|------|---------|
| `classifier.go` | Classify parameters as potential object identifiers (sequential int, UUID, base64, email, slug) |
| `patterns.go` | Regex patterns and name-signal scoring for parameter names (e.g., `user_id` = high signal) |
| `enforcement.go` | Detect authorization enforcement in responses (soft-denial strings, login redirects) |
| `response_compare.go` | Compare two HTTP responses for differential analysis (status, length, headers, body similarity) |
| `neighbors.go` | Generate neighbor values for an object ID (e.g., `id=5` → `id=4`, `id=6`) |

Example — classify a parameter and generate neighbor IDs:

```go
import "github.com/vigolium/vigolium/pkg/modules/shared/authzutil"

classification := authzutil.ClassifyParam(ip.Name(), ip.BaseValue())
if classification.NameSignal >= authzutil.MediumSignal {
    neighbors := authzutil.GenerateNeighbors(ip.BaseValue(), classification.IDType)
    // Test each neighbor value for authorization bypass
}
```

### `shared/diffscan/` — Differential Analysis

Differential response analysis for injection detection — probes, attacks, response snapshots, and quantitative measurement comparison.

---

## Registration

After implementing your module, register it in two places.

### 1. Create `metadata.go` in your module directory

Create a `metadata.go` file in your module's package directory with the standard constant names:

```go
package my_new_scanner

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
    ModuleID    = "active-my-new-scanner"
    ModuleName  = "My New Scanner"
    ModuleShort = "Detects my new vuln"
)

var (
    ModuleDesc = `## Description
Detects my new vulnerability type by injecting test payloads and analyzing responses
for characteristic error patterns.

## Notes
- Tests each insertion point independently
- Uses request deduplication to avoid redundant checks

## References
- https://owasp.org/www-community/attacks/My_Vulnerability`

    ModuleConfirmation = "Confirmed when injected payloads trigger characteristic error patterns in the response"
    ModuleSeverity     = severity.High
    ModuleConfidence   = severity.Firm
    ModuleTags         = []string{"injection", "moderate"}
)
```

Every module uses the same constant names (`ModuleID`, `ModuleName`, `ModuleDesc`, `ModuleShort`, `ModuleConfirmation`, `ModuleSeverity`, `ModuleConfidence`, `ModuleTags`), keeping each package self-contained.

### 2. Register in `pkg/modules/default_registry.go`

Import your package and add to the fluent chain:

```go
import (
    // ... existing imports ...
    "github.com/vigolium/vigolium/pkg/modules/active/my_new_scanner"
)

var DefaultRegistry = NewRegistry().
    // ... existing modules ...
    RegisterActive(my_new_scanner.New()).
    // ... rest of chain ...
```

For passive modules, use `RegisterPassive()` instead.

---

## Testing

### Unit tests

Create `scanner_test.go` in your module's package. Test the scan logic directly:

```go
package my_scanner_test

import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/vigolium/vigolium/pkg/httpmsg"
    "github.com/vigolium/vigolium/pkg/modules/active/my_scanner"
)

func TestModule_Metadata(t *testing.T) {
    m := my_scanner.New()
    assert.Equal(t, "active-my-scanner", m.ID())
    assert.NotEmpty(t, m.Name())
    assert.NotEmpty(t, m.Description())
    assert.NotEmpty(t, m.ConfirmationCriteria())
}

func TestModule_CanProcess(t *testing.T) {
    m := my_scanner.New()

    // Should skip media files
    req, _ := httpmsg.ParseRawRequest("GET /image.png HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert.False(t, m.CanProcess(req))

    // Should process normal requests
    req, _ = httpmsg.ParseRawRequest("GET /api?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert.True(t, m.CanProcess(req))
}
```

### E2E tests

For integration testing against real vulnerable applications, add tests under `test/e2e/` with the `//go:build e2e` tag. See `test/e2e/jsext_examples_test.go` and `test/e2e/server_e2e_test.go` for examples.

### Run tests

```bash
make test-unit              # Fast unit tests (includes your module)
make test                   # All tests
make test-race              # Tests with race detector (important for thread safety)
```

---

## Checklist

Before submitting a new module, verify:

- [ ] **ID format** — starts with `active-` or `passive-`, lowercase kebab-case, no underscores
- [ ] **Metadata** — `metadata.go` created in module directory with all required fields:
  - `ID`, `Name`, `Short` as `const`
  - `Desc` as `var` with structured markdown (`## Description`, `## Notes`, `## References`)
  - `Confirmation` as `var` — one sentence starting with "Confirmed when..." or "Indicated when..."
  - `Severity` and `Confidence` as `var`
  - `Tags` as `var` — classification tags (framework, vulnerability type, weight)
- [ ] **Tags assigned** — `m.ModuleTags = ModuleTags` set in constructor after building the base module
- [ ] **Registered** — added to `DefaultRegistry` in `pkg/modules/default_registry.go`
- [ ] **Thread-safe** — no shared mutable state without synchronization; dedup uses `Lazy` pattern
- [ ] **ScanScopes** — only implements scan methods matching declared types
- [ ] **InsertionPointTypeSet** — restricted to relevant types (don't use `AllInsertionPointTypes` unless you actually handle all types)
- [ ] **Responses closed** — `resp.Close()` called after every `httpClient.Execute()`
- [ ] **Host error handling** — returns early on `hosterrors.ErrUnresponsiveHost`
- [ ] **Dedup** — uses `RequestHashManager` (active) or `DiskSet` (passive) to avoid redundant work
- [ ] **ResultEvent** — sets `URL`, `Request`, and finding-specific `Info.Description`; does NOT set `ModuleID` (auto-filled)
- [ ] **OAST usage** (if applicable) — checks `scanCtx.OASTProv()` for nil and `Enabled()` before generating callback URLs
- [ ] **Mutation usage** (if applicable) — uses `scanCtx.MutGen()` for value-aware payload generation instead of hardcoded values
- [ ] **No panics** — handles errors gracefully; returns `(nil, nil)` for skipped items
- [ ] **Tests** — unit tests for metadata and core logic; race detector passes
