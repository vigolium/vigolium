# Developing Scanner Modules

This guide walks through writing a new scanner **module** — the unit of detection
logic in Vigolium's native scan. Modules are plain Go types registered into the
central **Registry** (`pkg/modules/registry.go`); the executor
(`pkg/core/executor.go`) dispatches HTTP request/response pairs to every module
that opts in.

There are two kinds:

- **Active modules** send new, mutated requests to probe for a vulnerability.
- **Passive modules** analyze the request/response pairs already flowing through
  the scan, without issuing extra traffic.

Both share the base `Module` interface and live under `pkg/modules/active/<name>/`
or `pkg/modules/passive/<name>/`.

## Interfaces at a glance

Every module implements `Module` (`pkg/modules/module.go`):

```go
type Module interface {
    ID() string                       // unique, lowercase, kebab-case (e.g. "cache-deception")
    Name() string                     // human-readable
    Description() string              // markdown, shown in reports
    ShortDescription() string         // one-line summary for listings
    ConfirmationCriteria() string     // how the module confirms a finding
    Severity() severity.Severity
    Confidence() severity.Confidence
    ScanScopes() ScanScope            // bitmask: InsertionPoint | Request | Host
    Tags() []string                   // classification labels for --module-tag
    CanProcess(ctx *httpmsg.HttpRequestResponse) bool
}
```

Active modules add three scan entry points (`pkg/modules/active.go`):

```go
type ActiveModule interface {
    Module
    AllowedInsertionPointTypes() InsertionPointTypeSet
    ScanPerInsertionPoint(ctx *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, httpClient *http.Requester, scanCtx *ScanContext) ([]*output.ResultEvent, error)
    ScanPerRequest(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *ScanContext) ([]*output.ResultEvent, error)
    ScanPerHost(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *ScanContext) ([]*output.ResultEvent, error)
}
```

Passive modules analyze existing traffic (`pkg/modules/passive.go`):

```go
type PassiveModule interface {
    Module
    Scope() PassiveScanScope          // request / response / both
    ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *ScanContext) ([]*output.ResultEvent, error)
    ScanPerHost(ctx *httpmsg.HttpRequestResponse, scanCtx *ScanContext) ([]*output.ResultEvent, error)
}
```

The executor calls the entry point that matches your declared `ScanScopes()`:

| Scope | When it fires |
|-------|---------------|
| `ScanScopeInsertionPoint` | once per parameter/header/cookie/body insertion point |
| `ScanScopeRequest` | once per unique request |
| `ScanScopeHost` | once per eligible module and canonical `scheme://host:port` origin claim |

> **Thread-safety:** scan methods are called concurrently from many worker
> goroutines. Keep module state immutable after construction, or guard it.

## Use `modkit` for the boilerplate

`pkg/modules/modkit` provides `BaseActiveModule` / `BasePassiveModule` that
implement all the metadata getters and sensible `CanProcess` defaults (URL
parse, media-file filter, method filter). You embed the base and implement only
the scan logic. Constructors:

```go
modkit.NewBaseActiveModule(id, name, description, shortDesc, confirmation,
    severity, confidence, scanScopes, allowedInsertionPointTypes) BaseActiveModule

modkit.NewBasePassiveModule(id, name, description, shortDesc, confirmation,
    severity, confidence, scanScopes, passiveScope) BasePassiveModule
```

`NewBaseActiveModule` / `NewBasePassiveModule` validate the ID (lowercase,
kebab-case) at construction and panic on a bad ID — so registration fails fast
during `init()` rather than silently.

## A complete example

Modules conventionally split into `metadata.go` (constants) and `scanner.go`
(logic). Here is the shape of the real `cache-deception` module
(`pkg/modules/active/cache_deception/`).

`metadata.go`:

```go
package cache_deception

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
    ModuleID    = "cache-deception"
    ModuleName  = "Web Cache Deception"
    ModuleShort = "Detects web cache deception via path confusion with static file extensions"
)

var (
    ModuleDesc         = `## Description ...`
    ModuleConfirmation = "Confirmed when a path-confused request returns the same authenticated content ..."
    ModuleSeverity     = severity.High
    ModuleConfidence   = severity.Firm
    ModuleTags         = []string{"cache-poisoning", "auth-bypass", "moderate"}
)
```

`scanner.go`:

```go
package cache_deception

type Module struct {
    modkit.BaseActiveModule
    ds dedup.Lazy[dedup.DiskSet] // optional: cross-request dedup
}

func New() *Module {
    m := &Module{
        BaseActiveModule: modkit.NewBaseActiveModule(
            ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
            ModuleSeverity, ModuleConfidence,
            modkit.ScanScopeRequest,        // dispatched once per request
            modkit.AllInsertionPointTypes,
        ),
        ds: dedup.LazyDiskSet("cache_deception"),
    }
    m.ModuleTags = ModuleTags
    return m
}

func (m *Module) ScanPerRequest(
    ctx *httpmsg.HttpRequestResponse,
    httpClient *http.Requester,
    scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
    // 1. Skip work you don't need (media URLs, already-seen host+path).
    // 2. Fetch/compare a baseline: scanCtx.GetOrFetchBaseline(ctx, httpClient).
    // 3. Send mutated requests via httpClient.Execute(req, http.Options{}).
    //    ALWAYS resp.Close() each response.
    // 4. Append an *output.ResultEvent per confirmed finding and return it.
    ...
}
```

Key conventions visible in the example:

- **Emit findings as `*output.ResultEvent`** with `URL`, `Matched`, `Request`,
  `Response`, `ExtractedResults` (the evidence), and an `Info` block. Severity /
  confidence / module identity are filled in from your metadata by the executor.
- **Close every response** (`resp.Close()`) — the response-body lifecycle is
  owned by the caller, and leaks degrade long scans.
- **Bail out cheaply.** Returning `(nil, nil)` early on irrelevant inputs is the
  norm and keeps scans fast.
- **Use `scanCtx` helpers**: `GetOrFetchBaseline`, `WildcardProbe`,
  `DedupMgr()`, and the OAST provider for blind detection.
- **Treat `hosterrors.ErrUnresponsiveHost` as "stop probing this host"**, not a
  scan error.

## Preserve signals without overstating vulnerabilities

Modules should keep useful security patterns visible while assigning the result kind that the evidence supports:

| Evidence | `RecordKind` | `EvidenceGrade` | Typical proof |
|---|---|---|---|
| Primitive exists | `observation` | `E0` | Header, sink, console, schema, public identifier, or configuration marker |
| Hypothesis supported | `candidate` | `E1` | Corroborated static context or a credential-shaped value |
| Controlled differential | `candidate` | `E2` | Baseline and negative controls isolate attacker influence |
| Bypass behavior | `candidate` unless impact is direct | `E3` | Authorization or validation behavior changes under a controlled probe |
| Demonstrated impact | `finding` | `E4` | Unauthorized read/write, execution, durable state, OAST, or cross-user replay |

The zero value remains a finding for backward compatibility. New heuristic modules should set `RecordKind` and `EvidenceGrade` explicitly. Status codes, generic strings, feature presence, or client-side code alone should not become findings. Active confirmation should use fresh canaries, clean and malformed controls, cache bypass, isolated credential-free clients, and repeated replay as appropriate.

Candidates and observations are persisted and queryable, but the executor excludes them from confirmed-finding totals, notifications, finding caps, and cross-module confirmed-result suppression. This lets a stronger module continue toward impact proof without discarding reconnaissance.

## Register the module

Add one line to the relevant registry wiring file:

- Active modules → `pkg/modules/default_registry_active.go`
- Passive modules → `pkg/modules/default_registry_passive.go`

```go
r.RegisterActive(cache_deception.New())
// or, for passive:
r.RegisterPassive(my_passive_module.New())
```

`RegisterActive` / `RegisterPassive` panic on a duplicate ID, so collisions are
caught at startup. Group the registration near related modules and keep the
section comment headers tidy.

## Optional capability interfaces

Adopt any of these incrementally — implement the method set and the executor
picks it up automatically. None of them break the base interface.

| Interface | Purpose |
|-----------|---------|
| `ContextualActiveModule` / `ContextualPassiveModule` | Receive a `context.Context` so HTTP calls cancel on phase deadline / scan shutdown |
| `Prioritized` | `Priority() int` — lower runs first (default 100); high-priority modules get earlier rate-limit slots |
| `VulnClassifier` | `VulnClass() string` — enables cross-module dedup (e.g. don't re-test XSS another module already confirmed) |
| `BodyDifferentialConfirmable` | Opt an active module into the executor's replay-and-baseline differential safety net; only for non-state-changing in-band body/header signals |
| `TechAware` | `RequiredTechs() []string` — allowlist; module only runs when the host's fingerprint matches (fails open if no tech detected yet) |
| `PerScanModule` | `Fresh() any` — return isolated mutable state for each scan when registry-singleton state cannot live in `ScanContext` |
| `ContentClassAware` | `RequiredContentClasses() []string` — gate passive analyzers to structurally compatible HTML/JSON/XML/text/binary responses |
| `TimeoutHinter` | `TimeoutHint() time.Duration` — raise the per-module timeout for legitimately slow analysis (e.g. timing-based DiffScan) |
| `Flusher` / `BatchFlusher` | End-of-scan finalization; `BatchFlusher` returns deferred findings through the normal pipeline |
| `ScopeAwareModule` | `ScopeAware() bool` — passive modules that should skip out-of-scope records |

## Test the module without Docker

`pkg/modules/modtest` wires a real `*http.Requester` against an
`httptest.Server` and builds the request/insertion-point objects a scan method
expects — all in a fast, untagged unit test (no Docker, no build tags). Write
paired positive (vulnerable server) and negative (clean server) tests:

```go
func TestCacheDeception_Positive(t *testing.T) {
    srv := httptest.NewServer(/* handler that caches path-confused responses */)
    defer srv.Close()

    client := modtest.Requester(t)
    rr := modtest.Request(t, srv.URL+"/account")

    res, err := cache_deception.New().ScanPerRequest(rr, client, &modkit.ScanContext{})
    if err != nil {
        t.Fatalf("scan: %v", err)
    }
    if len(res) == 0 {
        t.Fatal("expected a cache-deception finding")
    }
}
```

Helpers: `modtest.Requester(t)`, `modtest.Request(t, url)`,
`modtest.RequestMethod(t, method, url, body)`, `modtest.Response(rr, ct, body)`
(attach a synthetic baseline), and `modtest.InsertionPoint(t, rr, name)`.

Run it:

```bash
go test -run TestCacheDeception ./pkg/modules/active/cache_deception/...
```

## Checklist

- [ ] `metadata.go` with `ModuleID` (kebab-case), name, description, severity,
      confidence, tags.
- [ ] `scanner.go` embedding `modkit.BaseActiveModule` / `BasePassiveModule`.
- [ ] Implement only the scan method(s) matching your declared `ScanScopes()`.
- [ ] Close every HTTP response; bail out early on irrelevant inputs.
- [ ] Register in `default_registry_active.go` / `default_registry_passive.go`.
- [ ] Paired positive/negative `modtest` unit tests.
- [ ] Heuristic results explicitly declare observation/candidate/finding kind and evidence grade.
- [ ] Negative tests cover generic strings, status-only responses, reflection, wildcards, and normal public behavior relevant to the oracle.
- [ ] `make fmt && make lint && make test-unit` is green.

See also: [project-structure.md](project-structure.md) for where things live and
[building.md](building.md) for the build/test workflow.
