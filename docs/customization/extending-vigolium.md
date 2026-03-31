# Customizing & Extending Vigolium

Vigolium is designed for extensibility. Whether you need to add a new vulnerability check, reshape scan behavior, or integrate AI-driven analysis, there are multiple extension points — each with different trade-offs.

This guide covers every customization mechanism, explains when to use each one, and helps you pick the right approach for your use case.

---

## Table of Contents

- [Extension Points at a Glance](#extension-points-at-a-glance)
- [1. JavaScript Extensions](#1-javascript-extensions)
- [2. YAML Extensions](#2-yaml-extensions)
- [3. Go Modules](#3-go-modules)
- [4. Custom Prompt Templates](#4-custom-prompt-templates)
- [5. Scanning Profiles](#5-scanning-profiles)
- [6. Scope Rules](#6-scope-rules)
- [7. Pre-Hooks and Post-Hooks](#7-pre-hooks-and-post-hooks)
- [8. Agent Backends](#8-agent-backends)
- [9. Configuration Overrides](#9-configuration-overrides)
- [Decision Matrix](#decision-matrix)

---

## Extension Points at a Glance

| Extension Point | Language | Recompile? | Best For |
|---|---|---|---|
| [JavaScript Extensions](#1-javascript-extensions) | JavaScript | No | Custom active/passive checks with full API access |
| [YAML Extensions](#2-yaml-extensions) | YAML | No | Declarative pattern matching, simple payload/matcher rules |
| [Go Modules](#3-go-modules) | Go | Yes | High-performance checks, deep integration with internals |
| [Prompt Templates](#4-custom-prompt-templates) | Markdown + Go templates | No | AI-driven code review, endpoint discovery, custom analysis |
| [Scanning Profiles](#5-scanning-profiles) | YAML | No | Reusable scan presets (speed, modules, phases) |
| [Scope Rules](#6-scope-rules) | YAML | No | Target filtering (hosts, paths, status codes, content types) |
| [Pre/Post Hooks](#7-pre-hooks-and-post-hooks) | JS or YAML | No | Request mutation, finding suppression, severity escalation |
| [Agent Backends](#8-agent-backends) | Any (subprocess) | No | Plugging in new AI models or custom CLI tools |
| [Config Overrides](#9-configuration-overrides) | YAML | No | Tuning concurrency, rate limits, database, notifications |

---

## 1. JavaScript Extensions

JavaScript extensions are the most flexible way to add custom scanning logic without recompiling Vigolium. They run inside an embedded JS engine (Grafana Sobek) and have access to the full `vigolium.*` API — HTTP requests, database queries, parsing utilities, AI integration, and more.

### What you can build

- **Active modules** — send payloads to insertion points (parameters, headers, cookies, paths) and analyze responses for vulnerabilities.
- **Passive modules** — analyze captured HTTP traffic without generating new requests.
- **Pre-hooks** — mutate requests before they reach scanner modules (inject auth headers, skip paths).
- **Post-hooks** — filter, tag, or escalate findings after detection.

### Minimal example (active module)

```javascript
module.exports = {
  id: "reflected-param-scanner",
  name: "Reflected Parameter Scanner",
  type: "active",
  severity: "medium",
  confidence: "firm",
  scanTypes: ["per_insertion_point"],

  scanPerInsertionPoint: function(ctx, insertion) {
    var canary = "VGNM" + vigolium.utils.randomString(8);
    var resp = vigolium.http.send(insertion.buildRequest(canary));

    if (resp && resp.body.indexOf(canary) !== -1) {
      return [{
        matched: canary,
        url: ctx.request.url,
        name: "Reflected parameter: " + insertion.name,
        severity: "medium",
        request: insertion.buildRequest(canary),
        response: resp.raw
      }];
    }
    return null;
  }
};
```

### Available APIs

| Namespace | Purpose | Key Methods |
|---|---|---|
| `vigolium.http` | Send HTTP requests | `get`, `post`, `request`, `send` |
| `vigolium.scan` | Scan control | `listModules`, `isInScope`, `createFinding`, `startNewScan` |
| `vigolium.db` | Database access | `records.query`, `findings.query`, `compareResponses` |
| `vigolium.parse` | HTTP parsing | `url`, `request`, `response`, `headers`, `json` |
| `vigolium.utils` | Encoding, hashing, I/O | `base64Encode`, `sha256`, `readFile`, `exec`, `detectAnomaly` |
| `vigolium.ingest` | Import traffic | `url`, `curl`, `raw`, `openapi`, `postman` |
| `vigolium.source` | Source code access | `list`, `readFile`, `listFiles`, `searchFiles` |
| `vigolium.agent` | AI integration | `ask`, `generatePayloads`, `analyzeResponse`, `confirmFinding` |
| `vigolium.config` | Extension variables | Read-only access to `extensions.variables` |

Full TypeScript definitions: [`pkg/jsext/vigolium.d.ts`](../../pkg/jsext/vigolium.d.ts)

### Setup

```yaml
# vigolium-configs.yaml
audit:
  extensions:
    enabled: true
    extension_dir: ~/.vigolium/extensions/
    variables:
      auth_token: "Bearer eyJ..."
```

Drop `.js` files into `~/.vigolium/extensions/` and verify with `vigolium extensions ls`.

### Pros

- **No recompilation** — drop a file and scan.
- **Full API access** — HTTP, database, AI, source code, parsing, and system utilities.
- **AI-augmented scanning** — use `vigolium.agent.generatePayloads()` and `vigolium.agent.analyzeResponse()` for LLM-powered detection.
- **Rapid iteration** — edit, save, rescan.
- **Sandboxed execution** — file I/O constrained to `sandbox_dir`, `exec()` gated behind config.

### Cons

- **Slower than Go** — interpreted JS engine adds overhead per invocation.
- **No Go standard library** — limited to `vigolium.*` APIs, no arbitrary imports.
- **Single-threaded per VM** — each extension instance runs in its own VM (thread-safe via pooling, but no parallelism within a single extension).
- **Limited debugging** — no step-through debugger, `vigolium.log.*` is your main tool.

### When to use

- You need a custom vulnerability check and don't want to recompile.
- You want AI-augmented payload generation or response analysis.
- You need database or source code access in your check logic.
- You're building organization-specific checks (e.g., custom header validation, business-logic flaws).

See the full guide: [Writing Extensions](writing-extensions.md)

---

## 2. YAML Extensions

YAML extensions (`.vgm.yaml`) are a declarative alternative to JavaScript. They're ideal for simple payload-and-matcher rules where you don't need programmatic control flow.

### Minimal example (active module)

```yaml
id: error-pattern-detector
name: Error Pattern Detector
type: active
severity: low
confidence: firm
scan_types: [per_request]

payloads:
  - "'"
  - "\" OR 1=1--"

matchers:
  - type: body
    regex: "(?i)(SQL syntax|mysql_fetch|ORA-\\d{5}|SQLSTATE\\[)"
  - type: body
    regex: "(?i)(Traceback \\(most recent call last\\)|at \\w+\\.java:\\d+)"

matchers_condition: or

finding:
  name: "Error-Based Information Leak"
  description: "Application returns verbose error messages that reveal implementation details"
  severity: low
```

### YAML hook example (pre-hook)

```yaml
id: auth-header-injector
name: Auth Header Injector
type: pre_hook

add_headers:
  Authorization: "Bearer ${AUTH_TOKEN}"
  X-Request-ID: "vgm-{{random}}"

skip_when:
  url_contains: ["/health", "/metrics"]
```

### YAML hook example (post-hook)

```yaml
id: suppress-low-on-static
name: Suppress Low Findings on Static Assets
type: post_hook

drop_when:
  severity: [low, info]
  url_contains: ["/static/", "/assets/", ".css", ".js"]

escalate:
  when_url_contains: ["/admin", "/api/v1/auth"]
  bump_severity: true
  tag: sensitive_endpoint
```

### Supported features

| Feature | Description |
|---|---|
| `payloads` | List of strings injected per insertion point or request |
| `matchers` | Body regex/contains, header checks, status codes, or inline JS |
| `matchers_condition` | `or` (any matcher) or `and` (all matchers) |
| `add_headers` | Pre-hook: headers to inject |
| `skip_when` | Pre-hook: conditions to skip processing |
| `drop_when` | Post-hook: conditions to discard findings |
| `escalate` | Post-hook: bump severity, add tags |
| `script` | Inline JS escape hatch for complex logic |

### Pros

- **Zero coding** — pure declarative YAML.
- **Fast to write** — a payload list + matcher regex is often all you need.
- **Easy to audit** — non-technical team members can review rules.
- **Same pipeline integration** — loaded alongside JS extensions, same lifecycle.

### Cons

- **Limited logic** — no conditionals, loops, or state beyond what matchers offer.
- **No API access** — no database queries, HTTP follow-ups, or AI calls (unless you use the `script` escape hatch, which is effectively JS).
- **No multi-step checks** — can't chain requests or compare responses across steps.
- **Coarser insertion control** — payload injection is straightforward but you can't dynamically generate payloads based on context.

### When to use

- Simple signature-based detection (error strings, header patterns, status codes).
- Quick pre-hook rules (add auth headers, skip static assets).
- Post-hook filtering (suppress low-severity findings on static paths).
- When non-developers need to contribute scanning rules.

See the full guide: [Writing Extensions](writing-extensions.md)

---

## 3. Go Modules

Go modules are the highest-performance extension point. They compile directly into the scanner binary, have full access to Go internals (HTTP client, deduplication, OAST, mutation engine), and run concurrently in the worker pool.

### Module interfaces

All modules implement the base `Module` interface:

```go
type Module interface {
    ID() string
    Name() string
    Description() string
    ShortDescription() string
    ConfirmationCriteria() string
    Severity() severity.Severity
    Confidence() severity.Confidence
    ScanScopes() ScanScope
    CanProcess(ctx *httpmsg.HttpRequestResponse) bool
}
```

**Active modules** add three scan methods (implement only the ones matching your declared `ScanScopes()`):

```go
type ActiveModule interface {
    Module
    AllowedInsertionPointTypes() InsertionPointTypeSet
    ScanPerInsertionPoint(ctx, ip, httpClient, scanCtx) ([]*ResultEvent, error)
    ScanPerRequest(ctx, httpClient, scanCtx) ([]*ResultEvent, error)
    ScanPerHost(ctx, httpClient, scanCtx) ([]*ResultEvent, error)
}
```

**Passive modules** analyze traffic without sending new requests:

```go
type PassiveModule interface {
    Module
    Scope() PassiveScanScope
    ScanPerRequest(ctx, scanCtx) ([]*ResultEvent, error)
    ScanPerHost(ctx, scanCtx) ([]*ResultEvent, error)
}
```

### Creating a module

1. Create a package under `pkg/modules/active/` or `pkg/modules/passive/`.
2. Embed `modkit.BaseActiveModule` or `modkit.BasePassiveModule` for defaults.
3. Implement scan methods for your declared scopes.
4. Register in `pkg/modules/default_registry.go`.

```go
package my_check

import (
    "github.com/vigolium/vigolium/pkg/modules/modkit"
    "github.com/vigolium/vigolium/pkg/output"
    // ...
)

type Module struct {
    modkit.BaseActiveModule
}

func New() *Module {
    return &Module{
        BaseActiveModule: modkit.NewBaseActiveModule(
            "my-check",
            "My Custom Check",
            "Detailed description of what this checks",
            "One-line summary",
            "How the vulnerability is confirmed",
            severity.High,
            severity.Firm,
            modkit.ScanScopeInsertionPoint,
            modkit.AllParamTypes,
        ),
    }
}

func (m *Module) ScanPerInsertionPoint(
    ctx *httpmsg.HttpRequestResponse,
    ip httpmsg.InsertionPoint,
    httpClient *http.Requester,
    scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
    // Your scanning logic here
    return nil, nil
}
```

### Scan scope options

| Scope | Invocation | Typical use |
|---|---|---|
| `ScanScopeInsertionPoint` | Once per parameter (URL param, body param, header, cookie, JSON key, path segment) | Injection vulnerabilities (XSS, SQLi, SSTI, command injection) |
| `ScanScopeRequest` | Once per unique request | Request-level checks (missing headers, auth bypass, method manipulation) |
| `ScanScopeHost` | Once per unique host | Host-level checks (TLS config, server fingerprinting, path discovery) |

Scopes are a bitmask — you can combine them (e.g., `ScanScopeRequest | ScanScopeHost`).

### Pros

- **Maximum performance** — compiled Go, no interpreter overhead, runs in the concurrent worker pool.
- **Full internal access** — HTTP client with middleware, deduplication manager, OAST callbacks, mutation engine, baseline caching.
- **Type safety** — compile-time checks, IDE support, Go testing ecosystem.
- **First-class integration** — same lifecycle as built-in modules, automatic pipeline wiring.

### Cons

- **Requires recompilation** — every change needs `make build`.
- **Go knowledge required** — must understand Go, the module interfaces, and internal types.
- **Slower iteration** — compile-test cycle is heavier than drop-in JS/YAML.
- **Tighter coupling** — changes to internal APIs may require module updates.

### When to use

- Performance-critical checks that run on every request or insertion point.
- Checks that need deep integration with Vigolium internals (OAST, mutation engine, dedup).
- You're contributing to the core scanner or building a permanent module.
- Checks requiring complex multi-step logic with full concurrency support.

See the full guide: [Developing Modules](../development/developing-modules.md)

---

## 4. Custom Prompt Templates

Prompt templates drive Vigolium's agent mode. They're Markdown files with YAML frontmatter that define what an AI agent should analyze and how it should report results. Templates support Go template syntax and are automatically enriched with context from the database, module registry, and source code.

### Template format

```markdown
---
id: my-custom-review
name: My Custom Review
description: What this template does
output_schema: findings    # or: http_records
variables:
  - SourceCode
  - Language
  - PreviousFindings
---

You are a security engineer. Analyze the following code for {{.Language}} vulnerabilities.

{{if .PreviousFindings}}
Previous findings to verify:
{{.PreviousFindings}}
{{end}}

Source code:
```
{{.SourceCode}}
```

Respond with JSON: {"findings": [...]}
```

### Available template variables

| Variable | Source | Description |
|---|---|---|
| `SourceCode` | Gathered from `--repo`/`--files` | Concatenated source code |
| `Language` | Auto-detected | Primary language (Go, Python, JS, etc.) |
| `Framework` | `--framework` flag | Framework hint |
| `FilePath` | Gathered | Primary file path |
| `RepoPath` | `--repo` flag | Repository root path |
| `TargetURL` | `--target` flag | Target URL |
| `Hostname` | Derived from target | Hostname for DB lookups |
| `Endpoints` | `--endpoints` flag | Pre-discovered endpoints |
| `PreviousFindings` | Database (JSON) | Prior findings for context |
| `DiscoveredEndpoints` | Database (JSON) | HTTP records from DB |
| `ModuleList` | Module registry (JSON) | Available scanner modules |
| `ScanStats` | Database (JSON) | Aggregate scan statistics |
| `AvailableCommands` | Hardcoded reference | CLI commands the agent can invoke |
| `Extra` | `--extra` flag | Custom key-value pairs |

Only variables listed in the frontmatter `variables` array trigger database queries, keeping prompts fast.

### Output schemas

**`findings`** — for code review, vulnerability detection:
```json
{
  "findings": [{
    "title": "SQL Injection in login handler",
    "severity": "critical",
    "confidence": "certain",
    "file": "auth/login.go",
    "line": 42,
    "snippet": "db.Query(\"SELECT * FROM users WHERE id=\" + userID)",
    "cwe": "CWE-89",
    "tags": ["sqli"]
  }]
}
```

**`http_records`** — for endpoint discovery, API input generation:
```json
{
  "http_records": [{
    "method": "POST",
    "url": "https://api.example.com/users",
    "headers": {"Content-Type": "application/json"},
    "body": "{\"name\": \"test\"}",
    "notes": "Create user endpoint"
  }]
}
```

### Preset templates

Vigolium ships with 15 built-in templates:

| Template | Schema | Purpose |
|---|---|---|
| `security-code-review` | findings | General OWASP-focused code review |
| `injection-sinks` | findings | Identify injection sinks (SQLi, cmd, SSRF) |
| `auth-bypass` | findings | Authentication/authorization bypass patterns |
| `secret-detection` | findings | Hardcoded secrets and credentials |
| `endpoint-discovery` | http_records | Extract API routes from source code |
| `api-input-gen` | http_records | Generate HTTP requests from endpoints |
| `curl-command-gen` | http_records | Generate curl commands for all routes |
| `interactive-scan` | findings | Autopilot: analyze + run scans |
| `targeted-retest` | findings | Autopilot: verify previous findings |
| `attack-surface-mapper` | http_records | Discover and cross-reference APIs |
| `nextjs-security-audit` | findings | Next.js-specific security review |
| `react-xss-audit` | findings | React XSS pattern analysis |
| `auth-session-review` | findings | Auth and session management |
| `cors-csrf-review` | findings | CORS/CSRF configuration review |
| `build-config-audit` | findings | Build/deployment config security |

### Setup

Place custom templates in `~/.vigolium/prompts/` or set `agent.templates_dir` in config. User templates override built-in ones by ID.

```bash
# Use a custom template
vigolium agent --prompt-template my-custom-review --repo /path/to/source

# Dry-run to see the rendered prompt
vigolium agent --prompt-template my-custom-review --repo /path/to/source --dry-run
```

### Pros

- **No code** — Markdown files with template syntax.
- **Context-aware** — automatic enrichment with database findings, endpoints, scan stats.
- **Multiple AI backends** — works with Claude, Codex, OpenCode, or any custom agent.
- **Iterative refinement** — autopilot and pipeline modes pass prior findings back for verification.
- **Two output modes** — emit findings for code review or HTTP records for endpoint discovery.

### Cons

- **AI dependency** — requires a configured agent backend and API access.
- **Non-deterministic** — LLM output varies between runs; false positives require tuning.
- **Latency** — agent invocations are slower than pattern matching (seconds to minutes per run).
- **Token costs** — large codebases consume significant tokens per analysis.

### When to use

- Code-level security review that needs semantic understanding (not just pattern matching).
- Generating HTTP test inputs from source code (route extraction, API fuzzing seeds).
- Framework-specific audits (Next.js, React, Django, Spring) where templates can embed domain knowledge.
- Iterative analysis where the agent refines findings across multiple passes.

---

## 5. Scanning Profiles

Profiles are YAML files that overlay on top of the main configuration. They bundle scanning strategy, pace, phase settings, and module selection into a reusable preset.

### Format

A profile is a subset of `vigolium-configs.yaml`. Only non-nil values override the base config.

```yaml
# ~/.vigolium/profiles/aggressive.yaml
# description: Fast aggressive scan for CI/CD pipelines

scanning_strategy:
  default_strategy: deep

scanning_pace:
  concurrency: 100
  rate_limit: 200
  max_per_host: 20
  audit:
    concurrency: 100
    max_duration: 60m

discovery:
  mode: files_and_dirs
  recursion:
    enabled: true
    max_depth: 8

spidering:
  max_depth: 0
  headless: true
  strategy: aggressive

audit:
  enabled_modules:
    active_modules:
      - all
    passive_modules:
      - all
```

### Usage

```bash
# Use a named profile
vigolium scan --target https://example.com --scanning-profile aggressive

# Use a profile file path
vigolium scan --target https://example.com --scanning-profile /path/to/profile.yaml
```

Profiles are resolved from `~/.vigolium/profiles/` or `public/presets/profiles/` by name.

### Pros

- **Reusable presets** — define once, use across targets and teams.
- **Composable** — overlay on top of base config; only override what you need.
- **No code** — pure YAML.
- **Team-friendly** — share profiles in version control for consistent scan policies.

### Cons

- **Config-only** — can't add new scanning logic, only tune existing settings.
- **No per-target logic** — same profile applies to all targets in a scan.
- **Limited validation** — typos in field names silently ignored.

### When to use

- You run different scan intensities for different contexts (CI/CD vs. full audit vs. quick check).
- You want to enforce consistent scan settings across a team.
- You need to toggle phases (e.g., skip discovery, only run passive modules).

---

## 6. Scope Rules

Scope rules control what gets scanned. They filter at the host, path, status code, content type, and body level. You can define them in the config, via CLI flags, or programmatically from JS extensions.

### Configuration

```yaml
# vigolium-configs.yaml
scope:
  applied_on_ingest: false     # enforce at ingest time or scan time

  host:
    include: ["*.example.com", "api.example.com"]
    exclude: ["staging.example.com"]

  path:
    include: ["/api/*"]
    exclude: ["/api/health", "/api/metrics", "/static/*"]

  status_code:
    include: ["2xx", "3xx"]    # exact, wildcard (2xx), range (400-499)
    exclude: ["404"]

  request_content_type:
    include: ["application/json*", "application/x-www-form-urlencoded*"]

  response_content_type:
    include: ["text/html*", "application/json*"]
    exclude: ["image/*", "font/*"]

  ignore_static_file: true     # auto-skip .jpg, .png, .css, etc.
```

### Scope from extensions

```javascript
// Check scope programmatically
if (vigolium.scan.isInScope("api.example.com", "/users")) {
  // proceed
}

// Read current scope
var scope = vigolium.scan.getScope();

// Modify scope at runtime
vigolium.scan.setScope({
  host: { include: ["*.example.com"], exclude: [] },
  path: { include: ["/api/*"], exclude: [] }
});
```

### Pros

- **Precision targeting** — scan only what matters, skip noise.
- **Multiple filter types** — host globs, path patterns, status codes, content types, body strings.
- **Runtime adjustable** — extensions can modify scope during a scan.
- **Safety net** — prevents accidental scanning of out-of-scope systems.

### Cons

- **Config-only complexity** — complex scope rules can be hard to debug.
- **No request-level conditions** — you can't scope by request header values or authentication state (use pre-hooks for that).

### When to use

- Restricting scans to specific subdomains or API paths.
- Excluding health checks, static assets, or third-party endpoints.
- Bug bounty programs with defined scope boundaries.
- Filtering by response characteristics (status codes, content types).

---

## 7. Pre-Hooks and Post-Hooks

Hooks wrap the scanning pipeline. Pre-hooks transform requests before modules process them. Post-hooks filter or modify findings after detection.

### Pre-hook use cases

| Use case | Implementation |
|---|---|
| Inject auth headers | YAML `add_headers` or JS returning `{headers: {...}}` |
| Skip static assets | YAML `skip_when.url_contains` or JS returning `null` |
| Add correlation IDs | JS generating unique IDs per request |
| Rewrite URLs | JS modifying `ctx.request` before forwarding |

### Post-hook use cases

| Use case | Implementation |
|---|---|
| Suppress low-severity on static paths | YAML `drop_when` |
| Escalate findings on admin endpoints | YAML `escalate.when_url_contains` |
| Tag findings by business unit | JS adding metadata based on URL patterns |
| AI-powered false positive filtering | JS calling `vigolium.agent.confirmFinding()` |

### JS pre-hook example

```javascript
module.exports = {
  id: "inject-session",
  name: "Session Injector",
  type: "pre_hook",

  execute: function(request) {
    return {
      headers: {
        "Cookie": "session=" + vigolium.config.session_token,
        "X-Correlation-ID": vigolium.utils.randomString(16)
      }
    };
  }
};
```

### JS post-hook example (AI false positive filter)

```javascript
module.exports = {
  id: "ai-fp-filter",
  name: "AI False Positive Filter",
  type: "post_hook",

  execute: function(result) {
    if (typeof vigolium.agent === "undefined") return result;

    var check = vigolium.agent.confirmFinding({
      name: result.info.name,
      request: result.request,
      response: result.response,
      matched: result.matched
    });

    if (!check.confirmed && check.confidence !== "low") {
      vigolium.log.info("Suppressed FP: " + result.info.name);
      return null; // drop the finding
    }
    return result;
  }
};
```

### Pros

- **Pipeline integration** — runs automatically on every request/finding.
- **Composable** — multiple hooks chain sequentially.
- **Both JS and YAML** — simple rules in YAML, complex logic in JS.
- **Non-invasive** — doesn't modify module code.

### Cons

- **Sequential overhead** — hooks run on the hot path; slow hooks slow everything.
- **Order-dependent** — hook execution order matters but isn't always obvious.
- **Pre-hooks can't see responses** — they only have access to the outbound request.

### When to use

- You need to inject authentication into every request (pre-hook).
- You want to suppress known false positives across all modules (post-hook).
- You need to tag or route findings based on URL patterns (post-hook).
- AI-powered confirmation of findings before reporting (post-hook).

See the full guide: [Writing Extensions](writing-extensions.md)

---

## 8. Agent Backends

Agent backends are external processes that Vigolium invokes for AI-driven analysis. You can plug in any CLI tool that accepts a prompt and returns structured output.

### Built-in backends

| Backend | Protocol | Command |
|---|---|---|
| Claude Code (SDK) | `sdk` | `claude` |
| Codex (codex-sdk) | `codex-sdk` | `codex` |
| OpenCode (opencode-sdk) | `opencode-sdk` | `opencode` |
| Claude CLI (pipe) | `pipe` | `claude --dangerously-skip-permissions -p` |

### Adding a custom backend

```yaml
# vigolium-configs.yaml
agent:
  backends:
    my-agent:
      command: my-tool
      args: ["--json", "--security-mode"]
      description: "My custom security agent"
      protocol: pipe        # pipe: prompt on stdin, output on stdout
      env:
        MY_API_KEY: "${MY_API_KEY}"
```

Use it:
```bash
vigolium agent --agent my-agent --prompt-template security-code-review --repo /path/to/code
```

### Protocols

| Protocol | How it works | Agent capabilities |
|---|---|---|
| `pipe` | Prompt piped to stdin, output read from stdout | Simple: no tool use, no file access |
| `sdk` | Claude Agent SDK — JSON-lines protocol | Full: file reading, tool invocation, streaming |
| `codex-sdk` | Codex native JSON-RPC v2 | Full tools |
| `opencode-sdk` | OpenCode native REST + SSE streaming | Full tools |

### Warm sessions

For iterative workflows (autopilot), backends support session pooling to avoid subprocess startup overhead:

```yaml
agent:
  warm_session:
    enable: true
    idle_timeout: 300    # seconds before killing idle session
    max_sessions: 2      # concurrent sessions per agent
```

### LLM config (for JS extensions)

The `agent.llm` section configures the LLM provider used by `vigolium.agent.*` APIs in JavaScript extensions:

```yaml
agent:
  llm:
    provider: anthropic    # or openai
    model: claude-sonnet-4-20250514
    api_key_env: ANTHROPIC_API_KEY
    max_tokens: 4096
    temperature: 0.0
    cache_size: 256        # LRU cache; 0 = disabled
    cache_ttl: 300         # seconds
```

### Pros

- **Any AI model** — plug in any CLI tool as a backend.
- **Multiple protocols** — SDK for full tool access, codex-sdk/opencode-sdk for native integration, pipe for simple tools.
- **Session pooling** — warm sessions reduce latency for iterative analysis.
- **Environment isolation** — per-agent env vars, scoped file access.

### Cons

- **External dependency** — requires installing and configuring the agent CLI.
- **Cost** — AI API calls have token costs.
- **Latency** — subprocess startup + LLM inference is slower than local checks.

### When to use

- You have a preferred AI model or a fine-tuned security model you want to integrate.
- You're building a custom tool that produces structured security findings.
- You need agent capabilities beyond what the built-in backends provide.

---

## 9. Configuration Overrides

The main `vigolium-configs.yaml` is the central control plane for all scan behavior. Every aspect of the scanner — phases, pace, modules, database, notifications, and more — is configurable.

### Key configuration sections

| Section | What it controls |
|---|---|
| `scanning_strategy` | Phase presets: `lite`, `balanced`, `deep`, `whitebox` |
| `scanning_pace` | Concurrency, rate limits, per-phase duration caps |
| `audit` | Active/passive module selection, extension config |
| `discovery` | Content discovery mode, recursion, wordlists |
| `spidering` | Browser crawling depth, strategy, headless mode |
| `scope` | Host/path/status/content-type filtering |
| `database` | SQLite or PostgreSQL, connection settings |
| `notify` | Alert routing: Telegram, Discord, severity filters |
| `mutation_strategy` | Payload mutation modes, field-type defaults |
| `oast` | Out-of-band testing server, blind XSS config |
| `agent` | AI backends, LLM config, warm sessions |

### Environment variable expansion

```yaml
database:
  postgres:
    password: ${VIGOLIUM_DB_PASSWORD}

agent:
  llm:
    api_key_env: ANTHROPIC_API_KEY
```

### Pros

- **Comprehensive** — controls every scanner behavior.
- **Environment-aware** — variable expansion for secrets.
- **Layered** — base config + profiles + CLI flags, in order of precedence.

### Cons

- **No logic** — pure configuration, can't express conditional behavior.
- **Silent failures** — unrecognized keys are ignored, not flagged.
- **Single file** — large configs can become unwieldy.

### When to use

- Tuning scan speed and resource usage for your infrastructure.
- Selecting which modules run by default.
- Configuring database, notifications, and OAST.
- Setting organization-wide defaults.

---

## Decision Matrix

Use this table to quickly pick the right extension mechanism:

| I want to... | Use |
|---|---|
| Add a custom vulnerability check (simple patterns) | [YAML Extension](#2-yaml-extensions) |
| Add a custom vulnerability check (complex logic) | [JS Extension](#1-javascript-extensions) |
| Add a high-performance check compiled into the binary | [Go Module](#3-go-modules) |
| Run AI code review with custom focus areas | [Prompt Template](#4-custom-prompt-templates) |
| Create a reusable scan preset for my team | [Scanning Profile](#5-scanning-profiles) |
| Restrict scanning to specific hosts/paths | [Scope Rules](#6-scope-rules) |
| Inject auth headers into every request | [Pre-Hook](#7-pre-hooks-and-post-hooks) |
| Suppress false positives across all modules | [Post-Hook](#7-pre-hooks-and-post-hooks) |
| Use AI to confirm findings before reporting | [Post-Hook + agent API](#7-pre-hooks-and-post-hooks) |
| Plug in a new AI model | [Agent Backend](#8-agent-backends) |
| Tune concurrency and rate limits | [Config Override](#9-configuration-overrides) or [Profile](#5-scanning-profiles) |
| Generate HTTP test inputs from source code | [Prompt Template](#4-custom-prompt-templates) (with `http_records` schema) |
| Build an organization-specific scanner pipeline | Combine: [Profile](#5-scanning-profiles) + [Scope](#6-scope-rules) + [Hooks](#7-pre-hooks-and-post-hooks) + [Extensions](#1-javascript-extensions) |
