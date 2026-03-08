# Writing Extensions

Extensions let you add custom scanning logic to Vigolium without modifying the core scanner. You can write them in **JavaScript** for full flexibility or in **YAML** for declarative pattern matching.

---

## Table of Contents

- [Overview](#overview)
- [Setup](#setup)
- [Extension Types](#extension-types)
- [Writing a JavaScript Extension](#writing-a-javascript-extension)
  - [Active Module](#active-module-js)
  - [Passive Module](#passive-module-js)
  - [Pre-Hook](#pre-hook-js)
  - [Post-Hook](#post-hook-js)
- [Writing a YAML Extension](#writing-a-yaml-extension)
  - [Active Module](#active-module-yaml)
  - [Passive Module](#passive-module-yaml)
  - [Pre-Hook](#pre-hook-yaml)
  - [Post-Hook](#post-hook-yaml)
- [Context Objects Reference](#context-objects-reference)
- [Testing Your Extension](#testing-your-extension)
- [Configuration Reference](#configuration-reference)
- [Tips and Best Practices](#tips-and-best-practices)

---

## Overview

Extensions plug into the scanner pipeline at four points:

| Type | Runs when | Use for |
|---|---|---|
| `active` | During dynamic assessment | Send payloads, detect vulnerabilities |
| `passive` | Analyzing captured traffic | Inspect request/response without new traffic |
| `pre_hook` | Before each request is sent | Modify requests, skip assets, inject headers |
| `post_hook` | After a finding is emitted | Escalate severity, drop false positives |

Both JS and YAML extensions support all four types. YAML is simpler for straightforward pattern matching. JS gives you full access to HTTP requests, regex, encoding utilities, the database API, and optional AI-augmented analysis.

---

## Setup

### 1. Enable extensions in your config

Add or uncomment the `extensions` block under `dynamic_assessment` in your `vigolium-configs.yaml`:

```yaml
dynamic_assessment:
  extensions:
    enabled: true
    extension_dir: ~/.vigolium/extensions/   # scan this dir for .js and .vgm.yaml files
    custom_dir: []                           # explicit extra paths
    variables:
      auth_token: "Bearer eyJ..."            # accessible as vigolium.config.auth_token
    limits:
      timeout: 30s
      max_memory_mb: 128
```

### 2. Place your extension file

Drop any `.js` or `.vgm.yaml` file into your `extension_dir`. Vigolium discovers them automatically on the next scan.

### 3. Verify it loaded

```bash
vigolium extensions ls
```

---

## Extension Types

### Module export contract (JS)

Every JS extension must export a `module.exports` object. Required fields:

| Field | Required | Description |
|---|---|---|
| `id` | No (auto from filename) | Unique identifier |
| `type` | **Yes** | `active`, `passive`, `pre_hook`, `post_hook` |
| `name` | No | Display name |
| `description` | No | What the extension does |
| `severity` | For active/passive | `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | No | `tentative`, `firm`, `certain` |
| `scanTypes` | For active/passive | `["per_insertion_point"]`, `["per_request"]`, `["per_host"]` |
| `tags` | No | Classification tags for `--module-tag` filtering (e.g. `["custom", "xss"]`) |

---

## Writing a JavaScript Extension

JS extensions run inside an embedded Goja (ES5.1-compatible) VM. The global `vigolium` object provides all APIs.

### Active Module (JS)

Active modules send modified requests to probe for vulnerabilities. Declare which scan granularity you need in `scanTypes`:

- `per_insertion_point` — called once per parameter (query, body, header, cookie)
- `per_request` — called once per request/response pair
- `per_host` — called once per unique hostname

**per_insertion_point example** — detect reflected input:

```javascript
// File: ~/.vigolium/extensions/reflected_param_scanner.js
module.exports = {
  id: "reflected-param",
  name: "Reflected Parameter Scanner",
  type: "active",
  severity: "medium",
  confidence: "firm",
  tags: ["custom", "xss", "reflection"],
  scanTypes: ["per_insertion_point"],

  scanPerInsertionPoint: function(ctx, insertion) {
    // Generate a unique canary
    var canary = "VGNM" + vigolium.utils.randomString(8);

    // Build and send a request with the canary injected
    var req = insertion.buildRequest(canary);
    var resp = vigolium.http.send(req);

    if (!resp || !resp.body) return null;

    // Check if the canary appears in the response
    if (resp.body.indexOf(canary) !== -1) {
      return [{
        matched: canary,
        url: ctx.request.url,
        name: "Reflected parameter: " + insertion.name,
        description: "Parameter '" + insertion.name + "' is reflected without encoding",
        severity: "medium"
      }];
    }
    return null;
  }
};
```

**per_request example** — detect error messages in existing responses:

```javascript
// File: ~/.vigolium/extensions/error_pattern_detector.js
module.exports = {
  id: "error-pattern-detector",
  name: "Error Pattern Detector",
  type: "active",
  severity: "low",
  confidence: "firm",
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.body) return null;

    var body = ctx.response.body;
    var patterns = [
      { regex: /Traceback \(most recent call last\)/i, name: "Python traceback" },
      { regex: /goroutine \d+ \[running\]/i,           name: "Go panic stack trace" },
      { regex: /SQLSTATE\[/i,                          name: "SQL error (SQLSTATE)" },
      { regex: /Fatal error:.*on line \d+/i,           name: "PHP fatal error" }
    ];

    var findings = [];
    for (var i = 0; i < patterns.length; i++) {
      if (patterns[i].regex.test(body)) {
        findings.push({
          matched: patterns[i].name,
          url: ctx.request.url,
          name: "Error pattern: " + patterns[i].name,
          description: "Response contains a " + patterns[i].name,
          severity: "low"
        });
      }
    }
    return findings.length > 0 ? findings : null;
  }
};
```

**Return value for active/passive:** an array of finding objects, or `null` if nothing found.

Each finding object:

```javascript
{
  matched: "...",        // what triggered the finding (shown in output)
  url: "...",            // full URL
  name: "...",           // finding title
  description: "...",    // detailed description
  severity: "medium"     // overrides module severity if set
}
```

---

### Passive Module (JS)

Passive modules analyze existing request/response pairs without making new requests. Add a `scope` field to limit to `"request"`, `"response"`, or `"both"` (default).

```javascript
// File: ~/.vigolium/extensions/sensitive_header_leak.js
module.exports = {
  id: "sensitive-header-leak",
  name: "Sensitive Header Leak",
  type: "passive",
  severity: "info",
  confidence: "certain",
  scope: "response",
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.headers) return null;

    var findings = [];
    var headers = ctx.response.headers;

    var poweredBy = headers["X-Powered-By"] || headers["x-powered-by"];
    if (poweredBy) {
      findings.push({
        matched: "X-Powered-By: " + poweredBy,
        url: ctx.request.url,
        name: "X-Powered-By header exposed",
        description: "Server technology revealed: " + poweredBy,
        severity: "info"
      });
    }

    return findings.length > 0 ? findings : null;
  }
};
```

---

### Pre-Hook (JS)

Pre-hooks run before each request is sent to a module. Return the modified request, a headers-only patch, or `null` to skip the request entirely.

```javascript
// File: ~/.vigolium/extensions/add_auth_header.js
module.exports = {
  id: "add-auth-header",
  name: "Auth Header Injector",
  type: "pre_hook",

  execute: function(request) {
    var token = vigolium.config.auth_token || "";
    if (token === "") {
      return request; // pass through unchanged
    }

    // Return a headers patch — these are merged into the existing request
    return {
      headers: {
        "Authorization": "Bearer " + token,
        "X-Correlation-ID": vigolium.utils.randomString(12)
      }
    };
  }
};
```

Return value options:

| Return | Effect |
|---|---|
| `request` (unchanged) | Pass through as-is |
| `{ headers: {...} }` | Merge these headers into the request |
| `{ raw: "GET /..." }` | Replace the entire raw request |
| `null` | Skip this request (module won't see it) |

**Skip static assets example:**

```javascript
// File: ~/.vigolium/extensions/skip_static_assets.js
module.exports = {
  id: "skip-static-assets",
  type: "pre_hook",

  execute: function(request) {
    var path = request.path || "";
    var skip = [".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico",
                ".woff", ".woff2", ".ttf", ".map"];
    for (var i = 0; i < skip.length; i++) {
      if (path.endsWith(skip[i])) return null;
    }
    return request;
  }
};
```

---

### Post-Hook (JS)

Post-hooks receive each emitted finding. Return the (possibly modified) result, or `null` to suppress the finding.

```javascript
// File: ~/.vigolium/extensions/tag_critical_domains.js
module.exports = {
  id: "tag-critical-domains",
  name: "Critical Domain Tagger",
  type: "post_hook",

  execute: function(result) {
    if (!result || !result.url) return result;

    var url = result.url.toLowerCase();
    var critical = ["payment", "admin", "auth", "checkout", "billing"];

    for (var i = 0; i < critical.length; i++) {
      if (url.indexOf(critical[i]) !== -1) {
        var sev = result.info ? result.info.severity : "info";
        var escalated = { info: "low", low: "medium", medium: "high", high: "critical" }[sev] || sev;

        return {
          url: result.url,
          matched: result.matched,
          info: {
            name: result.info.name + " [CRITICAL: " + critical[i] + "]",
            description: result.info.description,
            severity: escalated
          }
        };
      }
    }
    return result;
  }
};
```

---

## Writing a YAML Extension

YAML extensions (`.vgm.yaml`) are a declarative alternative for common patterns. They require no programming knowledge and are compiled to the same internal module interface as JS extensions.

### Active Module (YAML)

Use `rules` to define match-then-emit pairs. Each rule specifies a match condition and the finding to emit when it matches.

```yaml
# File: ~/.vigolium/extensions/error_patterns.vgm.yaml
id: error-pattern-detector-yaml
name: Error Pattern Detector (YAML)
description: Detects stack traces and error messages in responses
type: active
severity: low
confidence: firm
tags: [custom, error-detection]
scan_types:
  - per_request

rules:
  - match:
      body_regex: "(?i)Traceback \\(most recent call last\\)"
    finding:
      name: "Error pattern: Python traceback"
      description: "Response body contains a Python traceback"
      severity: low

  - match:
      body_regex: "(?i)goroutine \\d+ \\[running\\]"
    finding:
      name: "Error pattern: Go panic stack trace"
      description: "Response body contains a Go panic stack trace"
      severity: low

  - match:
      body_regex: "(?i)SQLSTATE\\["
    finding:
      name: "Error pattern: SQL error"
      description: "Response body contains a SQL SQLSTATE error"
      severity: low
```

**Top-level active fields:**

| Field | Description |
|---|---|
| `tags` | Classification tags for `--module-tag` filtering |
| `scan_types` | `per_insertion_point`, `per_request`, `per_host` |
| `payloads` | List of strings to inject (used with `per_insertion_point`) |
| `matchers` | List of `MatcherDef` — all applied to the same finding |
| `matchers_condition` | `or` (default) or `and` — how matchers combine |
| `finding` | Single finding emitted when matchers pass |
| `rules` | List of `{match, finding}` pairs — evaluated independently |

Use `rules` when different patterns should emit different findings. Use `matchers` + `finding` when all conditions must be true together.

**Matcher types:**

```yaml
matchers:
  # Check body contains a string
  - contains: "password"

  # Check body with regex
  - regex: "(?i)error|exception"

  # Check response header exists
  - type: header
    name: X-Powered-By

  # Check HTTP status code
  - type: status
    codes: [500, 502, 503]

  # Negate a condition
  - contains: "success"
    negate: true
```

---

### Passive Module (YAML)

Passive YAML modules use the same `rules` structure but do not send new requests:

```yaml
# File: ~/.vigolium/extensions/sensitive_headers.vgm.yaml
id: sensitive-header-leak-yaml
name: Sensitive Header Leak (YAML)
type: passive
severity: info
confidence: certain
scope: response          # request | response | both
scan_types:
  - per_request

rules:
  - match:
      response_header: X-Powered-By
    finding:
      name: X-Powered-By header exposed
      description: "Server technology revealed via X-Powered-By header"
      matched: "{{matched}}"  # interpolates the matched header value
      severity: info

  - match:
      response_header: Server
      regex: "[0-9]+\\.[0-9]+"   # only match if value contains a version number
    finding:
      name: Server version disclosed
      description: "Server header exposes version information"
      matched: "{{matched}}"
      severity: low
```

**Rule match fields for `rules[].match`:**

| Field | Description |
|---|---|
| `body_contains` | Response body contains string |
| `body_regex` | Response body matches regex |
| `response_header` | Response header name exists |
| `regex` | Additional regex to apply to the header value |
| `contains` | String the header value must contain |
| `status` | List of HTTP status codes |

---

### Pre-Hook (YAML)

Pre-hooks in YAML support header injection, extension skipping, and conditional skipping.

**Inject headers:**

```yaml
# File: ~/.vigolium/extensions/add_auth.vgm.yaml
id: add-auth-header-yaml
name: Auth Header Injector (YAML)
type: pre_hook

# Skip this hook if the config variable is not set
skip_when:
  config_empty: auth_token

add_headers:
  Authorization: "Bearer {{config.auth_token}}"
  X-Correlation-ID: "{{rand(12)}}"
```

**Skip static files:**

```yaml
# File: ~/.vigolium/extensions/skip_static.vgm.yaml
id: skip-static-assets-yaml
name: Static Asset Skipper (YAML)
type: pre_hook

skip_extensions:
  - .css
  - .js
  - .png
  - .jpg
  - .gif
  - .svg
  - .ico
  - .woff
  - .woff2
  - .ttf
  - .map
```

**Pre-hook YAML fields:**

| Field | Description |
|---|---|
| `add_headers` | Map of header name → value to inject |
| `skip_extensions` | URL path suffixes that cause the request to be skipped |
| `skip_when.config_empty` | Skip if this config variable is empty |
| `skip_when.url_contains` | Skip if URL contains any of these strings |

**Template functions available in header values:**

| Template | Expands to |
|---|---|
| `{{config.VAR_NAME}}` | User-defined config variable |
| `{{rand(N)}}` | Random alphanumeric string of length N |

---

### Post-Hook (YAML)

Post-hooks in YAML can escalate severity or drop findings based on URL patterns.

**Escalate severity for critical paths:**

```yaml
# File: ~/.vigolium/extensions/critical_tagger.vgm.yaml
id: tag-critical-domains-yaml
name: Critical Domain Tagger (YAML)
type: post_hook

escalate:
  when_url_contains:
    - payment
    - admin
    - auth
    - checkout
    - billing
  tag: "CRITICAL"
  bump_severity: true      # info→low, low→medium, medium→high, high→critical
```

**Drop low-severity findings on certain paths:**

```yaml
id: drop-noisy-findings
type: post_hook

drop_when:
  severity:
    - info
  url_contains:
    - /static/
    - /assets/
```

---

## Context Objects Reference

### `ctx` — passed to all active/passive module functions

```javascript
ctx.request.url        // "https://example.com/api/users?id=1"
ctx.request.method     // "GET"
ctx.request.path       // "/api/users"
ctx.request.hostname   // "example.com"
ctx.request.headers    // { "Content-Type": "application/json", ... }
ctx.request.raw        // full raw HTTP request string

ctx.response.status    // 200
ctx.response.body      // response body as string
ctx.response.headers   // { "X-Powered-By": "PHP/8.1", ... }
ctx.response.raw       // full raw HTTP response string
ctx.response.title     // HTML page title (if applicable)
```

### `insertion` — second arg to `scanPerInsertionPoint`

```javascript
insertion.name              // "id" (parameter name)
insertion.baseValue         // "1" (original value)
insertion.type              // "url_param" | "body_param" | "header" | "cookie"
insertion.buildRequest(val) // returns raw request string with val injected
```

---

## Testing Your Extension

### Run only the extension phase

The fastest way to test your extension against already-ingested traffic without running a full scan:

```bash
# Run only extensions against existing scan data
vigolium scan --config vigolium-configs.yaml --only extension

# Alias: ext works too
vigolium scan --config vigolium-configs.yaml --only ext
```

This skips discovery, spidering, and standard dynamic-assessment modules — only your extensions run against traffic already in the database.

### Test against a live target

To ingest fresh traffic and immediately run only extensions:

```bash
# Ingest a URL list and run extensions only
vigolium scan -u targets.txt --only extension --config vigolium-configs.yaml

# Ingest a single URL
vigolium scan -u https://example.com --only extension --config vigolium-configs.yaml
```

### Use a one-off config with a custom extension path

You don't need to copy files to `~/.vigolium/extensions/`. Use `custom_dir` to point directly at your file:

```bash
# Point to your extension file via config or inline
vigolium scan -u https://example.com \
  --only extension \
  --config ./my-test-config.yaml
```

With `my-test-config.yaml`:

```yaml
dynamic_assessment:
  extensions:
    enabled: true
    custom_dir:
      - ./my_extension.js
      - ./my_extension.vgm.yaml
```

### Verify your extension loads

Before running a scan, check your extension is discovered and parsed correctly:

```bash
# List all loaded extensions
vigolium extensions ls

# Filter by your extension's ID
vigolium extensions ls my-extension-id

# Show full description and confirmation criteria
vigolium extensions ls --verbose

# Filter by type
vigolium extensions ls --type active
vigolium extensions ls --type passive
vigolium extensions ls --type pre_hook
vigolium extensions ls --type post_hook
```

### Browse the built-in API reference

```bash
# List all available vigolium.* API functions
vigolium extensions docs

# Filter to a specific function or namespace
vigolium extensions docs http
vigolium extensions docs randomString
vigolium extensions docs regexMatch
```

### Install preset examples to learn from

```bash
# Install all presets to ~/.vigolium/extensions/
vigolium extensions preset

# Install a single preset
vigolium extensions preset reflected_param_scanner
```

---

## Configuration Reference

Full `extensions` block options in `vigolium-configs.yaml`:

```yaml
dynamic_assessment:
  extensions:
    # Enable the extension engine. Default: false
    enabled: true

    # Directory scanned for .js and .vgm.yaml files
    # Default: ~/.vigolium/extensions/
    extension_dir: ~/.vigolium/extensions/

    # Additional explicit script paths (loaded in addition to extension_dir)
    custom_dir:
      - /path/to/my_scanner.js
      - /path/to/my_passive.vgm.yaml

    # Variables accessible as vigolium.config.* in scripts
    # Values support ${ENV_VAR} expansion
    variables:
      auth_token: "eyJhbGci..."
      collaborator_domain: "collab.example.com"
      api_key: "${MY_API_KEY}"

    # Resource limits per VM invocation
    limits:
      timeout: 30s         # Maximum execution time
      max_memory_mb: 128   # Memory cap per VM

    # Allow extensions to run shell commands (exec) and set env vars
    # Default: false — enable only for trusted extensions
    allow_exec: false

    # Restrict file I/O to this directory (readFile, writeFile, glob)
    sandbox_dir: /tmp/vigolium-sandbox
```

---

## Tips and Best Practices

**Return `null`, not `[]`** — returning an empty array is treated the same as `null`, but `null` is the conventional no-finding signal.

**Check for nil before accessing properties:**
```javascript
if (!ctx.response || !ctx.response.body) return null;
```

**Use `vigolium.utils.randomString` for canaries** to avoid collisions between concurrent extension invocations.

**Keep pre-hooks fast** — they run on every request before any module sees it. Avoid HTTP calls inside pre-hooks.

**YAML vs JS decision guide:**
- Use YAML when you need regex/header/status matching with a fixed finding output
- Use JS when you need: conditional logic, multiple HTTP requests, encoding/decoding, database lookups, or AI-augmented analysis

**Scope your passive module** — set `scope: "response"` if you only need response data. This avoids unnecessary invocations.

**Use `vigolium.config.*`** for secrets and environment-specific values instead of hardcoding them:
```javascript
var target = vigolium.config.collaborator_domain || "oast.pro";
```

**Avoid hardcoding the extension id** if you plan to distribute extensions — the filename without extension is used as the default ID, which is usually fine.

**Test incrementally** — start with `--only extension` and a small known dataset so your module's `console.log` output is easy to read.
