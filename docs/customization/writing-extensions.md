# Writing Extensions

Extensions let you add custom scanning logic to Vigolium without modifying the core scanner. You can write them in **JavaScript** for full flexibility, in **YAML** for declarative pattern matching, or use lightweight **quick checks** and **snippets** for fast iteration.

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
- [Quick Checks](#quick-checks)
- [Snippets](#snippets)
- [Context Objects Reference](#context-objects-reference)
- [API Reference](#api-reference)
- [Testing Your Extension](#testing-your-extension)
- [Configuration Reference](#configuration-reference)
- [Tips and Best Practices](#tips-and-best-practices)

---

## Overview

Extensions plug into the scanner pipeline at four points:

| Type | Runs when | Use for |
|---|---|---|
| `active` | During dynamic-assessment phase | Send payloads, detect vulnerabilities |
| `passive` | Analyzing captured traffic | Inspect request/response without new traffic |
| `pre_hook` | Before each request is sent | Modify requests, skip assets, inject headers |
| `post_hook` | After a finding is emitted | Escalate severity, drop false positives |

All four types are supported in JS, YAML, and (for active/passive) as quick checks or snippets. YAML is simpler for straightforward pattern matching. JS gives you full access to HTTP requests, regex, encoding utilities, the database API, OAST (out-of-band) testing, and optional AI-augmented analysis. Quick checks and snippets are even lighter — ideal for agent-generated or ad-hoc checks.

---

## Setup

### 1. Enable extensions in your config

Add or uncomment the `extensions` block under `dynamic-assessment` in your `vigolium-configs.yaml`:

```yaml
dynamic-assessment:
  extensions:
    enabled: true
    extension_dir: ~/.vigolium/extensions/   # scan this dir for .js and .vgm.yaml files
    custom_dir: []                           # explicit extra paths
    variables:
      auth_token: "Bearer eyJ..."            # accessible as vigolium.config.auth_token
    limits:
      timeout: 30s
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
| `severity` | For active/passive | `critical`, `high`, `medium`, `low`, `info`, `suspect` |
| `confidence` | No | `tentative`, `firm`, `certain` |
| `scanTypes` | For active/passive | `["per_insertion_point"]`, `["per_request"]`, `["per_host"]` |
| `tags` | No | Classification tags for `--module-tag` filtering (e.g. `["custom", "xss"]`) |

---

## Writing a JavaScript Extension

JS extensions run inside an embedded Sobek (ES5.1-compatible) VM. The global `vigolium` object provides all APIs.

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
    var canary = "VIGOLIUM" + vigolium.utils.randomString(8);

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

    var poweredBy = headers.get("x-powered-by");
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

Pre-hooks run before each request is sent to a module. `execute(request)` receives `{raw, method, url, headers}` (there is no `path` field; parse it from `url`). Return the modified request, a headers-only patch, or `null` to skip the request entirely.

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
    var parsed = vigolium.parse.url(request.url || "");
    var path = (parsed && parsed.path) || "";
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

## Quick Checks

Quick checks are the lightest extension format — declarative JSON objects that define "send payload, check response" patterns with zero JavaScript. They're ideal for agent-generated checks and rapid iteration.

### Per Insertion Point

Inject payloads into each parameter and check the response:

```json
{
  "id": "ssti-jinja2",
  "severity": "high",
  "scan": "per_insertion_point",
  "payloads": ["{{7*7}}", "${7*7}", "<%=7*7%>"],
  "match": {"body_contains": "49"}
}
```

### Per Request / Per Host

Send specific requests and check responses:

```json
{
  "id": "debug-endpoint",
  "severity": "medium",
  "scan": "per_host",
  "requests": [
    {"method": "GET", "path": "/.env"},
    {"method": "GET", "path": "/debug/vars"}
  ],
  "match": {"status": 200, "body_regex": "(DB_PASSWORD|SECRET_KEY)"}
}
```

### Match Fields

Match conditions use OR logic:

| Field | Description |
|---|---|
| `body_contains` | Response body contains string |
| `body_regex` | Response body matches regex |
| `status` | HTTP status code equals value |
| `header_contains` | Response header contains string |

### Rules

- `id` must be lowercase with hyphens (e.g. `"ssti-jinja2"`)
- `scan` is one of: `per_insertion_point`, `per_request`, `per_host`
- `severity` is one of: `critical`, `high`, `medium`, `low`, `info`
- Quick checks are automatically wrapped into full extension modules at runtime

---

## Snippets

Snippets are a middle ground between quick checks and full extensions — you write just the **function body** (no boilerplate), and it gets wrapped in a module scaffold automatically. Use snippets when you need custom logic or `vigolium.*` API access.

### Format

```json
{
  "id": "idor-check",
  "severity": "high",
  "scan": "per_request",
  "body": "var related = vigolium.db.records.getRelated(ctx.record.uuid);\nvar cmp = vigolium.db.compareResponses(related);\nif (!cmp.all_similar) {\n  return [{url: ctx.request.url, matched: 'Response variance', name: 'Potential IDOR'}];\n}\nreturn null;"
}
```

### Available Variables

Inside the snippet body, you have access to:

| Variable | Description |
|---|---|
| `ctx` | Request/response context (`ctx.request`, `ctx.response`, `ctx.record`) |
| `insertion` | Insertion point object (only for `per_insertion_point` scan type) |
| `vigolium.http` | HTTP requests, sessions, batch, replay, sequence, auth testing |
| `vigolium.db` | Database queries for records and findings |
| `vigolium.utils` | Encoding, hashing, diff, JWT, CSS selectors, etc. |
| `vigolium.parse` | URL, request, response, HTML parsing |
| `vigolium.scan` | Module listing, scope, finding creation |
| `vigolium.source` | Source code access and search |
| `vigolium.agent` | AI-augmented analysis |
| `vigolium.oast` | Out-of-band testing |
| `vigolium.ingest` | Data ingestion |
| `vigolium.payloads()` | Built-in payload wordlists |

### Rules

- `id` must be lowercase with hyphens
- `scan` is one of: `per_insertion_point`, `per_request`, `per_host`
- `body` contains the function body as a string (newlines escaped as `\n`)
- The return value follows the same convention as full extensions: array of findings or `null`

---

## Context Objects Reference

### `ctx` — passed to all active/passive module functions

```javascript
ctx.request.url        // "https://example.com/api/users?id=1"
ctx.request.method     // "GET"
ctx.request.path       // "/api/users"
ctx.request.hostname   // "example.com"
ctx.request.headers    // header object, see below
ctx.request.raw        // full raw HTTP request string

ctx.response.status    // 200
ctx.response.body      // response body as string
ctx.response.headers   // header object, see below
ctx.response.raw       // full raw HTTP response string
ctx.response.title     // HTML page title (if applicable)
```

### Header objects

`ctx.request.headers`, `ctx.response.headers`, the pre-hook `request.headers`, the `headers` of every `vigolium.http.*`/session/MCP response, and the YAML `js` matcher's `response.headers` all behave the same way:

```javascript
headers.get("x-powered-by")      // "PHP/8.1": case-insensitive, null when absent
headers["X-Powered-By"]          // same value; property access is case-insensitive too
headers.has("content-type")      // true
headers.getAll("set-cookie")     // ["a=1; Path=/", "b=2; Path=/"]: every value, wire order
headers["set-cookie"]            // "b=2; Path=/": set-cookie reads as the LAST value
headers["cache-control"]         // "no-cache, no-store": other repeats join with ", "
Object.keys(headers)             // ["content-type", "set-cookie", ...]: lowercase, first-occurrence order
headers.entries()                // [["Set-Cookie", "a=1; Path=/"], ...]: original case, every occurrence
headers.raw()                    // { "Set-Cookie": "b=2; Path=/", ... }: the pre-0.7 original-case object
```

Assigning or deleting a property changes only the JS view. In a pre-hook, returning `{headers: request.headers}` applies just the headers you assigned or deleted. A header whose name matches a method (`get`, `getAll`, `has`, `entries`, `raw`) or an `Object.prototype` member is not exposed as a property, so a server cannot shadow `headers.get`; read it with `headers.get(name)` or `headers.entries()`.

### `insertion` — second arg to `scanPerInsertionPoint`

```javascript
insertion.name              // "id" (parameter name)
insertion.baseValue         // "1" (original value)
insertion.type              // "url_param" | "body_param" | "header" | "cookie"
insertion.buildRequest(val) // returns raw request string with val injected
```

### `ctx.record` — current HTTP record context

```javascript
ctx.record.uuid              // database UUID of the current record
ctx.record.annotate(patch)   // update risk_score/remarks
ctx.record.addRiskScore(delta) // increment risk score (can be negative, clamped to 0)
ctx.record.addRemarks(remarks) // append remarks with deduplication
```

---

## API Reference

### vigolium.log

| Function | Description |
|---|---|
| `info(msg)` | Log info message |
| `warn(msg)` | Log warning message |
| `error(msg)` | Log error message |
| `debug(msg)` | Log debug message |

### vigolium.utils

**Encoding:**

| Function | Description |
|---|---|
| `base64Encode(s)` / `base64Decode(s)` | Base64 encode/decode |
| `urlEncode(s)` / `urlDecode(s)` | URL encode/decode |
| `htmlEncode(s)` / `htmlDecode(s)` | HTML entity encode/decode |

**Hashing:**

| Function | Description |
|---|---|
| `sha1(s)` | SHA-1 hash |
| `sha256(s)` | SHA-256 hash |
| `md5(s)` | MD5 hash |

**Random:**

| Function | Description |
|---|---|
| `randomString(len)` | Random alphanumeric string |

**Regex:**

| Function | Description |
|---|---|
| `regexMatch(str, pattern)` | Test if string matches regex |
| `regexExtract(str, pattern)` | Extract matches from string |

**File I/O:**

| Function | Description |
|---|---|
| `readFile(path)` | Read file contents |
| `readLines(path)` | Read file as array of lines |
| `writeFile(path, data)` | Write data to file |
| `mkdir(path)` | Create directory |
| `glob(pattern)` | Find files matching pattern |

**URL utilities:**

| Function | Description |
|---|---|
| `parse_url(url, format)` | Parse URL with format |
| `pathToTemplate(path)` | Replace dynamic segments with `*` |
| `hasDynamicSegment(path)` | Check for dynamic segments (IDs, UUIDs) |

**Parameter utilities:**

| Function | Description |
|---|---|
| `toSet(csv)` | Convert CSV string to `{key: true}` map |
| `extractParamNames(str)` | Extract deduplicated param names from query/body |

**Diff and similarity:**

| Function | Description |
|---|---|
| `diff(a, b)` | Line-by-line comparison → `{added, removed, similarity}` |
| `similarity(a, b)` | Jaccard similarity (0.0–1.0) on word tokens |
| `diffResponses(a, b)` | Structural HTTP response comparison → `{status_match, body_similarity, header_diff, body_diff, length_diff, likely_same_content}` |

**HTML:**

| Function | Description |
|---|---|
| `cssSelect(html, selector)` | CSS selector query → `[{text, attrs, html}]` |

**Token extraction:**

| Function | Description |
|---|---|
| `extractToken(response, rules)` | Extract tokens from HTTP response using configurable rules (json/header/cookie/regex) |

**JWT:**

| Function | Description |
|---|---|
| `jwtDecode(token)` | Decode JWT without verification → `{header, payload, signature}` |
| `jwtEncode(payload, opts?)` | Forge JWT (HS256/HS384/HS512/none) |
| `jwtExpired(token)` | Check if JWT is expired |

**Multipart:**

| Function | Description |
|---|---|
| `multipart(fields)` | Build multipart/form-data body → `{body, contentType}` |

**Anomaly detection:**

| Function | Description |
|---|---|
| `detectAnomaly(responses)` | Score responses by divergence → `[{index, score}]` |

**Other:**

| Function | Description |
|---|---|
| `sleep(ms)` | Sleep for milliseconds |
| `exec(cmd)` | Execute shell command (requires `allow_exec`) → `{stdout, stderr, exitCode}` |
| `getEnv(name)` / `setEnv(name, value)` | Environment variables |
| `jsonExtract(json, path)` | Extract value from JSON by path |

### vigolium.parse

| Function | Description |
|---|---|
| `url(str)` | Parse URL → `{scheme, host, hostname, port, path, query, fragment, params, segments, template}` |
| `request(raw)` | Parse raw HTTP request → `{method, path, query, version, headers, body, host, params, cookies}` |
| `response(raw)` | Parse raw HTTP response → `{status, statusText, version, headers, body, cookies, contentType}` |
| `headers(str)` | Parse header block → `{name: value}` |
| `cookies(str)` | Parse Cookie header → `{name: value}` |
| `query(str)` | Parse query string → `{name: value}` |
| `json(str)` | Parse JSON string → native value |
| `form(body)` | Parse URL-encoded form → `{name: value}` |
| `html(str)` | Parse HTML → `{forms, links, scripts, meta}` |

### vigolium.http

**Basic requests:**

| Function | Description |
|---|---|
| `get(url, opts?)` | HTTP GET |
| `post(url, body, opts?)` | HTTP POST |
| `request(opts)` | Full control (method, url, headers, body) |
| `send(rawRequest)` | Send raw HTTP request string |
| `buildRequest(rawRequest, overrides)` | Clone and modify a raw request (method, path, headers, body, query) |

**Sessions:**

| Function | Description |
|---|---|
| `session(opts?)` | Create persistent session with shared cookie jar and default headers |
| `login(opts)` | Send credentials, extract auth tokens, return authenticated session |
| `sessionPool(configs)` | Create named session pool from config map |
| `followAuth(opts)` | Execute OAuth2 flow (client_credentials, password, code grants) |

Session objects expose: `get()`, `post()`, `request()`, `send()`, `setHeader()`, `removeHeader()`, `getHeaders()`, `getCookies()`, `setCookie()`, `cloneAs()`, `onRequest()`, `onResponse()`, `setAutoRefresh()`.

**Batch and replay:**

| Function | Description |
|---|---|
| `batch(requests, opts?)` | Send multiple requests in parallel (configurable concurrency) |
| `replay(rawRequest, variations)` | Replay request with multiple variations (header overrides, body swaps) |

**Multi-step workflows:**

| Function | Description |
|---|---|
| `sequence(steps)` | Execute request sequence with variable extraction (`{{varName}}`), conditional execution, fallback steps, and repeat loops |

**Auth testing:**

| Function | Description |
|---|---|
| `authTest(opts)` | Test IDOR/BOLA by replaying requests across sessions with different privilege levels |
| `csrf(url, opts?)` | Extract CSRF token from page (form, meta, header, cookie sources) |

**Retry and caching:**

| Function | Description |
|---|---|
| `retry(request, opts?)` | Retry with configurable backoff (max retries, retry_on status codes, until predicate) |
| `cache(opts?)` | Enable response caching with TTL and max entries |
| `clearCache()` | Clear all cached responses |
| `cachedGet(url, opts?)` | GET with cache |
| `cachedRequest(opts)` | Full request with cache |

**GraphQL:**

| Function | Description |
|---|---|
| `graphql(url, opts)` | Send GraphQL query/mutation → `{data, errors, raw}` |
| `graphqlSchema(url, opts?)` | Fetch introspection schema |

### vigolium.scan

| Function | Description |
|---|---|
| `listModules()` | List all registered modules |
| `listModuleTags()` | List all unique module tags |
| `listModulesByTag(tag)` | List modules with a specific tag |
| `isInScope(host, path)` | Check if host/path is in scope |
| `getScope()` / `setScope(scope)` | Get/set scope configuration |
| `createFinding(finding)` | Persist a finding |
| `getCurrentScan()` | Get current scan info |
| `startNewScan(opts)` | Start a new scan |
| `scanRecords(opts)` | Queue scan for existing records by UUIDs |

### vigolium.ingest

| Function | Description |
|---|---|
| `url(url)` | Ingest a single URL |
| `urls(content)` | Ingest multiple URLs from content |
| `curl(command)` | Ingest from curl command |
| `raw(rawRequest, rawResponse?)` | Ingest raw HTTP request/response |
| `openapi(spec, opts?)` | Ingest from OpenAPI spec |
| `postman(collection)` | Ingest from Postman collection |

### vigolium.source

| Function | Description |
|---|---|
| `list(hostname?)` | List source repos |
| `get(id)` | Get source repo by ID |
| `getByHostname(hostname)` | Get repos by hostname |
| `readFile(hostname, path)` | Read source file |
| `listFiles(hostname, glob?)` | List source files |
| `searchFiles(hostname, pattern)` | Search source files by pattern |

### vigolium.agent (AI-augmented)

| Function | Description |
|---|---|
| `complete(opts)` | Full control: model, messages, schema, max_tokens → `{content, model, tokens_in, tokens_out}` (`temperature` is accepted and ignored) |
| `ask(prompt, opts?)` | Single prompt → text response |
| `chat(messages, opts?)` | Conversation → text response |
| `generatePayloads(opts)` | Generate context-aware security payloads by type, context, technology, WAF |
| `analyzeResponse(opts)` | Analyze HTTP exchange for vulnerability → `{vulnerable, confidence, evidence, details}` |
| `confirmFinding(opts)` | Verify true positive → `{confirmed, confidence, reasoning, false_positive_indicators}` |

### vigolium.oast (Out-of-Band Testing)

| Function | Description |
|---|---|
| `enabled()` | Check if OAST service is active |
| `payload(targetURL?, paramName?, injectionType?)` | Generate unique OAST callback URL → `{url}` (callbacks rated by a class guessed from `injectionType`) |
| `url({class?, target?, param?, label?})` | Generate unique OAST callback URL → string, or `null` when OAST is unavailable. `class` sets how a callback is rated: `ssrf`, `ssrf-smuggle`, `xxe`, `cmdi`, `sqli`, `jwt-key-url`, `host-routing`, `header-harvest`, `password-reset-poisoning`, `blind-xss`, `ssti`, `deserialization`, `jndi`, `text4shell`, `esi`, `smtp`, `mcp-arg`, or `generic` (default). An unknown class throws, and `ext lint` reports a literal unknown class as an error |
| `poll(timeoutMs?)` | Wait then return all OAST interactions → `[{protocol, unique_id, remote_address, target_url, parameter_name, module_id, interacted_at}]` |

### vigolium.db

**Records:**

| Function | Description |
|---|---|
| `records.query(filters?)` | Query HTTP records with filters (hostname, path, methods, status_codes, source, search, fuzzy, min_risk_score, limit, offset, sort) |
| `records.get(uuid)` | Get single record by UUID |
| `records.getRelated(uuid, opts?)` | Get records with same path template/hostname |
| `records.annotate(uuid, patch)` | Update risk_score/remarks |
| `records.grouped(opts?)` | Group by path template for IDOR detection → `[{template, method, records, param_values}]` |

**Findings:**

| Function | Description |
|---|---|
| `findings.query(filters?)` | Query findings (severity, module_name, scan_uuid filters) |
| `findings.get(id)` | Get finding by ID |
| `findings.getByRecord(uuid)` | Get findings for an HTTP record |
| `findings.create(finding)` | Persist a new finding |

**Comparison:**

| Function | Description |
|---|---|
| `compareResponses(records)` | Anomaly detection across record set → `{all_similar, scores, variant_count, summary}` |

### vigolium.payloads(type)

Returns built-in payload wordlists by vulnerability type. Types: `"xss"`, `"sqli"`, `"ssti"`, `"ssrf"`, `"lfi"`, `"path_traversal"`, `"xxe"`, `"cmdi"`, `"open_redirect"`, `"crlf"`.

```javascript
var payloads = vigolium.payloads("xss");
// ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", ...]
```

### vigolium.config

Read-only config values from the `variables` block in `vigolium-configs.yaml`:

```javascript
var token = vigolium.config.auth_token;
var domain = vigolium.config.collaborator_domain || "oast.pro";
```

---

## Testing Your Extension

### Run only the extension phase

The fastest way to test your extension against already-ingested traffic without running a full scan:

```bash
# Run only extensions against existing scan data
vigolium scan --all-records --config vigolium-configs.yaml --only extension

# Alias: ext works too
vigolium scan --all-records --config vigolium-configs.yaml --only ext
```

This skips discovery, spidering, and standard dynamic-assessment modules — only your extensions run against traffic already in the database.

### Test against a live target

To ingest fresh traffic and immediately run only extensions:

```bash
# Ingest a URL list and run extensions only
vigolium scan -T targets.txt --only extension --config vigolium-configs.yaml

# Ingest a single URL
vigolium scan https://example.com --only extension --config vigolium-configs.yaml
```

### Use a one-off config with a custom extension path

You don't need to copy files to `~/.vigolium/extensions/`. Use `custom_dir` to point directly at your file:

```bash
# Point to your extension file via config or inline
vigolium scan https://example.com \
  --only extension \
  --config ./my-test-config.yaml
```

With `my-test-config.yaml`:

```yaml
dynamic-assessment:
  extensions:
    enabled: true
    custom_dir:
      - ./my_extension.js
      - ./my_extension.vgm.yaml
```

### Lint before you scan

`vigolium ext lint` loads each file the way a scan does — the top-level code runs in
the loader's own VM — and reports what would go wrong:

```bash
vigolium ext lint my_scanner.js            # exit 1 (error.code lint_failed) on errors
vigolium ext lint ~/.vigolium/extensions/  # every .js/.ts/.vgm.yaml in the directory
vigolium ext lint my_scanner.js --strict   # warnings fail too
vigolium ext lint ./exts -j                # one JSON document (see below)
cat check.vgm.yaml | vigolium ext lint --stdin   # sniffed as YAML; force with --stdin-kind js|ts|yaml
```

What lint checks, with the rule id each issue carries:

| Rule | Severity | Meaning |
|---|---|---|
| `syntax`, `transpile` | error | The JavaScript does not parse, or the TypeScript does not transpile |
| `metadata` | error | Top-level code threw, or `module.exports` lacks a `type` |
| `no-exports` | error | The file exports nothing. A plain script meant for `vigolium js` can opt out with a `// vigolium:script` line |
| `missing-handler` | error | A declared `scanTypes` entry (default `per_request`) or hook type has no matching function (`scanPerInsertionPoint`, `scanPerRequest`, `scanPerHost`, `execute`). The scan would load the extension and never call it |
| `invalid-type`, `bad-confidence` | error | Unknown `type` or `confidence` value |
| `top-level-effect` | warning | Top-level code calls an effectful API (`vigolium.http.*`, `utils.exec`, `utils.writeFile`, `db.*`, `agent.*`, …). At load time such calls are stubbed and return an empty value; at scan time they run for real in every VM. Move them into a handler |
| `unknown-api`, `unknown-oast-class` | warning / error | A `vigolium.*` name, or a `vigolium.oast.url` class, that does not exist |
| `missing-severity`, `bad-severity`, `bad-scan-type`, `bad-scope` | warning | Metadata values outside the known set |
| `yaml-parse`, `yaml-schema`, `yaml-unknown-key` | error | YAML that does not parse or does not match the schema. Unknown keys name the closest real key: `unknown key "matchers_condtion" (did you mean "matchers_condition"?)` |
| `payloads-unused` | warning | A YAML extension has `payloads` but `scan_types` lacks `per_insertion_point`, the only scan type that sends them |

Pure APIs (`vigolium.parse.*`, `utils` encoding/hashing/regex helpers, `log.*`, `payloads()`, `config.*`) run for real at load time, so `var u = vigolium.parse.url("…")` at the top of a file is fine. Every namespace exists at load time, so feature detection such as `if (vigolium.db)` is always true there; check inside a handler instead.

With `-j` the result is one document: `items` holds one entry per file
(`{path, kind: js|ts|yaml, issues: [{severity, line, col, message, rule}]}`),
`summary` holds `{files, errors, warnings}`, and `ok` is `false` exactly when there are errors.

### Run it against one stored record

`vigolium ext run` loads one extension the way a scan does and calls its handlers against a stored HTTP record. It sends nothing unless you allow it, and it never writes to the database. `ext eval --ext <file> --record-uuid <uuid>` is the same command.

```bash
vigolium traffic --compact --fields uuid,url -j                  # find a record
vigolium ext run --ext my_scanner.js --record-uuid 3f2a9c1e      # a UUID or a unique prefix
vigolium ext run --ext my_scanner.js --record-uuid 3f2a9c1e --handler scanPerInsertionPoint --insertion URL_PARAM:id
vigolium ext run --ext my_scanner.js --record-uuid 3f2a9c1e --allow-network -j
```

- Without `--handler`, every handler the module's `scanTypes` select is called. `scanPerInsertionPoint` runs once per insertion point the module accepts, or only on `--insertion TYPE:name` (`URL_PARAM:id`, `BODY_PARAM:user`, `HEADER:X-Api-Key`). An unknown point exits `2` and lists the available ones.
- **Offline by default.** Every request fails with `network disabled in ext eval; pass --allow-network`, and `vigolium.http.*` throws it, so the handler stops at the first call and you see where. Each refused request counts in `network_calls_blocked`. `--allow-network` sends them through the normal HTTP stack (`--proxy` applies).
- **Read-only database.** `vigolium.db.*` reads work. `ctx.record.uuid` is the record, but `annotate`, `addRiskScore`, `addRemarks` and `vigolium.ingest.*` return `false`. `vigolium.oast` and `vigolium.agent` are not available.
- **Exit codes.** A handler that threw exits `1`. An unknown record exits `2` (`record_not_found`), and an extension that does not load exits `2` (`extension_load_failed`).
- **`-j` document.** `items` are the results, with the module's severity, confidence, name and tags filled in as a scan fills them. The top level carries `module_id`, `record_uuid`, `handler`, `handlers`, `calls`, `errors` (`[{handler, insertion, message}]`, where the message ends with the script position), `network_allowed`, `network_calls_blocked` and `duration_ms`.

### Pin its behaviour with fixtures: `ext test`

Fixture cases live next to the extension in `<name>.fixtures/`. `vigolium ext test <dir|file>` runs every case and reports TAP-like output. It exits `1` when any case fails, and `-j` prints one document whose items are the cases, with `passed`, `failed` and `skipped` counts.

```text
my-extensions/
  my_scanner.js
  my_scanner.fixtures/
    weak.http                 # a raw request, a blank line, a raw response
    weak.expect.json          # what the case must produce
    clean.http                # the expectation can also be a leading "// expect:" line
    reflected.http            # an active case
    reflected.responses/      # canned responses for the extension's own requests
      search.http
```

```http
// expect: {"findings": [{"name~": "weak content-security-policy", "severity": "medium", "confidence": "firm"}]}
GET / HTTP/1.1
Host: app.example.com

HTTP/1.1 200 OK
Content-Type: text/html
Content-Security-Policy: default-src *; script-src 'unsafe-inline'

<html></html>
```

- **Expectation** (`<case>.expect.json` or `// expect: {...}`). `findings` is a count, or a list of matchers that must all match distinct results, in any order, with equal counts. Matcher keys are `name~` (substring), `name` (whole name), `severity` and `confidence`, all case-insensitive. `errors` (handler calls allowed to fail) defaults to `0`. `network_calls_blocked`, `mock_requests`, `handler` and `insertion` are optional. An unknown key fails the case.
- **Directives** go on leading `//` lines: `expect`, `handler`, `insertion` and `url` (the request's origin, default `http://<Host>`). LF line endings are accepted, and a declared `Content-Length` is corrected to the body in the file.
- **Offline cases.** A case without a `.responses` directory runs offline, exactly like `ext run`: requests are refused and counted.
- **Mock-backed cases.** A case with `<case>.responses/` is served by an in-process mock bound to 127.0.0.1, and the case's `Host` is pointed at it, so the full HTTP stack runs without leaving the machine. Each response file is a request line (`GET /search`, or `GET /search?q=x` to match the full target, `*` for any method), an optional `// match: <text>` line that the request target or body must contain (such routes are tried first), a blank line, and the raw response. A request no file matches gets a 404 and is listed in `unmatched_requests`.
- `ext test` opens no database, so `vigolium.db` is undefined there. An extension with no fixtures, and a hook, is reported as skipped. A `.fixtures` directory with no matching extension fails.

The bundled presets ship their fixtures in `public/presets/extensions/*.fixtures`, and `make test-unit` runs them. Read those fixtures for working examples.

### When an extension fails to load

- **Named with `--ext` (or listed in `custom_dir`)**: the scan stops before it sends any request, exits `2` with `error.code` `extension_load_failed`, and names the file and the stage that failed (`read`, `transpile`, `compile`, `metadata`, `schema`, `unknown_type`, `module`). Pass `--ext-allow-failures` (or set `allow_load_failures: true`) to scan without it.
- **Found in the extension directory**: the scan continues without it.
- Either way each failure prints a warning on stderr, emits an `extension.failed` event (`module_id`, `path`, `stage`, `explicit`, `message`) on `--events`, and is listed in `scan.finished.extensions_failed` and on the scan row.
- **YAML unknown keys** are a warning at load time in this release. Set `yaml_strict: true` to make them a load failure (an explicit file then stops the scan); the default becomes `true` in the next minor release. `ext lint` always reports them as errors.

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
dynamic-assessment:
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

    # Allow extensions to run shell commands (exec) and set env vars
    # Default: false — enable only for trusted extensions
    allow_exec: false

    # Restrict file I/O to this directory (readFile, writeFile, glob)
    sandbox_dir: /tmp/vigolium-sandbox

    # Make an unknown key in a .vgm.yaml file a load failure instead of a
    # warning. Default: false (becomes true in the next minor release)
    yaml_strict: false

    # Keep scanning when an extension named with --ext / custom_dir fails to
    # load (same as --ext-allow-failures). Default: false — the scan stops
    # before any traffic with exit 2, extension_load_failed
    allow_load_failures: false
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

**YAML vs JS vs quick check decision guide:**
- Use **quick checks** when you need simple payload-and-match patterns with no logic
- Use **snippets** when you need `vigolium.*` API access but don't want full boilerplate
- Use **YAML** when you need regex/header/status matching with a fixed finding output
- Use **JS** when you need: conditional logic, multiple HTTP requests, encoding/decoding, database lookups, session management, or AI-augmented analysis

**Scope your passive module** — set `scope: "response"` if you only need response data. This avoids unnecessary invocations.

**Use `vigolium.config.*`** for secrets and environment-specific values instead of hardcoding them:
```javascript
var target = vigolium.config.collaborator_domain || "oast.pro";
```

**Use built-in payloads** instead of hardcoding wordlists:
```javascript
var payloads = vigolium.payloads("xss");
```

**Enable response caching** for extensions that make repeated baseline requests:
```javascript
vigolium.http.cache({ ttl_ms: 30000 });
var baseline = vigolium.http.cachedGet(url);
```

**Use sessions for multi-request flows** — sessions persist cookies and headers:
```javascript
var session = vigolium.http.session({ headers: { "Authorization": "Bearer " + token } });
session.get(url1);
session.post(url2, body); // cookies from url1 are sent automatically
```

**Avoid hardcoding the extension id** if you plan to distribute extensions — the filename without extension is used as the default ID, which is usually fine.

**Test incrementally** — start with `--only extension` and a small known dataset so your module's `console.log` output is easy to read.
