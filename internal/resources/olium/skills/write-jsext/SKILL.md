---
name: write-jsext
description: Reference for writing custom vigolium JavaScript extensions. Use when you need to author a one-off scanner module — passive (reads existing HTTP records) or active (sends new requests) — and run it via the run_extension tool. Covers the module shape, the vigolium.* API surface, and the common pitfalls.
license: MIT
allowed-tools:
  - read_file
  - write_file
  - edit_file
  - run_extension
  - run_scan
---

# Writing a Custom Vigolium JS Extension

You're authoring a single-file JavaScript extension that the vigolium scanner
will load and run. Two output paths from here:

1. Hand the file path or inline source to **`run_extension`** to execute it
   immediately and get back findings.
2. Write the file to disk (e.g. into the session dir) for the operator to
   reuse later via `vigolium scan --ext path/to/script.js`.

You do **not** need a build step. Vigolium's embedded JS engine (Sobek) runs
the script directly. ES2017 features work; no `import` / `export` — use
`module.exports`.

## Module Shape

Every extension exports one object via `module.exports`. The shape decides
whether it runs as a passive or active scanner module.

### Passive (read-only, runs against stored HTTP records)

```javascript
module.exports = {
  id: "kebab-case-id",                // unique within the run
  name: "Human-readable name",
  description: "1–2 sentence purpose",
  type: "passive",                     // required
  severity: "low",                     // critical|high|medium|low|info
  confidence: "tentative",             // certain|firm|tentative
  scope: "response",                   // request|response|both — what to read
  tags: ["exposure", "light"],         // free-form classification
  scanTypes: ["per_request"],          // only "per_request" for passive

  scanPerRequest: function(ctx) {
    // ctx.request:  { url, method, headers, body, ... }
    // ctx.response: { status, headers, body, ... }
    // ctx.record:   { uuid, addRemarks(tags) }  (DB-backed records only)
    //
    // Return null when there's nothing to report, OR an array of finding
    // objects (see "Finding shape" below). Throwing is fine — vigolium
    // catches per-record errors and continues.
  }
};
```

### Active (sends new requests; can mutate inputs and probe)

```javascript
module.exports = {
  id: "active-extension-id",
  name: "Active Extension",
  description: "What it tests for",
  type: "active",                      // required
  severity: "medium",
  confidence: "tentative",
  tags: ["injection", "custom"],
  scanTypes: ["per_request"],          // most common; per_host / per_insertion_point also exist

  scanPerRequest: function(ctx) {
    // Same ctx as passive, plus you can call vigolium.http.* to send
    // new requests, and vigolium.parse.* / vigolium.utils.* for helpers.
    // Return null or an array of findings.
  }
};
```

### Finding shape (what scanPerRequest returns)

```javascript
return [{
  url: ctx.request ? ctx.request.url : "",  // required
  matched: "the substring or evidence",      // shown verbatim in reports
  name: "Specific bug title",                // overrides module name
  description: "Markdown-friendly evidence + reasoning",
  severity: "high",                          // overrides module severity
  // optional:
  request: ctx.request ? ctx.request.raw : "",
  response: ctx.response ? ctx.response.raw : "",
  tags: ["custom", "graphql"]
}];
```

Or, instead of returning, you can call `vigolium.scan.createFinding(obj)`
directly. Returning is preferred — it composes better with the executor's
deduplication and rate-limiting.

## Core API Cheat-Sheet

Only the most common pieces. Full TypeScript defs live at
`pkg/jsext/vigolium.d.ts` — read it if you need an obscure helper.

### `vigolium.http`

```javascript
vigolium.http.get(url, opts)                 // -> HttpResponse
vigolium.http.post(url, body, opts)          // -> HttpResponse
vigolium.http.request({ url, method, headers, body })
vigolium.http.send(rawHttpRequestString)     // raw request, ignores cookies
vigolium.http.batch([req1, req2, ...])       // parallel; returns []
vigolium.http.session({ headers, cookies })  // persistent jar + defaults
vigolium.http.login({ url, body, ... })      // returns authed session
vigolium.http.cachedGet(url, opts)           // memoized within the run
```

`HttpResponse` exposes `status`, `headers`, `body`, `raw`, plus helpers like
`.json()`, `.text()`. Treat `headers` as case-insensitive but values as
arrays-or-strings; normalize with `vigolium.utils.headerValue(h, "name")`.

### `vigolium.parse` and `vigolium.utils`

```javascript
vigolium.parse.url(url)                      // { scheme, hostname, port, path, query, ... }
vigolium.utils.hasDynamicSegment(path)       // true for /users/123, /items/<uuid>
vigolium.utils.pathToTemplate(path)          // /users/123 -> /users/*
vigolium.utils.regexMatch(haystack, regex)   // boolean
vigolium.utils.regexExtract(haystack, regex) // array of matches (capture group 1)
vigolium.utils.md5(s) / sha256(s) / base64Encode(s)
```

### `vigolium.log`

```javascript
vigolium.log.info("...")   // visible in runtime.log + verbose output
vigolium.log.warn("...")   // surfaces in operator console
vigolium.log.error("...")  // tagged red; doesn't abort the script
```

Don't use `console.log` — it's a no-op in this engine.

### `vigolium.db` (only when a repository is wired up — usually true at run time)

```javascript
vigolium.db.records.query({ hostname, path, method, limit })
vigolium.db.records.annotate(uuid, { risk_score, remarks })
vigolium.db.compareResponses(records)        // anomaly grouping helper
vigolium.db.findings.query({ scanUUID, severity })
```

### `vigolium.scan`

```javascript
vigolium.scan.isInScope(host, path)          // honor scope rules in custom checks
vigolium.scan.getCurrentScan()               // { uuid: "<scan-uuid>" }
vigolium.scan.createFinding(findingObj)      // bypasses return-array path
```

### `vigolium.oast` (out-of-band callback testing)

```javascript
var oast = vigolium.oast.allocate();         // { url, hostname, ... }
// fire a request that triggers a callback to oast.url
var hits = vigolium.oast.poll(oast.id, 30);  // wait up to 30s for callbacks
```

Use this for SSRF, blind XSS, blind SQLi, log4shell-style probes.

### `vigolium.agent` (LLM-assisted analysis — optional, may be unavailable)

```javascript
var verdict = vigolium.agent.confirmFinding({
  name: "Reflected XSS",
  request: ctx.request.raw,
  response: ctx.response.raw,
  matched: payload
});
if (verdict && verdict.confirmed) { /* ... */ }

vigolium.agent.generatePayloads({ type: "xss", context: "html", count: 5 });
```

Always null-check the result — `vigolium.agent.*` returns null when no LLM
client is configured.

## Common Pitfalls

1. **No `import` / `export` / `require`** beyond `module.exports`. Stick to
   plain JS plus the `vigolium.*` globals.
2. **Don't mutate `ctx.request` / `ctx.response`** — they're shared with
   other modules. If you need a modified request, build a new one with
   `vigolium.http.buildRequest(ctx.request.raw, { ... })`.
3. **Regex flags use string syntax**, not literal `/.../i`. The engine
   accepts a string pattern; pass `"(?i)foo"` for case-insensitive.
4. **Skip irrelevant content types.** Most passive checks should bail
   early on CSS / images / fonts — see `internal_url_leak.js` for the
   pattern.
5. **Always set `confidence: "tentative"` for heuristic checks.** Save
   `firm` / `certain` for cases where you've actually verified the bug
   (e.g., OAST callback received, response diff confirmed).
6. **Per-request modules are fan-out.** They run for every record in
   scope — keep them cheap. Use `vigolium.http.cachedGet` for repeated
   lookups, and bail on the first signal that the check doesn't apply.

## Minimal Working Example (passive)

```javascript
// detect-debug-headers.js
module.exports = {
  id: "debug-headers",
  name: "Debug headers exposed",
  description: "Flags responses leaking X-Debug-* / X-Powered-By in production-looking apps",
  type: "passive",
  severity: "low",
  confidence: "firm",
  scope: "response",
  tags: ["exposure", "headers", "light"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.headers) return null;

    var leaked = [];
    var headers = ctx.response.headers;
    for (var name in headers) {
      var lower = name.toLowerCase();
      if (lower.indexOf("x-debug") === 0 ||
          lower === "x-powered-by" ||
          lower === "server") {
        leaked.push(name + ": " + headers[name]);
      }
    }
    if (leaked.length === 0) return null;

    return [{
      url: ctx.request.url,
      matched: leaked.join("; "),
      name: "Debug / framework headers exposed",
      description: "Response includes verbose framework headers:\n" +
        leaked.map(function(l) { return "- `" + l + "`"; }).join("\n"),
      severity: "low"
    }];
  }
};
```

## Iteration Loop

Once you have a draft:

1. **Validate by running it.** Call `run_extension` with `script_source`
   (or `script_path` if you wrote it to disk first). Pass concrete
   targets so you get real findings back, not just a smoke test.
2. **Read the result struct.** `finding_count > 0` is your signal that
   the matcher fires. Zero usually means a regex / scope mistake — add
   `vigolium.log.info(...)` lines and re-run.
3. **Tighten before declaring success.** False positives are the
   default — a passing run on one URL doesn't mean the rule is good.
   Run against at least 2–3 targets, including one that should NOT
   match.
4. **Persist when settled.** If the operator wants this to run as part
   of regular scans, write the file under `<sessionDir>/extensions/`
   or a project-level extensions directory.

## When NOT to Write an Extension

If the bug class already has a built-in module (xss, sqli, ssrf, idor,
etc.), prefer `run_scan` with `modules: ["<id>"]` over a hand-written
extension. Extensions are for novel logic that doesn't fit the
generic scanner shape — protocol quirks, app-specific invariants,
correlation across records, custom OAST flows.
