# Writing JavaScript Extensions

Guide for writing custom vigolium scanner modules as JavaScript extensions.

## Table of Contents

- [Overview](#overview)
- [Extension Structure](#extension-structure)
- [Running Extensions](#running-extensions)
- [Module Types](#module-types)
- [Context Object](#context-object)
- [API Reference Summary](#api-reference-summary)
- [Creating Findings](#creating-findings)
- [Examples](#examples)
- [YAML Extensions](#yaml-extensions)

---

## Overview

Vigolium extensions are JavaScript files that implement scanner modules using the embedded Sobek (Grafana k6) engine. Extensions can be:

- **Active modules**: Send modified requests to detect vulnerabilities
- **Passive modules**: Analyze existing request/response pairs without sending traffic
- **Pre/post hooks**: Run before or after the scan pipeline

Extensions have access to the full `vigolium.*` API for HTTP requests, database queries, parsing, AI-augmented analysis, and finding creation.

---

## Extension Structure

Every extension exports a `module.exports` object with metadata and scan functions:

```javascript
module.exports = {
  // Required metadata
  id: "my-custom-check",           // Unique module ID
  name: "My Custom Check",         // Human-readable name
  type: "passive",                 // "active" or "passive"
  severity: "medium",              // "info", "low", "medium", "high", "critical", "suspect"
  confidence: "certain",           // "certain", "firm", "tentative"

  // Optional metadata
  description: "Checks for ...",
  scope: "response",               // "request", "response", "both" (passive only)
  tags: ["custom", "light"],       // Module tags for filtering
  scanTypes: ["per_request"],      // "per_request", "per_host", "per_insertion_point"

  // Scan functions (implement one or more)
  scanPerRequest: function(ctx) {
    // Analyze the request/response pair
    // Return a finding object or null
  },

  scanPerHost: function(ctx) {
    // Analyze all records for a host
  },

  scanPerInsertionPoint: function(ctx) {
    // Test a specific insertion point (active modules)
  }
};
```

---

## Running Extensions

```bash
# Run a single extension against a target
vigolium run extension -t https://example.com --ext custom-check.js

# Short alias
vigolium run ext -t https://example.com --ext custom-check.js

# Run during a full scan (alongside built-in modules)
vigolium scan -t https://example.com --ext custom-check.js

# Run only extensions, skip built-in modules
vigolium scan -t https://example.com --only extension --ext custom-check.js

# Load multiple extensions
vigolium scan -t https://example.com --ext check1.js --ext check2.js

# Load all extensions from a directory
vigolium scan -t https://example.com --ext-dir ./my-extensions/

# Quick-test JS code inline
vigolium ext eval 'vigolium.log.info("hello")'
vigolium ext eval --ext-file script.js

# Install preset examples
vigolium ext preset

# View full API docs
vigolium ext docs
vigolium ext docs --example
vigolium ext docs http   # filter by namespace
```

---

## Module Types

### Passive Module

Analyzes existing traffic without sending new requests. Good for pattern detection, data exposure, misconfiguration checks.

```javascript
module.exports = {
  id: "header-check",
  name: "Missing Security Headers",
  type: "passive",
  severity: "low",
  confidence: "certain",
  scope: "response",
  tags: ["headers", "misconfiguration", "light"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response) return null;
    var headers = ctx.response.headers;

    var missing = [];
    if (!headers["x-frame-options"] && !headers["content-security-policy"]) {
      missing.push("X-Frame-Options or CSP frame-ancestors");
    }
    if (!headers["strict-transport-security"]) {
      missing.push("Strict-Transport-Security");
    }

    if (missing.length === 0) return null;

    return {
      url: ctx.request.url,
      name: "Missing Security Headers: " + missing.join(", "),
      severity: "low",
      description: "The response is missing recommended security headers."
    };
  }
};
```

### Active Module

Sends modified requests to test for vulnerabilities. Use `vigolium.http` to send requests.

```javascript
module.exports = {
  id: "custom-path-traversal",
  name: "Path Traversal Check",
  type: "active",
  severity: "high",
  confidence: "firm",
  tags: ["lfi", "traversal"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    var payloads = ["../../../etc/passwd", "....//....//....//etc/passwd"];
    var parsed = vigolium.parse.url(ctx.request.url);
    if (!parsed) return null;

    for (var i = 0; i < payloads.length; i++) {
      var testUrl = parsed.scheme + "://" + parsed.host + "/" + payloads[i];
      var resp = vigolium.http.get(testUrl, {
        headers: ctx.request.headers
      });

      if (resp.status === 200 && resp.body.indexOf("root:") !== -1) {
        return {
          url: testUrl,
          name: "Path Traversal",
          severity: "high",
          matched: "root:",
          request: "GET " + testUrl,
          response: resp.raw
        };
      }
    }
    return null;
  }
};
```

---

## Context Object

The `ctx` object passed to scan functions contains:

```typescript
{
  request: {
    raw: string,        // Full raw HTTP request
    method: string,     // HTTP method
    url: string,        // Full URL
    headers: Record<string, string>
  },
  response: {
    status: number,     // HTTP status code
    body: string,       // Response body
    raw: string,        // Full raw HTTP response
    headers: Record<string, string>
  },
  record: {
    uuid: string,       // Database UUID of the HTTP record
    annotate(patch),    // Update risk_score/remarks
    addRiskScore(delta),// Increment risk score
    addRemarks(remarks) // Append remarks
  }
}
```

The global `vigolium.record` also provides access to the current record context.

---

## API Reference Summary

### vigolium.log
- `info(msg)`, `warn(msg)`, `error(msg)`, `debug(msg)`

### vigolium.utils
- Encoding: `base64Encode/Decode`, `urlEncode/Decode`, `htmlEncode/Decode`
- Hashing: `sha1`, `sha256`, `md5`
- Random: `randomString(len)`
- Regex: `regexMatch(str, pattern)`, `regexExtract(str, pattern)`
- File I/O: `readFile`, `readLines`, `writeFile`, `mkdir`, `glob`
- URL: `parse_url(url, format)`, `pathToTemplate(path)`, `hasDynamicSegment(path)`
- Other: `sleep(ms)`, `exec(cmd)`, `getEnv`, `setEnv`, `jsonExtract`, `detectAnomaly`

### vigolium.parse
- `url(str)`, `request(raw)`, `response(raw)`
- `headers(str)`, `cookies(str)`, `query(str)`, `json(str)`, `form(body)`

### vigolium.http
- `get(url, opts?)`, `post(url, body, opts?)`
- `request(opts)` — full control (method, url, headers, body)
- `send(rawRequest)` — send raw HTTP request string

### vigolium.scan
- `listModules()`, `isInScope(host, path)`, `getScope()`, `setScope(scope)`
- `createFinding(finding)`, `getCurrentScan()`, `startNewScan(opts)`

### vigolium.ingest
- `url(url)`, `urls(content)`, `curl(command)`, `raw(request, response?)`
- `openapi(spec, opts?)`, `postman(collection)`

### vigolium.source
- `list(hostname?)`, `get(id)`, `getByHostname(hostname)`
- `readFile(hostname, path)`, `listFiles(hostname, glob?)`, `searchFiles(hostname, pattern)`

### vigolium.agent (AI-augmented)
- `ask(prompt, opts?)` — single prompt → text response
- `chat(messages, opts?)` — conversation → text response
- `complete(opts)` — full control with JSON schema support
- `generatePayloads(opts)` — generate security test payloads
- `analyzeResponse(opts)` — analyze HTTP exchange for vulnerabilities
- `confirmFinding(opts)` — verify if a finding is a true positive
- `run(opts)` — run a full agent backend subprocess

### vigolium.db
- `records.query(filters?)`, `records.get(uuid)`, `records.getRelated(uuid)`
- `records.annotate(uuid, patch)`
- `findings.query(filters?)`, `findings.get(id)`, `findings.getByRecord(uuid)`
- `findings.create(finding)`
- `compareResponses(records)` — anomaly detection across records

### vigolium.config
- Read-only config values: `vigolium.config["key"]`

---

## Creating Findings

Return a finding object from scan functions:

```javascript
return {
  url: "https://example.com/vuln",     // Required: URL where the issue was found
  name: "Finding Title",               // Required: short title
  severity: "high",                     // Optional: overrides module default
  description: "Detailed explanation",  // Optional
  matched: "pattern found in response", // Optional: matched evidence
  request: "raw request string",        // Optional: HTTP request
  response: "raw response string",      // Optional: HTTP response
  additional_evidence: ["extra1"]       // Optional: array of extra evidence
};
```

Or use `vigolium.scan.createFinding()` for more control:

```javascript
vigolium.scan.createFinding({
  url: "https://example.com/vuln",
  name: "Custom Finding",
  severity: "high",
  description: "...",
  request: rawReq,
  response: rawResp
});
```

---

## Examples

### AI-Augmented Active Scanner

```javascript
module.exports = {
  id: "ai-xss-check",
  name: "AI-Augmented XSS Scanner",
  type: "active",
  severity: "high",
  confidence: "firm",
  tags: ["xss", "ai"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    // Generate context-aware payloads using AI
    var payloads = vigolium.agent.generatePayloads({
      type: "xss",
      context: "HTML attribute",
      technology: "React",
      count: 5
    });

    var parsed = vigolium.parse.url(ctx.request.url);
    if (!parsed || !parsed.query) return null;

    for (var i = 0; i < payloads.length; i++) {
      var testUrl = parsed.scheme + "://" + parsed.host + parsed.path + "?q=" + encodeURIComponent(payloads[i]);
      var resp = vigolium.http.get(testUrl);

      // Use AI to analyze the response
      var analysis = vigolium.agent.analyzeResponse({
        request: "GET " + testUrl,
        response: resp.raw,
        vulnerability_type: "xss",
        payload: payloads[i]
      });

      if (analysis.vulnerable && analysis.confidence !== "low") {
        return {
          url: testUrl,
          name: "XSS via AI analysis",
          severity: "high",
          matched: analysis.evidence,
          description: analysis.details
        };
      }
    }
    return null;
  }
};
```

### Database-Driven IDOR Detector

```javascript
module.exports = {
  id: "idor-detector",
  name: "IDOR Detection via Response Comparison",
  type: "passive",
  severity: "suspect",
  confidence: "tentative",
  tags: ["idor", "bola", "access-control"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.record.uuid) return null;
    var parsed = vigolium.parse.url(ctx.request.url);
    if (!parsed || !vigolium.utils.hasDynamicSegment(parsed.path)) return null;

    // Get related records (same path template, different IDs)
    var related = vigolium.db.records.getRelated(ctx.record.uuid, { limit: 5 });
    if (related.length < 2) return null;

    // Compare responses for anomalies
    var result = vigolium.db.compareResponses(related);
    if (result.all_similar || result.variant_count === 0) return null;

    ctx.record.addRiskScore(30);
    ctx.record.addRemarks(["idor-candidate: " + result.summary]);

    return {
      url: ctx.request.url,
      name: "Potential IDOR: " + result.summary,
      severity: "suspect",
      description: "Response divergence detected across records with same path template."
    };
  }
};
```

### Multi-Version Extensions (Multiple Detection Techniques)

For the same vulnerability sink, create multiple extension files using different detection techniques. This maximizes coverage — if one technique is blocked by WAF or doesn't apply to the target stack, another may succeed.

**Naming convention:** `agent-<vuln>-<context>-<technique>.js`

#### Error-based SQL Injection (`agent-sqli-login-error.js`)

```javascript
module.exports = {
  id: "agent-sqli-login-error",
  name: "SQL Injection in login (error-based)",
  type: "active",
  severity: "high",
  confidence: "firm",
  tags: ["sqli", "agent-generated"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (ctx.request.path !== "/api/login") return null;
    var payloads = ["' OR 1=1--", "admin'--", "' UNION SELECT NULL--"];
    for (var i = 0; i < payloads.length; i++) {
      var resp = vigolium.http.post(ctx.request.url, {
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({username: payloads[i], password: "x"})
      });
      if (resp && resp.body && /SQL|syntax|mysql|pg_|ORA-/.test(resp.body)) {
        return {
          url: ctx.request.url,
          name: "SQL Injection (error-based) in login",
          severity: "high",
          matched: resp.body.substring(0, 200),
          request: "POST " + ctx.request.url,
          response: resp.raw
        };
      }
    }
    return null;
  }
};
```

#### Time-based SQL Injection (`agent-sqli-login-time.js`)

```javascript
module.exports = {
  id: "agent-sqli-login-time",
  name: "SQL Injection in login (time-based)",
  type: "active",
  severity: "high",
  confidence: "firm",
  tags: ["sqli", "agent-generated"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (ctx.request.path !== "/api/login") return null;
    // Baseline request
    var start0 = Date.now();
    vigolium.http.post(ctx.request.url, {
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({username: "baseline", password: "x"})
    });
    var baseline = Date.now() - start0;

    // Time-based payload
    var payload = "' OR SLEEP(3)--";
    var start = Date.now();
    var resp = vigolium.http.post(ctx.request.url, {
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({username: payload, password: "x"})
    });
    var elapsed = Date.now() - start;

    if (elapsed > baseline + 2500) {
      return {
        url: ctx.request.url,
        name: "SQL Injection (time-based) in login",
        severity: "high",
        matched: "Response delayed by " + (elapsed - baseline) + "ms",
        request: "POST " + ctx.request.url,
        response: resp.raw
      };
    }
    return null;
  }
};
```

#### Boolean-based SQL Injection (`agent-sqli-login-boolean.js`)

```javascript
module.exports = {
  id: "agent-sqli-login-boolean",
  name: "SQL Injection in login (boolean-based)",
  type: "active",
  severity: "high",
  confidence: "firm",
  tags: ["sqli", "agent-generated"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (ctx.request.path !== "/api/login") return null;
    var trueResp = vigolium.http.post(ctx.request.url, {
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({username: "' OR 1=1--", password: "x"})
    });
    var falseResp = vigolium.http.post(ctx.request.url, {
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({username: "' OR 1=2--", password: "x"})
    });
    if (trueResp && falseResp && trueResp.status !== falseResp.status) {
      return {
        url: ctx.request.url,
        name: "SQL Injection (boolean-based) in login",
        severity: "high",
        matched: "True condition: " + trueResp.status + ", False condition: " + falseResp.status,
        request: "POST " + ctx.request.url
      };
    }
    return null;
  }
};
```

This pattern applies to other vulnerability classes too — for example, SSTI extensions could have Jinja2, Freemarker, and Twig variants; XSS extensions could have reflected, DOM-based, and attribute-context variants.

### Source Code Correlation

```javascript
module.exports = {
  id: "source-correlation",
  name: "Source-Traffic Correlation",
  type: "passive",
  severity: "info",
  confidence: "firm",
  tags: ["source", "correlation"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    var parsed = vigolium.parse.url(ctx.request.url);
    if (!parsed) return null;

    var repos = vigolium.source.getByHostname(parsed.hostname);
    if (repos.length === 0) return null;

    // Search source code for the endpoint path
    var matches = vigolium.source.searchFiles(parsed.hostname, parsed.path);
    if (matches.length === 0) return null;

    ctx.record.addRemarks(["source-match: " + matches[0].path + ":" + matches[0].line]);
    return null; // Info-only, just annotate
  }
};
```

---

## YAML Extensions

Simple pattern-matching modules can be defined as YAML:

```yaml
id: error-pattern-detector
name: Verbose Error Pattern Detector
type: passive
severity: suspect
confidence: tentative
scope: response
tags:
  - error
  - information-disclosure
  - light
scanTypes:
  - per_request
patterns:
  - name: "Stack Trace Detected"
    regex: "(?:at\\s+[\\w.$]+\\(|Traceback \\(most recent|Exception in thread)"
    severity: suspect
  - name: "SQL Error Message"
    regex: "(?:mysql_|pg_|sqlite_|ORA-\\d{5}|SQLSTATE\\[)"
    severity: medium
  - name: "Debug Mode Enabled"
    regex: "(?:DEBUG\\s*=\\s*True|DJANGO_DEBUG|app\\.debug\\s*=)"
    severity: low
```

YAML extensions match regex patterns against response bodies and automatically create findings.
