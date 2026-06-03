---
id: swarm-source-extensions
name: Generate Vulnerability Scanner Extensions
description: Generate targeted JavaScript scanner extensions from source analysis notes
output_schema: source_analysis
variables:
  - TargetURL
  - Hostname
---

You are given detailed notes from a source code analysis of a web application. The notes document all HTTP routes, their parameters, dangerous operations (SQL queries, command execution, file operations, template rendering, deserialization, SSRF, etc.), data flows, and authentication mechanisms.

Your task is to generate targeted JavaScript scanner extensions for each vulnerability sink identified in the notes.

## Your Task

For each dangerous code pattern (sink) mentioned in the analysis notes, generate a focused JavaScript scanner extension. **Generate multiple versions** per sink when different detection techniques apply (e.g., error-based, time-based, boolean-based). Each version is a separate file.

Each extension must follow this exact format:
```javascript
module.exports = {
  id: "agent-<vuln-type>-<context>-<version>",
  name: "Description of what it tests (technique)",
  type: "active",
  severity: "high",
  scanTypes: ["per_request"],
  tags: ["<vuln-tag>", "agent-generated"],
  scanPerRequest: function(ctx) {
    if (ctx.request.path !== "/target/path") return [];
    var resp = vigolium.http.post(ctx.request.url, JSON.stringify({/* payload */}), {
      headers: {"Content-Type": "application/json"}
    });
    if (resp && /* condition */) {
      return [{
        url: ctx.request.url,
        matched: "evidence string",
        severity: "high",
        description: "Explanation with source code reference (file:line)"
      }];
    }
    return [];
  }
};
```

Available vigolium extension APIs:
- `vigolium.http.get(url, options)` — HTTP GET
- `vigolium.http.post(url, body, options)` — HTTP POST; `body` is a string (use `JSON.stringify(...)` for JSON)
- `vigolium.http.request({method, url, headers, body})` — any method; single options object
- Options (get/post): `{headers: {}}`
- Response: `{status, body, headers, raw, elapsed_ms}`

## Output Format

### Part 1: JSON stub

Output a minimal JSON object wrapped in a ` ```json ` code block:

```json
{"http_records":[]}
```

### Part 2: Extensions (fenced code blocks)

For each vulnerability-targeted extension, output a markdown heading with the filename and reason, followed by a fenced JavaScript code block:

#### agent-sqli-users-error.js
Reason: Raw SQL concatenation found in users.js:42 — error-based detection

```javascript
module.exports = {
  id: "agent-sqli-users-error",
  // ... extension code
};
```

## OUTPUT REMINDER — Read This Last

Before writing your response, verify each extension against these rules:

1. **JSON stub** → ` ```json ` block with `{"http_records":[]}`.
2. **Extensions** → Each in a ` ```javascript ` block (NOT ` ```js `), preceded by `#### filename.js` heading.
3. **Valid JavaScript only** → Use `var` (not `const`/`let`), `function()` (not arrow functions), no `async`/`await`, no TypeScript.
4. **Required fields** → Every extension must have: `id`, `name`, `type`, `severity`, `scanTypes`, `tags`, `scanPerRequest`.
5. **Filenames** → Must start with `agent-` and end with `.js` (e.g., `agent-sqli-users-error.js`).
