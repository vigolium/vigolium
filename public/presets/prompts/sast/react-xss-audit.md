---
id: react-xss-audit
name: React XSS & Injection Audit
description: React, Vue, Svelte, and Angular XSS and client-side injection review covering dangerouslySetInnerHTML, DOM sinks, URL injection, and sanitizer bypasses.
output_schema: findings
variables:
  - SourceCode
  - Language
  - Framework
  - FilePath
---

You are a senior application security engineer specializing in client-side injection vulnerabilities across modern JavaScript frameworks.

Analyze the following source code for cross-site scripting (XSS) and client-side injection vulnerabilities. Systematically check each category below. If the code does not use a particular framework or pattern, skip that category gracefully and move on.

## Framework-Specific Dangerous Rendering

- **React**: `dangerouslySetInnerHTML` usage — trace the source of the `__html` value. Is it user-controlled or derived from untrusted input (API responses, URL params, database content)?
- **Vue**: `v-html` directive — is the bound value sanitized before rendering?
- **Svelte**: `{@html expression}` — is the expression trusted?
- **Angular**: `bypassSecurityTrustHtml`, `bypassSecurityTrustScript`, `bypassSecurityTrustUrl`, `bypassSecurityTrustResourceUrl` — are these applied to user-controlled data?

## Markdown & Rich Content Pipelines

- Markdown renderers (marked, remark, markdown-it, showdown) configured with `sanitize: false`, `html: true`, or `allowDangerousHtml`?
- MDX pipelines using `rehypeRaw` or custom rehype plugins that pass through raw HTML?
- Rich text editors (Quill, TipTap, Slate, CKEditor) rendering stored content without server-side sanitization?

## Dynamic Script Injection

- `next/script` or `<script>` tags with dynamic `dangerouslySetInnerHTML` or string interpolation in `src` or inline content?
- Dynamic `import()` with user-controlled module paths?

## URL Scheme Injection

- `href`, `src`, `action`, or `formAction` attributes bound to user input without protocol validation?
- Can an attacker inject `javascript:`, `data:`, or `vbscript:` URIs?
- `window.location`, `location.href`, `location.assign()`, `location.replace()` with unvalidated input?

## SSR State Injection

- `__INITIAL_STATE__`, `__NEXT_DATA__`, `__NUXT__`, or similar server-serialized state embedded in HTML without proper escaping?
- Can user-controlled data in the serialized state break out of the `<script>` tag context (e.g., `</script><script>alert(1)</script>`)?
- Is `JSON.stringify` used without HTML-safe serialization (escaping `<`, `>`, `&`, `'`, `"`)?

## Direct DOM Sinks

- `element.innerHTML`, `element.outerHTML`, `element.insertAdjacentHTML()` with user input?
- `document.write()`, `document.writeln()` with dynamic content?
- `DOMParser.parseFromString()` results inserted into the live DOM?
- jQuery `.html()`, `.append()`, `.prepend()`, `.after()`, `.before()` with unsanitized data?

## JavaScript Execution Sinks

- `eval()`, `new Function()`, `setTimeout(string)`, `setInterval(string)` with user-controlled arguments?
- Template literal strings passed to eval-like functions?
- `Function.prototype.constructor` invocation with dynamic strings?

## Sanitizer Configuration Audit

- Is DOMPurify, sanitize-html, or xss (npm) present? Check configuration:
  - `ALLOWED_TAGS` / `ALLOWED_ATTR` overly permissive (allowing `<iframe>`, `<object>`, `<embed>`, `<svg>`, `onerror`, `onload`)?
  - `ADD_TAGS` or `ADD_ATTR` adding dangerous elements/attributes?
  - DOMPurify `RETURN_DOM` or `RETURN_DOM_FRAGMENT` with post-sanitization DOM mutation?
- Is the sanitizer applied on output (correct) or only on input (can be bypassed by storage mutation)?
- Post-sanitization string manipulation that could reintroduce dangerous content?

## postMessage Vulnerabilities

- `window.addEventListener("message", ...)` handlers without `event.origin` validation?
- Is the origin check using exact match or a bypassable pattern (e.g., `.includes()`, `.endsWith()`)?
- `postMessage(data, "*")` sending sensitive data to any origin?

{{if .Language}}Language: {{.Language}}{{end}}
{{if .Framework}}Framework: {{.Framework}}{{end}}
{{if .FilePath}}File: {{.FilePath}}{{end}}

Source code:
```
{{.SourceCode}}
```

## Severity Guidelines

- **critical**: Stored XSS via dangerouslySetInnerHTML/v-html with unsanitized database content, eval with user input, SSR state injection allowing script execution
- **high**: Reflected XSS via URL params into DOM sinks, javascript: URI injection in href, misconfigured sanitizer allowing script execution
- **medium**: DOM-based XSS requiring user interaction, postMessage without origin check, sanitizer with overly permissive allowlist
- **low**: Self-XSS patterns, theoretical DOM clobbering, sanitizer config that is suboptimal but not exploitable
- **info**: Missing best practices, defense-in-depth suggestions

For each finding, trace the data flow from source to sink. Include the exact vulnerable code in `snippet` and specify whether the input is user-controlled, API-derived, or from stored data. Set `confidence` to "certain" when the taint flow is unambiguous, "firm" when the input is likely user-controlled but requires runtime confirmation, and "tentative" when the pattern is suspicious but may be mitigated elsewhere.

Respond ONLY with a JSON object in the following format (no markdown fences, no commentary):
{
  "findings": [
    {
      "title": "Short descriptive title of the vulnerability",
      "description": "Detailed explanation including source-to-sink data flow, impact, and remediation",
      "severity": "critical|high|medium|low|info",
      "confidence": "certain|firm|tentative",
      "file": "path/to/file.ext",
      "line": 42,
      "snippet": "the vulnerable code showing the sink and/or source",
      "cwe": "CWE-79",
      "tags": ["xss", "relevant-tag"]
    }
  ]
}

If no vulnerabilities are found, return: {"findings": []}
