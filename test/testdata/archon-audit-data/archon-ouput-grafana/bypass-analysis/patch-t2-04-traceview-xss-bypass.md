# Bypass Analysis: PATCH-T2-04 -- CVE-2025-41117 -- XSS in TraceView

**Patch Commit:** `8dfa6446942`
**Severity:** MEDIUM (6.8)
**Component:** `public/app/features/explore/TraceView/components/TraceTimelineViewer/SpanDetail/KeyValuesTable.tsx`
**Cluster ID:** traceview-xss-01

## Patch Summary

The patch addresses a stored/reflected XSS vulnerability in the TraceView span detail panel. The `KeyValuesTable` component renders trace span key-value pairs (tags, process attributes, log fields) and previously interpolated `row.value` directly into HTML strings passed to `dangerouslySetInnerHTML` without any sanitization.

**Pre-patch vulnerable code:**
- For `row.type === 'code'`: raw `row.value` interpolated into `<pre>` tag
- For `row.type === 'text'`: raw `row.value` interpolated into `<span>` tag  
- For all other types: `row.value` passed through `jsonMarkup()` (which has its own `escape()` function for the JSON path, but the code/text paths had none)

**Fix mechanism:** All three HTML construction branches now pass through `DOMPurify.sanitize(html)` before assignment to `dangerouslySetInnerHTML`. DOMPurify is called with default configuration (no custom options).

## Bypass Verdict: **sound**

The fix is well-implemented. Below is the systematic analysis of each bypass vector.

## Evidence and Analysis

### 1. DOMPurify Configuration Assessment

DOMPurify is called with default configuration: `DOMPurify.sanitize(html)`. The version in use is **3.3.2** (per `packages/grafana-data/package.json` and `yarn.lock`).

Default DOMPurify behavior:
- Strips all event handlers (`onerror`, `onload`, `onfocus`, etc.)
- Strips `<script>`, `<iframe>`, `<object>`, `<embed>` tags
- Strips `javascript:` and `data:` URI schemes from href/src attributes
- Strips SVG event handlers and dangerous SVG elements

Default configuration is appropriate here. The rendered content consists of `<pre>`, `<span>`, and `<div>` elements with basic styling -- no need for permissive `ADD_TAGS` or `ADD_ATTR` options. The absence of custom configuration is a strength, not a weakness.

### 2. Other `dangerouslySetInnerHTML` Usages in TraceView

Only **one** instance of `dangerouslySetInnerHTML` exists in the entire `TraceView/components` directory tree -- the patched line in `KeyValuesTable.tsx:140`. No other unsanitized innerHTML usage was found.

A separate instance exists in `public/app/plugins/datasource/tempo/_importedDependencies/datasources/prometheus/RawQuery.tsx:24` but this renders syntax-highlighted query text, not trace span data from external sources.

### 3. Non-innerHTML Injection Vectors

**`row.key` rendering (line 159):** Rendered as `{row.key}` in JSX text content. React automatically escapes JSX text children, converting `<`, `>`, `&`, `"` to HTML entities. This is safe and does not require DOMPurify.

**`LinkValue` component `href` (line 110):** The `path` attribute comes from `linksGetter`, which is an internally constructed function that generates data links from Grafana's link configuration, not from raw trace data. Not directly attacker-controllable through trace injection.

### 4. jsonMarkup.js Internal Escaping

The `jsonMarkup.js` module has its own `escape()` function (line 66-68) that handles `&`, `<`, `>`, `"` for JSON string values. The link case uses `encodeURI()` for the `href` attribute value (line 113). The link type detection regex `/^https?:/` (line 56) correctly rejects `javascript:` URIs, so even before DOMPurify, the `javascript:` protocol cannot enter the href.

However, the jsonMarkup escaping is defense-in-depth -- DOMPurify now serves as the authoritative sanitization layer for all three branches.

### 5. SVG/MathML Namespace Bypass

DOMPurify 3.3.2 with default settings handles SVG/MathML mutation XSS (mXSS) correctly. No known bypasses exist for this version with default configuration.

### 6. Missing Coverage Assessment

The patch covers the single point where trace key-value data is rendered as HTML. The `TextList.tsx` component (sibling file) renders data as React `{row}` text content within `<li>` elements -- no HTML injection possible there.

No other components in the TraceView tree render trace attribute data via innerHTML.

### 7. Encoding/Normalization Gaps

DOMPurify handles all standard encoding tricks (HTML entities, Unicode escapes, null bytes, UTF-7, etc.) in its default mode. No normalization bypass is possible.

## Residual Observations (Low Risk)

1. **Pre-DOMPurify string interpolation still occurs:** The code still constructs `html` strings by interpolating `row.value` into template literals before sanitizing. While DOMPurify makes this safe, a cleaner pattern would be to construct DOM elements directly via React. This is a code quality observation, not a security issue.

2. **CopyIcon receives unsanitized `row.value` (line 166-167):** The `copyText` prop passes raw `row.value` to the clipboard. This is not an XSS vector since clipboard content is not rendered as HTML, but downstream consumers of clipboard data should be aware that it may contain HTML/script payloads.

## Conclusion

The DOMPurify sanitization with default configuration on version 3.3.2 is a sound fix for this XSS vulnerability. The single `dangerouslySetInnerHTML` usage is now properly guarded. No alternate entry points, sibling paths, or configuration-gated bypasses were identified.
