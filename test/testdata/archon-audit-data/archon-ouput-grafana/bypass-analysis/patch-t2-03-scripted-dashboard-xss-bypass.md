# Patch T2-03 Bypass Analysis: CVE-2025-6023

**Advisory:** CVE-2025-6023
**Severity:** HIGH (7.6)
**Cluster ID:** CLUSTER-T2-03-REDIRECT
**Bypass Verdict:** sound (for the actual vulnerability fixed), with residual concerns

---

## 1. Advisory Metadata vs. Actual Fix Discrepancy

**Important:** The task description labels CVE-2025-6023 as "XSS in Scripted Dashboards." However, the actual commits tagged `Security: Fixes for CVE-2025-6197 and CVE-2025-6023` (commits `bfbfe020c30`, `4669b586e98`, `988d9642000`, `0567ef29bee`, `aee6b20c7f8`, `5c609d0f51c`, `1fdeca10151`) fix **open redirect vulnerabilities** in two locations:

1. **Login redirect validation** (`pkg/api/login.go` -- `ValidateRedirectTo`)
2. **Org switch redirect validation** (`pkg/middleware/org_redirect.go` -- `OrgRedirect`)

The fix is NOT about scripted dashboard XSS sanitization. The CVE-2025-6023 vulnerability is an **open redirect** issue, not an XSS issue.

## 2. Patch Summary: What Was Actually Fixed

### Login Redirect (`pkg/api/login.go`)
- Added `redirectAllowRe` regex: `^/[a-zA-Z0-9-_./]*$` -- only allows paths starting with `/` followed by alphanumeric chars, dashes, underscores, dots, or slashes.
- Added `redirectDenyRe` regex: `(//|\.\.)` -- blocks double slashes and directory traversal.
- `ValidateRedirectTo()` now additionally checks the cleaned path against both regexes and denies fragments containing `//` or `..`.

### Org Redirect (`pkg/middleware/org_redirect.go`)
- Added `validRedirectPath()` function with the same allow/deny regex pattern.
- The `OrgRedirect` middleware now validates the request URL path before performing the redirect.
- Blocks payloads like `/\example.com`, `//grafana`, `/../`, and similar.

### Fix Mechanism
Both fixes use a two-layer approach:
1. **Deny list**: Reject paths containing `//` or `..`
2. **Allow list**: Require paths to match `^/?[a-zA-Z0-9-_./]*$` (org redirect) or `^/[a-zA-Z0-9-_./]*$` (login)

## 3. Bypass Analysis of the Open Redirect Fix

### Verdict: **sound**

The fix addresses the open redirect comprehensively:

| Vector | Assessment |
|--------|-----------|
| Backslash domain bypass (`/\example.com`) | **Blocked** -- backslash not in allow regex |
| Double-slash bypass (`//example.com`) | **Blocked** -- deny regex matches `//` |
| Path traversal (`/../\example.com`) | **Blocked** -- deny regex matches `..` |
| URL-encoded bypass (`%2f%2f`) | **Blocked** -- `url.Parse()` decodes before validation |
| Fragment injection | **Blocked** -- fragments are now checked against deny regex |
| Query string injection | **Not applicable** -- query strings pass through but path is validated |

**Minor observation:** The login version requires a leading slash (`^/[a-zA-Z0-9-_./]*$`) while the org redirect version allows an optional leading slash (`^/?[a-zA-Z0-9-_./]*$`). This inconsistency is harmless because the org redirect's `validRedirectPath()` also accepts empty paths and `/` as valid.

## 4. Scripted Dashboard XSS: Separate Residual Risk Assessment

While CVE-2025-6023 is about open redirect, the scripted dashboard mechanism does present significant XSS-adjacent risks that were addressed by a separate security measure (commit `b30f501bffd` -- `validatePath` implementation):

### Scripted Dashboard Execution Path

The `DashboardLoaderSrv` (`public/app/features/dashboard/services/DashboardLoaderSrv.ts`) executes scripted dashboards via:

1. User navigates to `/dashboard/script/<filename>` 
2. `loadScriptedDashboard()` fetches `public/dashboards/<filename>.js` (with `validatePath: true`)
3. `executeScript()` runs the fetched JS via `new Function()` constructor (line 76)
4. The script receives `ARGS` from URL query parameters (`locationService.getSearchObject()`)
5. The returned dashboard object flows into the rendering pipeline

### Path Traversal Mitigation
The `validatePath` function (`packages/grafana-data/src/text/sanitize.ts:147`) performs:
- Recursive `decodeURIComponent()` until stable
- Rejects `..`, `/\`, tabs, newlines, carriage returns
- This prevents reading arbitrary `.js` files outside `public/dashboards/`

### XSS via ARGS in Scripted Dashboards
The scripted dashboard scripts (e.g., `scripted.js`) use `ARGS.name` to set panel properties like `alias`. If a user crafts a URL like:
```
/dashboard/script/scripted.js?name=<img src=x onerror=alert(1)>
```
The `ARGS.name` value flows into `seriesName`, which becomes a panel target `alias`. This data then flows through the rendering pipeline where:
- **Text panels**: Sanitized by `sanitizeTextPanelContent()` (xss library) or `renderTextPanelMarkdown()` (marked + sanitize)
- **Panel titles/descriptions**: Rendered through `PanelHeaderCorner.tsx` using `renderMarkdown()` which calls `sanitizeTextPanelContent()`
- **Graph panel aliases**: Rendered as text content in chart legends, not as HTML

### Current Sanitization Coverage
- `DangerouslySetHtmlContent` in TextPanel uses `processContent()` which sanitizes unless `config.disableSanitizeHtml` is true
- `dangerouslySetInnerHTML` in AnnotationTooltip uses `textUtil.sanitize()` (DOMPurify)
- `renderMarkdown()` defaults to sanitization via `sanitizeTextPanelContent()`
- The `sanitize()` function uses DOMPurify with `USE_PROFILES: { html: true }` and `FORBID_TAGS: ['form', 'input']`

### DOMPurify SVG/Math Namespace Analysis
- The general `sanitize()` function uses `USE_PROFILES: { html: true }` -- this **does NOT include** SVG or MathML profiles, meaning SVG-based XSS vectors are stripped by default in the HTML sanitizer.
- A separate `sanitizeSVGContent()` function exists with `USE_PROFILES: { svg: true, svgFilters: true }` but is only used for explicit SVG content rendering.
- The `sanitizeTextPanelContent()` function uses the `xss` library (js-xss), not DOMPurify, with an explicit whitelist of tags. SVG and MathML tags are not in the whitelist.

### Config-Gated Risk: `disableSanitizeHtml`
The `config.disableSanitizeHtml` flag can disable sanitization in:
- TextPanel HTML mode (line 82 of TextPanel.tsx)
- TextPanel Markdown mode via `noSanitize` option
- Table panel
- DashList panel URLs
- Panel links (`link_srv.ts`)

When this flag is enabled, scripted dashboard content controlled by URL parameters would render unsanitized. This is a **documented, intentional** configuration choice but represents a risk if enabled.

## 5. Related Patches (Cluster)

| Commit | Description | Relationship |
|--------|-------------|-------------|
| `bfbfe020c30` | Login + org redirect validation (CVE-2025-6023) | **Primary fix** |
| `4669b586e98` | Cherry-pick to main | Same fix |
| `988d9642000` through `aee6b20c7f8` | Cherry-picks to release branches | Same fix |
| `b30f501bffd` | `validatePath` for BackendSrv fetch calls | **Related defense** -- prevents path traversal in scripted dashboard file fetch |
| `c37bb1d0a61` | Fix query param handling in `validatePath` | Refinement of `b30f501bffd` |
| `0a0d926531c` | Validate newlines/tabs in `validatePath` | Refinement of `b30f501bffd` |
| `be4dc6fdb6a` | Remove ampersand handling in `validatePath` | Refinement of `b30f501bffd` |

## 6. Summary

| Aspect | Finding |
|--------|---------|
| **Actual vulnerability** | Open redirect in login and org redirect paths |
| **Fix mechanism** | Allow-list regex + deny-list regex for redirect paths |
| **Bypass verdict** | **sound** -- regex-based validation is comprehensive for this use case |
| **Advisory label accuracy** | The advisory label "XSS in Scripted Dashboards" does not match the actual fix, which is for open redirect |
| **Scripted dashboard XSS** | Residual risk exists but is mitigated by existing sanitization (DOMPurify + xss library), `validatePath` for path traversal, and the fact that ARGS data flows primarily into chart metadata rather than HTML rendering contexts |
| **Config-gated gap** | `disableSanitizeHtml=true` removes all sanitization from Text panels, potentially enabling XSS via scripted dashboard ARGS |
| **`new Function()` usage** | The scripted dashboard mechanism uses `new Function()` to execute JS, but the script files are served from the server's own `public/dashboards/` directory (with path traversal protection), so this is controlled code execution, not arbitrary user input |
